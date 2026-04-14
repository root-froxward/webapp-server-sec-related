#!/usr/bin/env python3
"""
froxward-soar
Real-time Wazuh alert processor with automated response actions + Telegram notifications
"""

import json
import os
import re
import subprocess
import sys
import time
import threading
import hashlib
import signal
import logging
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# ─── config ───────────────────────────────────────────────────────────────────

ALERTS_JSON     = os.getenv("ALERTS_JSON", "/var/ossec/logs/alerts/alerts.json")
TELEGRAM_TOKEN  = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT   = os.getenv("TELEGRAM_CHAT", "")
LOG_FILE        = os.getenv("SOAR_LOG", "/var/log/froxward_soar.log")
BANNED_DB       = os.getenv("BANNED_DB", "/tmp/froxward_banned.db")
DEDUP_DB        = os.getenv("DEDUP_DB", "/tmp/froxward_dedup.db")
DRY_RUN         = os.getenv("DRY_RUN", "0") == "1"
MAX_DEDUP       = 50000

# ban durations (seconds)
BAN_TIMES = {
    "critical": 86400,   # 24h
    "high":      7200,   # 2h
    "medium":    3600,   # 1h
    "low":        600,   # 10m
}

# rule id → (severity_override, action)
RULE_MAP = {
    # SSH
    "5710": ("medium", "ban"),
    "5712": ("high",   "ban"),
    "5720": ("high",   "ban"),
    "5763": ("high",   "ban"),
    # Web / ModSec
    "31100": ("high",  "ban"),    # SQLi
    "31108": ("critical", "ban"), # Log4Shell
    "31120": ("medium","ban"),    # LFI/traversal
    # Rootcheck / privesc
    "510":  ("high",  "alert"),
    "550":  ("high",  "alert"),
    "2502": ("high",  "alert"),
    # Firewall
    "4151": ("medium","ban"),
    # Auth
    "2501": ("medium","alert"),
    "2502": ("high",  "alert"),
    # Lateral
    "60122": ("critical", "ban"),  # PtH
    "60204": ("critical", "ban"),
}

# pattern → (severity, action, label)
PATTERN_MAP = [
    (r"sql.?inject|sqli|\bunion\b.+select",         "high",    "ban",   "SQLi"),
    (r"xss|cross.site|<script",                     "medium",  "ban",   "XSS"),
    (r"log4shell|jndi:|ldap://",                    "critical","ban",   "Log4Shell"),
    (r"path.travers|\.\.\/|lfi",                    "medium",  "ban",   "LFI/Traversal"),
    (r"brute.?force|password.attempt|auth.fail",    "high",    "ban",   "Brute Force"),
    (r"port.scan|scanner|nmap|masscan",             "medium",  "ban",   "Port Scan"),
    (r"pass.?the.?hash|pth|ntlm.?relay",            "critical","ban",   "Pass-the-Hash"),
    (r"privilege.escal|suid|sudo.abuse",            "high",    "alert", "PrivEsc"),
    (r"rce|remote.code.exec|command.inject",        "critical","ban",   "RCE"),
    (r"malware|trojan|backdoor|rootkit",            "critical","ban",   "Malware"),
    (r"log.clear|log.delet|history.wipe",           "high",    "alert", "Log Tampering"),
    (r"lateral.move|pivoting|smb.recon",            "high",    "alert", "Lateral Movement"),
    (r"credential.dump|mimikatz|lsass",             "critical","ban",   "Credential Dump"),
    (r"defense.evas|obfuscat|base64.decode",        "medium",  "alert", "Defense Evasion"),
    (r"ssrf|server.side.request",                   "high",    "ban",   "SSRF"),
    (r"xxe|xml.external",                           "high",    "ban",   "XXE"),
    (r"ddos|syn.flood|amplif",                      "critical","ban",   "DDoS"),
]


# ─── logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("froxward-soar")


# ─── state ────────────────────────────────────────────────────────────────────

processed_ids = set()
banned_ips = {}      # ip → expiry_ts
alert_counts = defaultdict(int)   # ip → count
_lock = threading.Lock()


# ─── firewall ─────────────────────────────────────────────────────────────────

def detect_firewall():
    rc, out, _ = _run("nft list ruleset 2>/dev/null | head -1")
    if rc == 0 and out.strip():
        return "nftables"
    return "iptables"


FIREWALL = detect_firewall()


def ban_ip(ip, duration_sec, reason):
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return
    expiry = time.time() + duration_sec
    with _lock:
        if ip in banned_ips and banned_ips[ip] > time.time():
            return  # already banned
        banned_ips[ip] = expiry

    h = int(duration_sec // 3600)
    m = int((duration_sec % 3600) // 60)
    duration_str = f"{h}h{m}m" if h else f"{m}m"

    logger.info(f"BAN {ip} for {duration_str} | reason: {reason}")

    if DRY_RUN:
        logger.info(f"[DRY RUN] would ban {ip}")
        return

    if FIREWALL == "nftables":
        _run(f"nft add element inet froxward banned_ips {{ {ip} timeout {duration_sec}s }}")
    else:
        _run(f"iptables -I FROXWARD_BANNED -s {ip} -j DROP 2>/dev/null || "
             f"iptables -I INPUT -s {ip} -j DROP")

    # persist to db
    _write_banned_db(ip, expiry, reason)

    # schedule unban
    threading.Timer(duration_sec, unban_ip, args=[ip]).start()


def unban_ip(ip):
    with _lock:
        banned_ips.pop(ip, None)
    if DRY_RUN:
        return
    if FIREWALL == "nftables":
        _run(f"nft delete element inet froxward banned_ips {{ {ip} }} 2>/dev/null")
    else:
        _run(f"iptables -D FROXWARD_BANNED -s {ip} -j DROP 2>/dev/null || "
             f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null")
    logger.info(f"UNBAN {ip}")


def _write_banned_db(ip, expiry, reason):
    try:
        with open(BANNED_DB, "a") as f:
            f.write(json.dumps({"ip": ip, "expiry": expiry, "reason": reason}) + "\n")
    except Exception:
        pass


# ─── telegram ─────────────────────────────────────────────────────────────────

def send_telegram(msg):
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        return
    try:
        import urllib.request
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = json.dumps({"chat_id": TELEGRAM_CHAT, "text": msg, "parse_mode": "HTML"}).encode()
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        logger.warning(f"Telegram send failed: {e}")


def format_telegram_alert(alert, action, label, severity, ip):
    level = alert.get("rule", {}).get("level", "?")
    desc  = alert.get("rule", {}).get("description", "?")
    agent = alert.get("agent", {}).get("name", "?")
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")

    lines = [
        f"{sev_emoji} <b>FROXWARD SOAR ALERT</b>",
        f"<b>Type:</b> {label}",
        f"<b>Severity:</b> {severity.upper()} (level {level})",
        f"<b>Description:</b> {desc}",
        f"<b>Agent:</b> {agent}",
    ]
    if ip:
        lines.append(f"<b>Source IP:</b> <code>{ip}</code>")
    lines.append(f"<b>Action:</b> {action.upper()}")
    lines.append(f"<b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return "\n".join(lines)


# ─── alert processing ─────────────────────────────────────────────────────────

def extract_ip(alert):
    """Try to extract source IP from alert"""
    data = alert.get("data", {})
    for field in ("srcip", "src_ip", "remote_ip", "attacker", "dstuser"):
        if v := data.get(field):
            if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", str(v)):
                return v
    # check full JSON for IP patterns
    full = json.dumps(alert)
    ips = re.findall(r"\b(?:(?!10\.0\.0\.|127\.|192\.168\.))\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", full)
    return ips[0] if ips else None


def classify_alert(alert):
    """Returns (severity, action, label) or None to skip"""
    rule    = alert.get("rule", {})
    rule_id = str(rule.get("id", ""))
    level   = int(rule.get("level", 0))
    desc    = rule.get("description", "").lower()
    full    = (desc + " " + json.dumps(alert.get("data", {})).lower())

    # rule id override
    if rule_id in RULE_MAP:
        sev, action = RULE_MAP[rule_id]
        return sev, action, desc[:60]

    # level-based
    if level >= 13:
        base_sev = "critical"
    elif level >= 10:
        base_sev = "high"
    elif level >= 7:
        base_sev = "medium"
    elif level >= 4:
        base_sev = "low"
    else:
        return None  # skip low noise

    # pattern match
    for pattern, pat_sev, action, label in PATTERN_MAP:
        if re.search(pattern, full, re.IGNORECASE):
            # take highest severity
            sev_order = ["low", "medium", "high", "critical"]
            sev = pat_sev if sev_order.index(pat_sev) > sev_order.index(base_sev) else base_sev
            return sev, action, label

    # fallback: alert only if level >= 7
    if level >= 7:
        return base_sev, "alert", desc[:60]
    return None


def process_alert(alert):
    # dedup
    alert_id = hashlib.md5(json.dumps(alert, sort_keys=True).encode()).hexdigest()
    if alert_id in processed_ids:
        return
    processed_ids.add(alert_id)
    if len(processed_ids) > MAX_DEDUP:
        processed_ids.clear()

    # skip injected test alerts
    if alert.get("_froxward_injected"):
        return

    result = classify_alert(alert)
    if not result:
        return

    severity, action, label = result
    ip = extract_ip(alert)

    logger.info(f"ALERT [{severity.upper()}] {label} | ip={ip} | action={action}")

    if action == "ban" and ip:
        duration = BAN_TIMES.get(severity, 3600)
        ban_ip(ip, duration, label)

    # telegram notification for medium+
    if severity in ("high", "critical", "medium"):
        msg = format_telegram_alert(alert, action, label, severity, ip)
        threading.Thread(target=send_telegram, args=[msg], daemon=True).start()

    # increment counter
    if ip:
        alert_counts[ip] += 1
        # auto-escalate: if same IP triggers 5+ alerts → force 24h ban
        if alert_counts[ip] >= 5 and ip not in banned_ips:
            logger.warning(f"ESCALATE {ip} — {alert_counts[ip]} alerts, forcing 24h ban")
            ban_ip(ip, 86400, f"escalated: {alert_counts[ip]} alerts")


# ─── tail ─────────────────────────────────────────────────────────────────────

def tail_alerts():
    path = Path(ALERTS_JSON)
    logger.info(f"Tailing {ALERTS_JSON}")

    # seek to end
    with open(path, "r") as f:
        f.seek(0, 2)
        buf = ""
        while True:
            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.3)
                continue
            buf += chunk
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    process_alert(alert)
                except json.JSONDecodeError:
                    pass


def wait_for_file(path, timeout=60):
    logger.info(f"Waiting for {path}...")
    t = 0
    while not Path(path).exists():
        time.sleep(2)
        t += 2
        if t >= timeout:
            logger.error(f"{path} not found after {timeout}s. Is Wazuh running?")
            sys.exit(1)


# ─── status ───────────────────────────────────────────────────────────────────

def status_loop():
    """Print live stats every 60s"""
    while True:
        time.sleep(60)
        with _lock:
            active_bans = sum(1 for exp in banned_ips.values() if exp > time.time())
        logger.info(f"STATUS | processed={len(processed_ids)} | active_bans={active_bans} | tracked_ips={len(alert_counts)}")


# ─── main ─────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="froxward-soar — real-time Wazuh SOAR")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions, don't actually ban")
    parser.add_argument("--status", action="store_true", help="Show current banned IPs and exit")
    args = parser.parse_args()

    global DRY_RUN
    if args.dry_run:
        DRY_RUN = True

    if args.status:
        if Path(BANNED_DB).exists():
            now = time.time()
            print("\nCurrently banned IPs:")
            with open(BANNED_DB) as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if entry["expiry"] > now:
                            remaining = int(entry["expiry"] - now)
                            print(f"  {entry['ip']:<20} expires in {remaining//60}m | {entry['reason']}")
                    except Exception:
                        pass
        else:
            print("No banned IPs.")
        return

    logger.info("froxward-soar starting")
    if DRY_RUN:
        logger.info("[DRY RUN MODE] no actual bans will be applied")

    if not TELEGRAM_TOKEN:
        logger.warning("TELEGRAM_TOKEN not set — notifications disabled")

    def handle_signal(sig, frame):
        logger.info("Shutting down froxward-soar")
        sys.exit(0)
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    wait_for_file(ALERTS_JSON)

    threading.Thread(target=status_loop, daemon=True).start()
    tail_alerts()


if __name__ == "__main__":
    main()

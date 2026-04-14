#!/usr/bin/env python3
# (c) 2024-2026 thelema-froxward
# Licensed under the MIT License
import sys
import os
import json
import subprocess
import logging
import ipaddress
from datetime import datetime

LOG_FILE        = "/var/log/wazuh/auto-mitigate.log"
NGINX_DENY_FILE = "/etc/nginx/conf.d/wazuh-blocked.conf"
WAF_DENY_FILE   = "/etc/nginx/conf.d/wazuh-waf-block.conf"
IPSET_NAME      = "wazuh_blocked"
IPSET_DDOS_NAME = "wazuh_ddos"
INCIDENT_DIR    = "/var/ossec/logs/critical-incidents"

CF_ENABLED    = False
CF_API_TOKEN  = ""
CF_ZONE_ID    = ""

BLOCK_DURATIONS = {
    "ddos"       : 3600,
    "http_flood" : 1800,
    "sqli"       : 86400,
    "rce"        : 0,
    "webshell"   : 0,
    "log4shell"  : 0,
    "scanner"    : 7200,
    "brute_force": 3600,
    "default"    : 3600,
}

MITIGATION_MAP = {
    "ddos"           : ["ipset_block_ddos", "iptables_rate_limit", "fail2ban", "cloudflare"],
    "l3"             : ["ipset_block_ddos", "iptables_rate_limit"],
    "l4"             : ["ipset_block_ddos", "iptables_rate_limit", "fail2ban"],
    "l7"             : ["nginx_deny", "iptables_rate_limit", "fail2ban", "cloudflare"],
    "http_flood"     : ["nginx_deny", "iptables_rate_limit", "fail2ban", "cloudflare"],
    "sqli"           : ["ipset_block", "nginx_deny", "waf_rule", "fail2ban"],
    "xss"            : ["ipset_block", "nginx_deny", "fail2ban"],
    "lfi"            : ["ipset_block", "nginx_deny", "fail2ban"],
    "rfi"            : ["ipset_block", "nginx_deny", "fail2ban"],
    "ssrf"           : ["ipset_block", "nginx_deny"],
    "rce"            : ["ipset_block", "nginx_deny", "waf_rule", "fail2ban", "cloudflare", "isolate_check"],
    "cmdi"           : ["ipset_block", "nginx_deny", "waf_rule", "fail2ban"],
    "log4shell"      : ["ipset_block", "nginx_deny", "waf_rule", "fail2ban", "cloudflare", "isolate_check"],
    "spring4shell"   : ["ipset_block", "nginx_deny", "fail2ban", "isolate_check"],
    "shellshock"     : ["ipset_block", "nginx_deny", "fail2ban"],
    "webshell"       : ["ipset_block", "nginx_deny", "fail2ban", "isolate_check"],
    "deserialization": ["ipset_block", "nginx_deny", "fail2ban"],
    "brute_force"    : ["ipset_block", "fail2ban"],
    "auth_bypass"    : ["ipset_block", "fail2ban"],
    "scanner"        : ["ipset_block", "fail2ban"],
    "multi_vector"   : ["ipset_block", "nginx_deny", "waf_rule", "fail2ban", "cloudflare"],
    "critical"       : ["ipset_block", "nginx_deny", "waf_rule", "fail2ban", "cloudflare"],
}

WHITELIST_NETWORKS = []

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
log = logging.getLogger("auto-mitigate")


def load_config():
    global CF_ENABLED, CF_API_TOKEN, CF_ZONE_ID, WHITELIST_NETWORKS
    cfg_path = "/var/ossec/etc/auto-mitigate.conf"
    if not os.path.exists(cfg_path):
        return
    with open(cfg_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                k, v = k.strip(), v.strip()
                if k == "CF_ENABLED":
                    CF_ENABLED = v.lower() == "true"
                elif k == "CF_API_TOKEN":
                    CF_API_TOKEN = v
                elif k == "CF_ZONE_ID":
                    CF_ZONE_ID = v
                elif k == "WHITELIST":
                    WHITELIST_NETWORKS.extend([x.strip() for x in v.split(",")])


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip(), r.returncode
    except Exception as e:
        log.error(f"CMD error: {cmd} | {e}")
        return "", 1


def is_whitelisted(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for net in WHITELIST_NETWORKS:
            if addr in ipaddress.ip_network(net.strip(), strict=False):
                log.info(f"Whitelisted: {ip}")
                return True
    except ValueError:
        pass
    return False


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def ensure_ipset(name, timeout=None):
    if timeout and timeout > 0:
        run(f"ipset create {name} hash:ip timeout {timeout} -exist")
    else:
        run(f"ipset create {name} hash:ip -exist")
    run(f"iptables -I INPUT 1 -m set --match-set {name} src -j DROP 2>/dev/null || true")
    run(f"iptables -I FORWARD 1 -m set --match-set {name} src -j DROP 2>/dev/null || true")


def get_alert_groups(alert):
    raw = alert.get("rule", {}).get("groups", [])
    if isinstance(raw, list):
        return [g.lower() for g in raw]
    if isinstance(raw, str):
        return [g.lower().strip() for g in raw.split(",")]
    return []


def get_actions(groups):
    actions = set()
    for grp in groups:
        for key, acts in MITIGATION_MAP.items():
            if key in grp:
                actions.update(acts)
    return list(actions)


def get_block_duration(groups):
    for key, dur in BLOCK_DURATIONS.items():
        if any(key in g for g in groups):
            return dur
    return BLOCK_DURATIONS["default"]


def ipset_block(ip, duration):
    ensure_ipset(IPSET_NAME, duration)
    if duration > 0:
        run(f"ipset add {IPSET_NAME} {ip} timeout {duration} -exist")
    else:
        run(f"ipset add {IPSET_NAME} {ip} -exist")
    log.info(f"[BLOCK] {ip} duration={duration}s")


def ipset_block_ddos(ip, duration):
    ensure_ipset(IPSET_DDOS_NAME, duration)
    if duration > 0:
        run(f"ipset add {IPSET_DDOS_NAME} {ip} timeout {duration} -exist")
    else:
        run(f"ipset add {IPSET_DDOS_NAME} {ip} -exist")
    run(f"iptables -t raw -I PREROUTING 1 -m set --match-set {IPSET_DDOS_NAME} src -j DROP 2>/dev/null || true")
    log.info(f"[DDOS-BLOCK] {ip} raw table duration={duration}s")


def iptables_rate_limit(ip):
    run(f"""iptables -I INPUT 2 -s {ip} -m hashlimit \
        --hashlimit-above 30/sec \
        --hashlimit-burst 50 \
        --hashlimit-mode srcip \
        --hashlimit-name rl_{ip.replace('.','_')} \
        -j DROP 2>/dev/null || true""")
    log.info(f"[RATE-LIMIT] {ip} 30pps")


def nginx_deny(ip):
    try:
        existing = open(NGINX_DENY_FILE).read() if os.path.exists(NGINX_DENY_FILE) else ""
        line = f"deny {ip};\n"
        if line not in existing:
            with open(NGINX_DENY_FILE, "a") as f:
                f.write(line)
            out, rc = run("nginx -t 2>&1")
            if rc == 0:
                run("nginx -s reload")
                log.info(f"[NGINX-DENY] {ip}")
            else:
                log.error(f"[NGINX-DENY] config test failed: {out}")
                with open(NGINX_DENY_FILE, "r") as f:
                    lines = f.readlines()
                with open(NGINX_DENY_FILE, "w") as f:
                    f.writelines(l for l in lines if ip not in l)
    except Exception as e:
        log.error(f"[NGINX-DENY] {ip}: {e}")


def fail2ban_ban(ip):
    out, rc = run("systemctl is-active fail2ban")
    if rc == 0:
        run(f"fail2ban-client set wazuh-auto banip {ip} 2>/dev/null || true")
        log.info(f"[FAIL2BAN] {ip}")


def waf_rule(ip):
    try:
        existing = open(WAF_DENY_FILE).read() if os.path.exists(WAF_DENY_FILE) else ""
        line = f"deny {ip};\n"
        if line not in existing:
            with open(WAF_DENY_FILE, "a") as f:
                f.write(line)
            run("nginx -t && nginx -s reload")
            log.info(f"[WAF-RULE] {ip}")
    except Exception as e:
        log.error(f"[WAF-RULE] {ip}: {e}")


def cloudflare_block(ip):
    if not CF_ENABLED or not CF_API_TOKEN or not CF_ZONE_ID:
        return
    try:
        import requests
        r = requests.post(
            f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/firewall/access_rules/rules",
            headers={"Authorization": f"Bearer {CF_API_TOKEN}", "Content-Type": "application/json"},
            json={
                "mode": "block",
                "configuration": {"target": "ip", "value": ip},
                "notes": f"wazuh-auto {datetime.utcnow().isoformat()}"
            },
            timeout=10
        )
        if r.status_code in (200, 201):
            log.info(f"[CLOUDFLARE] {ip} blocked at edge")
        else:
            log.error(f"[CLOUDFLARE] {r.status_code}: {r.text}")
    except Exception as e:
        log.error(f"[CLOUDFLARE] {e}")


def isolate_check(ip):
    os.makedirs(INCIDENT_DIR, exist_ok=True)
    path = f"{INCIDENT_DIR}/{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{ip}.txt"
    with open(path, "w") as f:
        f.write(f"CRITICAL INCIDENT\nTime: {datetime.utcnow().isoformat()}Z\nAttacker: {ip}\n")
        f.write("Possible RCE/webshell/Log4Shell — MANUAL REVIEW REQUIRED\n")
    log.info(f"[INCIDENT] {path}")


def unblock_ip(ip):
    run(f"ipset del {IPSET_NAME} {ip} 2>/dev/null || true")
    run(f"ipset del {IPSET_DDOS_NAME} {ip} 2>/dev/null || true")
    run(f"iptables -D INPUT -s {ip} -m hashlimit --hashlimit-name rl_{ip.replace('.','_')} -j DROP 2>/dev/null || true")
    for fpath in [NGINX_DENY_FILE, WAF_DENY_FILE]:
        if os.path.exists(fpath):
            with open(fpath, "r") as f:
                lines = f.readlines()
            with open(fpath, "w") as f:
                f.writelines(l for l in lines if ip not in l)
    run("nginx -t && nginx -s reload 2>/dev/null || true")
    run(f"fail2ban-client set wazuh-auto unbanip {ip} 2>/dev/null || true")
    log.info(f"[UNBLOCK] {ip}")


def main():
    load_config()

    if len(sys.argv) < 2:
        sys.exit(1)

    action = sys.argv[1]

    try:
        raw = sys.stdin.read().strip()
        alert = json.loads(raw)
    except Exception as e:
        log.error(f"JSON parse error: {e}")
        sys.exit(1)

    ip = (alert.get("data", {}).get("srcip") or
          alert.get("data", {}).get("src_ip") or
          alert.get("data", {}).get("remote_ip") or "")

    if not ip or not is_valid_ip(ip):
        log.warning("No valid source IP in alert")
        sys.exit(0)

    if action == "delete":
        unblock_ip(ip)
        sys.exit(0)

    if is_whitelisted(ip):
        sys.exit(0)

    groups   = get_alert_groups(alert)
    actions  = get_actions(groups)
    duration = get_block_duration(groups)
    rule_id  = alert.get("rule", {}).get("id", "?")

    log.info(f"[TRIGGER] rule={rule_id} ip={ip} groups={groups} duration={duration}s")

    for act in actions:
        try:
            if   act == "ipset_block"        : ipset_block(ip, duration)
            elif act == "ipset_block_ddos"   : ipset_block_ddos(ip, duration)
            elif act == "iptables_rate_limit": iptables_rate_limit(ip)
            elif act == "nginx_deny"         : nginx_deny(ip)
            elif act == "fail2ban"           : fail2ban_ban(ip)
            elif act == "waf_rule"           : waf_rule(ip)
            elif act == "cloudflare"         : cloudflare_block(ip)
            elif act == "isolate_check"      : isolate_check(ip)
        except Exception as e:
            log.error(f"Action {act} failed for {ip}: {e}")


if __name__ == "__main__":
    main()

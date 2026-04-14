#!/usr/bin/env python3
"""
playbooks/ban.py — IP ban via ipset
Supports optional shared ipset with honeypot (honeypot-banned-ips)
"""

import asyncio
import ipaddress
import logging
import subprocess
from pathlib import Path

log = logging.getLogger("soar.ban")

# Rule categories → ban behaviour
# web_attack: ban immediately on any level >= threshold
# mitre_attack: ban + log MITRE tactic
CATEGORY_CONFIG = {
    "web_attack": {"ban_subnet": True, "subnet_prefix": 24},
    "mitre_attack": {"ban_subnet": True, "subnet_prefix": 24},
    "generic": {"ban_subnet": False},
}

# Whitelist — never ban these
ALWAYS_ALLOW = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]


def _is_whitelisted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in ALWAYS_ALLOW:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def _get_subnet(ip: str, prefix: int = 24) -> str:
    try:
        return str(ipaddress.ip_interface(f"{ip}/{prefix}").network)
    except ValueError:
        return ip


def _run(cmd: list[str]) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=5)
        return r.returncode == 0
    except Exception as e:
        log.error(f"Command failed {' '.join(cmd)}: {e}")
        return False


class BanPlaybook:
    def __init__(self, cfg: dict):
        self._min_level = cfg.get("min_level", 6)
        self._use_honeypot_ipset = cfg.get("use_honeypot_ipset", False)

        # ipset names
        if self._use_honeypot_ipset:
            self._ipset_ips = "honeypot-banned-ips"
            self._ipset_nets = "honeypot-banned-nets"
            log.info("🔗 Ban playbook: using SHARED honeypot ipset")
        else:
            self._ipset_ips = "soar-banned-ips"
            self._ipset_nets = "soar-banned-nets"
            self._ensure_ipsets()
            log.info("🔒 Ban playbook: using standalone SOAR ipset")

        self._banned: set[str] = set()
        self._ban_log = Path("/var/log/soar/banned.txt")

    def _ensure_ipsets(self):
        for name, type_ in [
            (self._ipset_ips, "hash:ip"),
            (self._ipset_nets, "hash:net"),
        ]:
            _run(["ipset", "create", name, type_,
                  "timeout", "0", "maxelem", "1000000"])

        for chain in ["INPUT", "FORWARD"]:
            for ipset in [self._ipset_ips, self._ipset_nets]:
                check = subprocess.run(
                    ["iptables", "-C", chain, "-m", "set",
                     "--match-set", ipset, "src", "-j", "DROP"],
                    capture_output=True
                )
                if check.returncode != 0:
                    _run(["iptables", "-I", chain, "1", "-m", "set",
                          "--match-set", ipset, "src", "-j", "DROP"])

    def should_ban(self, rule_id: int, level: int, category: str) -> bool:
        return level >= self._min_level

    async def execute(self, ip: str, rule_id: int, desc: str) -> bool:
        if _is_whitelisted(ip):
            log.info(f"Ban skipped — whitelisted: {ip}")
            return False

        if ip in self._banned:
            return False

        self._banned.add(ip)

        # Async wrapper around blocking ipset calls
        loop = asyncio.get_running_loop()
        ok_ip = await loop.run_in_executor(
            None, lambda: _run(["ipset", "add", self._ipset_ips, ip, "-exist"])
        )

        cat = "generic"
        for c, cfg in CATEGORY_CONFIG.items():
            pass  # category already known from caller
        # get category from rule_id
        if 100100 <= rule_id <= 100999:
            cat = "web_attack"
        elif 101000 <= rule_id <= 101999:
            cat = "mitre_attack"

        cc = CATEGORY_CONFIG.get(cat, CATEGORY_CONFIG["generic"])
        if cc["ban_subnet"]:
            subnet = _get_subnet(ip, cc["subnet_prefix"])
            await loop.run_in_executor(
                None,
                lambda: _run(["ipset", "add", self._ipset_nets, subnet, "-exist"])
            )
            log.warning(f"🚫 Banned IP {ip} + subnet {subnet} [rule {rule_id}]")
        else:
            log.warning(f"🚫 Banned IP {ip} [rule {rule_id}]")

        # Append to ban log
        with open(self._ban_log, "a") as f:
            f.write(f"{ip}\t{rule_id}\t{desc}\n")

        return ok_ip

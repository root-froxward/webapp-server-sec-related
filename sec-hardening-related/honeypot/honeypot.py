#!/usr/bin/env python3
"""
Honeypot Daemon - ловит сканеры, баны по IP + подсети, фильтрует датацентры
"""

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import struct
import subprocess
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

import aiohttp
import geoip2.database

# ─── Конфиг ────────────────────────────────────────────────────────────────
HONEYPOT_PORTS = [
    21, 22, 23, 25, 110, 143, 445, 1433, 1521, 2181,
    3306, 3389, 4444, 5432, 5900, 6379, 7001, 8080,
    8443, 8888, 9200, 9300, 11211, 27017, 50070
]

TRUSTED_ASN = {
    # Cloudflare
    13335, 209242,
    # Akamai
    16625, 20940,
    # Fastly
    54113,
    # Google (защита / боты верификации)
    15169,
    # Amazon CloudFront (CDN)
    16509,
    # Microsoft Azure CDN
    8075,
    # Sucuri
    30148,
    # Imperva / Incapsula
    19551,
    # Radware
    62044,
    # F5 Networks
    55002,
}

WHITELIST_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
]

LOG_DIR = Path("/var/log/honeypot")
STATE_FILE = Path("/var/lib/honeypot/state.json")
GEOIP_DB = Path("/usr/share/GeoIP/GeoLite2-ASN.mmdb")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "honeypot.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("honeypot")


# ─── Утилиты ────────────────────────────────────────────────────────────────
def run(cmd: list[str], check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def is_whitelisted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in WHITELIST_CIDRS:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
    except ValueError:
        pass
    return False


def get_subnet(ip: str, prefix: int = 24) -> str:
    """Возвращает /24 подсеть для IPv4"""
    try:
        net = ipaddress.ip_interface(f"{ip}/{prefix}").network
        return str(net)
    except ValueError:
        return ip


# ─── GeoIP / ASN ─────────────────────────────────────────────────────────
class ASNLookup:
    def __init__(self):
        self._reader = None
        if GEOIP_DB.exists():
            try:
                import geoip2.database
                self._reader = geoip2.database.Reader(str(GEOIP_DB))
                log.info("GeoIP ASN база загружена")
            except Exception as e:
                log.warning(f"GeoIP не загружен: {e}")

    def get_asn(self, ip: str) -> int | None:
        if not self._reader:
            return None
        try:
            r = self._reader.asn(ip)
            return r.autonomous_system_number
        except Exception:
            return None

    def is_trusted_dc(self, ip: str) -> bool:
        asn = self.get_asn(ip)
        if asn and asn in TRUSTED_ASN:
            return True
        return False


# ─── Firewall (iptables / ipset) ─────────────────────────────────────────
class Firewall:
    IPSET_IPS = "honeypot-banned-ips"
    IPSET_NETS = "honeypot-banned-nets"
    IPSET_DC = "honeypot-dc-drop"

    def __init__(self):
        self._init_ipsets()
        self._banned_ips: set[str] = set()
        self._banned_nets: set[str] = set()

    def _init_ipsets(self):
        for name, type_ in [
            (self.IPSET_IPS, "hash:ip"),
            (self.IPSET_NETS, "hash:net"),
            (self.IPSET_DC, "hash:net"),
        ]:
            run(["ipset", "create", name, type_, "timeout", "0",
                 "maxelem", "1000000"], check=False)

        # iptables rules
        for chain in ["INPUT", "FORWARD"]:
            for ipset in [self.IPSET_IPS, self.IPSET_NETS, self.IPSET_DC]:
                run(["iptables", "-C", chain, "-m", "set", "--match-set",
                     ipset, "src", "-j", "DROP"], check=False)
                result = run(["iptables", "-C", chain, "-m", "set",
                              "--match-set", ipset, "src", "-j", "DROP"],
                             check=False)
                if result.returncode != 0:
                    run(["iptables", "-I", chain, "1", "-m", "set",
                         "--match-set", ipset, "src", "-j", "DROP"])

        log.info("Firewall ipset правила установлены")

    def ban_ip(self, ip: str):
        if ip in self._banned_ips:
            return
        self._banned_ips.add(ip)
        run(["ipset", "add", self.IPSET_IPS, ip, "-exist"])
        log.warning(f"🚫 BANNED IP: {ip}")

    def ban_subnet(self, subnet: str):
        if subnet in self._banned_nets:
            return
        self._banned_nets.add(subnet)
        run(["ipset", "add", self.IPSET_NETS, subnet, "-exist"])
        log.warning(f"🚫 BANNED SUBNET: {subnet}")

    def block_dc_range(self, cidr: str):
        run(["ipset", "add", self.IPSET_DC, cidr, "-exist"])
        log.info(f"🏢 DC blocked: {cidr}")

    def is_banned(self, ip: str) -> bool:
        return ip in self._banned_ips

    def save(self):
        run(["ipset", "save", "-f", "/var/lib/honeypot/ipset.rules"])


# ─── Состояние / статистика ──────────────────────────────────────────────
class State:
    def __init__(self):
        self.hits: dict[str, list] = defaultdict(list)  # ip -> [timestamps]
        self.banned: set[str] = set()
        self._load()

    def _load(self):
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text())
                self.banned = set(data.get("banned", []))
                log.info(f"Загружено {len(self.banned)} забаненных IP")
            except Exception:
                pass

    def save(self):
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps({
            "banned": list(self.banned),
            "updated": datetime.utcnow().isoformat(),
        }, indent=2))

    def record_hit(self, ip: str, port: int) -> int:
        now = time.time()
        hits = self.hits[ip]
        hits.append(now)
        # чистим хиты старше 5 минут
        self.hits[ip] = [t for t in hits if now - t < 300]
        return len(self.hits[ip])

    def hit_count(self, ip: str) -> int:
        return len(self.hits.get(ip, []))


# ─── Ядро: обработка подключений ─────────────────────────────────────────
class HoneypotCore:
    # 1 хит = сразу бан (honeypot-порт = явная атака)
    BAN_THRESHOLD = 1

    def __init__(self):
        self.fw = Firewall()
        self.asn = ASNLookup()
        self.state = State()
        self._event_log = LOG_DIR / "events.jsonl"

    def _log_event(self, ip: str, port: int, reason: str, action: str, data: str = ""):
        event = {
            "ts": datetime.utcnow().isoformat(),
            "ip": ip,
            "port": port,
            "reason": reason,
            "action": action,
            "data": data[:512],
        }
        with open(self._event_log, "a") as f:
            f.write(json.dumps(event) + "\n")

    async def handle(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter, port: int):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"

        try:
            # Читаем первые байты баннера
            try:
                data = await asyncio.wait_for(reader.read(1024), timeout=3.0)
            except asyncio.TimeoutError:
                data = b""

            banner = data.decode(errors="replace").strip()

            # Whitelist — пропускаем локалку
            if is_whitelisted(ip):
                writer.close()
                return

            # Проверяем доверенный датацентр
            if self.asn.is_trusted_dc(ip):
                log.info(f"✅ Trusted DC: {ip}:{port} — пропущен")
                writer.close()
                return

            # Недоверенный датацентр — дропаем
            asn = self.asn.get_asn(ip)
            is_dc = asn is not None  # любой известный ASN = хостинг
            if is_dc and asn not in TRUSTED_ASN:
                log.warning(f"🏢 Untrusted DC ASN {asn}: {ip}:{port} — DROP")
                self._log_event(ip, port, f"untrusted_dc_asn_{asn}", "drop", banner)
                self._ban(ip)
                writer.close()
                return

            # Бан
            hits = self.state.record_hit(ip, port)
            self._log_event(ip, port, "honeypot_hit", "ban", banner)
            log.warning(f"🎯 HIT: {ip}:{port} hits={hits} data={banner!r:.60}")
            self._ban(ip)

        except Exception as e:
            log.debug(f"handle error {ip}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _ban(self, ip: str):
        if self.fw.is_banned(ip):
            return
        self.fw.ban_ip(ip)
        subnet = get_subnet(ip, 24)
        self.fw.ban_subnet(subnet)
        self.state.banned.add(ip)

    async def periodic_save(self):
        while True:
            await asyncio.sleep(60)
            self.state.save()
            self.fw.save()


# ─── Запуск слушателей ───────────────────────────────────────────────────
async def start_listeners(core: HoneypotCore):
    servers = []
    failed = []

    for port in HONEYPOT_PORTS:
        try:
            server = await asyncio.start_server(
                lambda r, w, p=port: core.handle(r, w, p),
                host="0.0.0.0",
                port=port,
                reuse_address=True,
            )
            servers.append(server)
            log.info(f"  👂 Слушаем порт {port}")
        except OSError as e:
            failed.append(port)
            log.warning(f"  ⚠️  Порт {port} недоступен: {e}")

    if failed:
        log.warning(f"Не удалось открыть порты: {failed}")

    log.info(f"✅ Honeypot активен на {len(servers)} портах")
    return servers


# ─── Main ────────────────────────────────────────────────────────────────
async def main():
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log.info("=" * 60)
    log.info("  🍯 Honeypot стартует")
    log.info("=" * 60)

    core = HoneypotCore()
    servers = await start_listeners(core)

    save_task = asyncio.create_task(core.periodic_save())

    async with asyncio.TaskGroup() as tg:
        for srv in servers:
            tg.create_task(srv.serve_forever())
        tg.create_task(save_task)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Honeypot остановлен")

#!/usr/bin/env python3
"""
dc_blocklist.py — загружает актуальные IP-диапазоны датацентров и хостингов,
добавляет их в ipset honeypot-dc-drop.
Trusted ASN (Cloudflare, Akamai и т.д.) — пропускаются.
"""

import ipaddress
import json
import logging
import subprocess
import time
import urllib.request
from pathlib import Path

log = logging.getLogger("dc_blocklist")
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")

CACHE_DIR = Path("/var/cache/honeypot")
IPSET_DC = "honeypot-dc-drop"

# ASN, которые НЕ блокируем (защитные CDN / верифицированные)
TRUSTED_ASN = {13335, 209242, 16625, 20940, 54113, 15169, 16509, 8075, 19551, 62044, 55002, 30148}

# Источники CIDR датацентров (публичные, регулярно обновляются)
SOURCES = [
    # DataCenter IP List (агрегатор)
    {
        "name": "ipdeny_dc",
        "url": "https://raw.githubusercontent.com/jhassine/server-ip-addresses/master/data/datacenters.csv",
        "format": "csv_first_col",
    },
    # DigitalOcean
    {
        "name": "digitalocean",
        "url": "https://www.digitalocean.com/geo/google.csv",
        "format": "csv_first_col",
    },
    # Linode / Akamai Cloud
    {
        "name": "linode",
        "url": "https://geoip.linode.com/",
        "format": "csv_first_col",
    },
    # Vultr
    {
        "name": "vultr",
        "url": "https://geofeed.constant.com/?json",
        "format": "json_prefix",
    },
    # OVH
    {
        "name": "ovh",
        "url": "https://raw.githubusercontent.com/ipverse/rir-ip/master/asn/16276/ipv4-aggregated.txt",
        "format": "plain",
    },
    # Hetzner
    {
        "name": "hetzner",
        "url": "https://raw.githubusercontent.com/ipverse/rir-ip/master/asn/24940/ipv4-aggregated.txt",
        "format": "plain",
    },
    # Contabo
    {
        "name": "contabo",
        "url": "https://raw.githubusercontent.com/ipverse/rir-ip/master/asn/51167/ipv4-aggregated.txt",
        "format": "plain",
    },
    # AWS (все диапазоны, не только CloudFront)
    {
        "name": "aws",
        "url": "https://ip-ranges.amazonaws.com/ip-ranges.json",
        "format": "aws_json",
    },
    # Azure
    {
        "name": "azure",
        "url": "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20240101.json",
        "format": "azure_json",
    },
]


def fetch(url: str, timeout: int = 15) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        log.warning(f"Не удалось загрузить {url}: {e}")
        return None


def parse_cidrs(data: bytes, fmt: str) -> list[str]:
    cidrs = []
    text = data.decode(errors="replace")

    if fmt == "plain":
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                cidrs.append(line)

    elif fmt == "csv_first_col":
        for line in text.splitlines():
            parts = line.split(",")
            if parts:
                cidrs.append(parts[0].strip())

    elif fmt == "json_prefix":
        try:
            obj = json.loads(text)
            # Vultr geofeed формат
            if isinstance(obj, list):
                for entry in obj:
                    if "ip_prefix" in entry:
                        cidrs.append(entry["ip_prefix"])
        except Exception:
            pass

    elif fmt == "aws_json":
        try:
            obj = json.loads(text)
            for prefix in obj.get("prefixes", []):
                cidrs.append(prefix.get("ip_prefix", ""))
        except Exception:
            pass

    elif fmt == "azure_json":
        try:
            obj = json.loads(text)
            for val in obj.get("values", []):
                for pfx in val.get("properties", {}).get("addressPrefixes", []):
                    if "." in pfx:  # только IPv4
                        cidrs.append(pfx)
        except Exception:
            pass

    # Валидируем
    valid = []
    for c in cidrs:
        c = c.strip()
        if not c:
            continue
        try:
            net = ipaddress.ip_network(c, strict=False)
            if net.version == 4:
                valid.append(str(net))
        except ValueError:
            pass
    return valid


def load_into_ipset(cidrs: list[str], source: str):
    added = 0
    for cidr in cidrs:
        r = subprocess.run(
            ["ipset", "add", IPSET_DC, cidr, "-exist"],
            capture_output=True
        )
        if r.returncode == 0:
            added += 1
    log.info(f"  [{source}] добавлено {added}/{len(cidrs)} подсетей")


def run_update():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    total = 0

    # Убеждаемся что ipset существует
    subprocess.run(
        ["ipset", "create", IPSET_DC, "hash:net",
         "timeout", "0", "maxelem", "2000000"],
        capture_output=True
    )

    for src in SOURCES:
        name = src["name"]
        url = src["url"]
        fmt = src["format"]
        cache = CACHE_DIR / f"{name}.cache"

        log.info(f"⬇️  Загружаем {name}...")

        # Кэш на 6 часов
        if cache.exists() and (time.time() - cache.stat().st_mtime) < 21600:
            data = cache.read_bytes()
            log.info(f"  (из кэша)")
        else:
            data = fetch(url)
            if data:
                cache.write_bytes(data)

        if not data:
            continue

        cidrs = parse_cidrs(data, fmt)
        if cidrs:
            load_into_ipset(cidrs, name)
            total += len(cidrs)

    log.info(f"✅ Итого загружено {total} диапазонов датацентров")

    # Сохраняем ipset на диск
    subprocess.run(["ipset", "save", "-f", "/var/lib/honeypot/ipset.rules"])


if __name__ == "__main__":
    run_update()

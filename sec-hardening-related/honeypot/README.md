# 🍯 Honeypot — Auto-ban Scanner IPs + Datacenter Blocking

A self-written honeypot in Python/asyncio for Ubuntu/Debian.
Opens decoy ports, catches scanners, bans IPs + subnets, drops unwanted datacenter traffic.

---

## Architecture

```
install.sh
├── sysctl (kernel hardening)
├── ipset (3 tables)
│   ├── honeypot-banned-ips    — banned individual IPs
│   ├── honeypot-banned-nets   — banned /24 subnets
│   └── honeypot-dc-drop       — unwanted datacenter ranges
├── iptables → ipset (DROP rules)
├── honeypot.py (main daemon)
│   ├── asyncio listeners on 25 ports
│   ├── ASN lookup (MaxMind GeoLite2)
│   ├── Trusted CDN whitelist
│   └── Autoban → ipset
└── dc_blocklist.py (updated every 6h)
    ├── DigitalOcean, Linode, Vultr, OVH
    ├── Hetzner, Contabo, AWS, Azure
    └── → ipset honeypot-dc-drop
```

---

## Installation

```bash
git clone <repo> /tmp/honeypot
cd /tmp/honeypot
sudo bash install.sh
```

Requirements: Ubuntu 20.04+ / Debian 11+, root access.

---

## Honeypot Ports (decoys)

| Port  | Simulated Service  |
|-------|--------------------|
| 21    | FTP                |
| 22    | SSH                |
| 23    | Telnet             |
| 25    | SMTP               |
| 110   | POP3               |
| 143   | IMAP               |
| 445   | SMB                |
| 1433  | MSSQL              |
| 1521  | Oracle             |
| 3306  | MySQL              |
| 3389  | RDP                |
| 4444  | Metasploit shell   |
| 5432  | PostgreSQL         |
| 5900  | VNC                |
| 6379  | Redis              |
| 7001  | WebLogic           |
| 8080  | HTTP proxy         |
| 8443  | HTTPS alt          |
| 8888  | Jupyter / misc     |
| 9200  | Elasticsearch      |
| 9300  | Elasticsearch      |
| 11211 | Memcached          |
| 27017 | MongoDB            |
| 50070 | Hadoop NameNode    |

---

## Ban Logic

```
Incoming connection on honeypot port
│
├── Local network (RFC1918) → ALLOW
│
├── Trusted ASN (Cloudflare, Akamai, etc.) → ALLOW
│
├── Known ASN, not trusted → DROP + ban IP + /24
│
└── Regular IP → ban_ip() + ban_subnet(/24)
    ├── ipset add honeypot-banned-ips <ip>
    └── ipset add honeypot-banned-nets <ip>/24
```

---

## Trusted CDN / Security Services (NOT blocked)

| ASN   | Provider                  |
|-------|---------------------------|
| 13335 | Cloudflare                |
| 16625 | Akamai CDN                |
| 20940 | Akamai Technologies       |
| 54113 | Fastly                    |
| 15169 | Google (verification bots)|
| 16509 | Amazon CloudFront         |
| 8075  | Microsoft Azure CDN       |
| 19551 | Imperva / Incapsula       |
| 62044 | Radware                   |
| 55002 | F5 Networks               |
| 30148 | Sucuri                    |

---

## Management Commands

```bash
# Service status
systemctl status honeypot

# Live logs
tail -f /var/log/honeypot/honeypot.log

# All events (JSON)
tail -f /var/log/honeypot/events.jsonl

# List banned IPs
ipset list honeypot-banned-ips

# Count banned subnets
ipset list honeypot-banned-nets | wc -l

# Count blocked DC ranges
ipset list honeypot-dc-drop | wc -l

# Manually unban an IP
ipset del honeypot-banned-ips 1.2.3.4
ipset del honeypot-banned-nets 1.2.3.0/24

# Force DC blocklist update
systemctl start honeypot-dc-update.service
journalctl -u honeypot-dc-update.service -f

# Restart
systemctl restart honeypot
```

---

## File Locations

| Path | Description |
|------|-------------|
| `/opt/honeypot/honeypot.py` | Main daemon |
| `/opt/honeypot/dc_blocklist.py` | DC range downloader |
| `/var/log/honeypot/honeypot.log` | System log |
| `/var/log/honeypot/events.jsonl` | All events in JSON |
| `/var/lib/honeypot/state.json` | State (ban list) |
| `/var/lib/honeypot/ipset.rules` | ipset dump (persistent) |
| `/var/cache/honeypot/` | DC list cache |
| `/etc/sysctl.d/99-honeypot.conf` | Kernel hardening |

---

## Customization

### Add custom ports

In `honeypot.py`, edit `HONEYPOT_PORTS`:

```python
HONEYPOT_PORTS = [
    21, 22, 23, ...,
    1234,  # ← add your port here
]
```

Then restart: `systemctl restart honeypot`

### Add trusted ASN

In `honeypot.py`, edit `TRUSTED_ASN`:

```python
TRUSTED_ASN = {
    13335,  # Cloudflare
    99999,  # ← your ASN
}
```

### Add IP to whitelist

In `honeypot.py`, edit `WHITELIST_CIDRS`:

```python
WHITELIST_CIDRS = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "1.2.3.4/32",  # ← your IP
]
```

---

## Uninstall

```bash
systemctl stop honeypot honeypot-dc-update.timer
systemctl disable honeypot honeypot-dc-update.timer honeypot-dc-update.service
rm /etc/systemd/system/honeypot*.service /etc/systemd/system/honeypot*.timer
systemctl daemon-reload

# Remove ipset rules from iptables
for s in honeypot-banned-ips honeypot-banned-nets honeypot-dc-drop; do
    iptables -D INPUT -m set --match-set $s src -j DROP 2>/dev/null || true
    iptables -D FORWARD -m set --match-set $s src -j DROP 2>/dev/null || true
    ipset destroy $s 2>/dev/null || true
done

rm -rf /opt/honeypot /var/log/honeypot /var/lib/honeypot /var/cache/honeypot
rm -f /etc/sysctl.d/99-honeypot.conf /etc/logrotate.d/honeypot
sysctl --system
```

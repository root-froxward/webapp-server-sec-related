# Wazuh DDoS & Web Attack Protection Suite
#  (c) 2024-2026 thelema-froxward
# Licensed under the MIT License
Automated threat detection and mitigation for Wazuh. Detects network-level DDoS and common web application attacks, then blocks the source using multiple layers — from kernel-level ipset/iptables to nginx, fail2ban, and optionally Cloudflare.

## What it does

The suite adds two sets of custom rules to Wazuh and an active response script that reacts to alerts in real time.

Detection covers:

- L3/L4 DDoS: SYN flood, UDP flood, ICMP flood, RST/ACK flood, IP fragmentation attacks
- Amplification attacks: DNS, NTP, SSDP, Memcached
- L7 DDoS: HTTP flood, Slowloris, slow POST, bot floods, distributed floods
- SQL injection (union, boolean, time-based, error-based, file write / RCE via SQL)
- XSS, LFI, RFI, SSRF, XXE, SSTI, command injection, deserialization
- Known CVEs: Log4Shell, Spring4Shell, Shellshock
- Webshell access and upload attempts
- Brute force, auth bypass, JWT algorithm none
- Scanner detection (sqlmap, nikto, nmap, gobuster, etc.)
- IDOR enumeration, open redirect, sensitive file probes
- Multi-vector correlation (DDoS + exploitation as smokescreen)

When an alert fires, the active response script applies a combination of countermeasures depending on the attack type:

- ipset block (kernel-level, with configurable timeout)
- iptables rate limiting (per-source hashlimit)
- nginx deny
- WAF deny rules
- fail2ban integration
- Cloudflare edge block (optional, API-based)
- Incident file creation for critical threats (RCE, webshell, Log4Shell)

All rules are mapped to MITRE ATT&CK techniques.

## Components

| File | Purpose |
|------|---------|
| `install.sh` | Interactive installer. Handles dependencies, ipset/iptables setup, kernel hardening, nginx rate limiting, fail2ban config, Wazuh rule deployment, and ossec.conf patching. |
| `0100-ddos-detection.xml` | Wazuh rules for DDoS detection (rule IDs 100100–100132) |
| `0110-web-vuln-detection.xml` | Wazuh rules for web attack detection (rule IDs 110100–110301) |
| `auto-mitigate.py` | Active response script. Reads Wazuh alerts from stdin, determines attack type, applies appropriate countermeasures. |

## Requirements

- Wazuh manager (tested on 4.x)
- Linux (Debian/Ubuntu or RHEL/CentOS)
- nginx or Apache (for web attack detection and L7 mitigation)
- Root access
- Python 3 with `requests` (for Cloudflare integration)

## Installation

```
git clone <repo-url>
sudo bash install.sh
```

The installer will ask for whitelist IPs and optional Cloudflare credentials. Everything else is automatic.

## Configuration

After installation, the config lives at `/var/ossec/etc/auto-mitigate.conf`:

```
CF_ENABLED=false
CF_API_TOKEN=
CF_ZONE_ID=
WHITELIST=10.0.0.1,192.168.1.0/24
```

Block durations are defined in `auto-mitigate.py` in the `BLOCK_DURATIONS` dict. Permanent blocks (timeout 0) are set for RCE, webshells, and Log4Shell by default.

## Logs and monitoring

Mitigation log:
```
tail -f /var/log/wazuh/auto-mitigate.log
```

Live alerts:
```
tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
```

Currently blocked IPs:
```
ipset list wazuh_blocked
ipset list wazuh_ddos
```

Critical incidents (manual review needed):
```
ls /var/ossec/logs/critical-incidents/
```

## Unblocking an IP

The active response script supports the `delete` action, which Wazuh calls automatically when a timeout expires. To unblock manually:

```
echo '{"data":{"srcip":"1.2.3.4"}}' | /var/ossec/active-response/bin/auto-mitigate.py delete
```

This removes the IP from ipset, iptables, nginx deny, WAF deny, and fail2ban.

## Notes

- Whitelist your management IPs before deploying to production. Locking yourself out of a remote server is not fun.
- The installer applies sysctl hardening (syncookies, conntrack tuning, etc.) which persists across reboots.
- Cloudflare blocking uses the access rules API. If you have a large number of blocks, consider switching to IP Lists.
- The rules assume nginx or Apache log format. If you use a custom format, you may need to adjust the decoders.

## License

MIT

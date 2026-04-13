```
███████╗██████╗  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ██████╗
██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
█████╗  ██████╔╝██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝██║  ██║
██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██║  ██║
██║     ██║  ██║╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║██████╔╝
╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# Froxward Security Stack

**One-command server hardening** — deploys a full defensive security stack (Wazuh SIEM + ModSecurity WAF + DDoS protection + SOAR automation + Fail2ban) and then audits it with live attack simulations.

# This readme currently for setup.sh and checksec.sh , its not about other files that gonna be added here,other security related files gonna be named and contain readme what the tool does,how it works and how to deploy. You can see other tools in folder sec-hardening-related.
---

## What It Does

**`setup.sh`** installs and configures five layers of defense:

| Layer | Component | What It Covers |
|-------|-----------|---------------|
| SIEM | Wazuh Manager | Log aggregation, threat detection, custom rules, active response |
| WAF | ModSecurity + OWASP CRS 4.7 | SQLi, XSS, RCE, SSRF, XXE, Log4Shell, path traversal, scanner blocking |
| Network | iptables / nftables | SYN flood, ICMP abuse, port scanning, connection rate limits, IP banning |
| Automation | SOAR-lite daemon | Real-time alert classification → automatic IP bans (by severity + attack type) |
| Access | Fail2ban + SSH hardening | Brute force protection, custom jails for ModSecurity/Wazuh/nginx |

**`checksec.sh`** audits the result across 10 categories with a scoring system (0–100% per category, A+/A/B/C/D/F overall grade), including **live attack tests** — it actually sends SQLi, XSS, Log4Shell payloads at your server and verifies they get blocked.

## Supported Systems

- Ubuntu 20.04 / 22.04 / 24.04
- Debian 11 / 12
- CentOS 7 / 8, RHEL 8 / 9, Rocky Linux, AlmaLinux
- Fedora (latest)
- Web servers: nginx (auto-installed if missing) and Apache

---

## Quick Start

```bash
# Deploy everything
sudo bash setup.sh

# Audit the result
sudo bash checksec.sh
```

That's it. The setup autodetects your OS, package manager, web server, firewall backend (nftables vs iptables), and application port.

## Installation Options

```bash
# Skip specific components
sudo bash setup.sh --skip-wazuh
sudo bash setup.sh --skip-modsec
sudo bash setup.sh --skip-ssh

# Set application port explicitly
APP_PORT=3000 sudo bash setup.sh

# Custom Wazuh/CRS versions
WAZUH_VERSION=4.9.2 CRS_VERSION=4.7.0 sudo bash setup.sh

# Show all options
bash setup.sh --help
```

## Audit Options

```bash
# Full audit with terminal output
sudo bash checksec.sh

# JSON output (for CI/CD, monitoring)
sudo bash checksec.sh --json

# Audit only specific modules
sudo bash checksec.sh --only wazuh,ssh,os
sudo bash checksec.sh --only modsec,headers

# Available modules:
#   wazuh, modsec, ddos, soar, fail2ban, headers, ssh, ports, tls, os

# Show all options
bash checksec.sh --help
```

---

## Architecture

```
                    ┌──────────────┐
                    │   Internet   │
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │  Firewall (nft/iptables) │◄──── DDoS L3/L4 rules
              │  SYN flood / rate limits │      banned_ips set
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │    nginx / Apache       │◄──── Security headers
              │    + ModSecurity WAF    │      Rate limiting (L7)
              │    + OWASP CRS (PL2)    │      Slowloris mitigation
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │   Your Application      │
              └────────────┬────────────┘
                           │ logs
              ┌────────────▼────────────┐
              │     Wazuh Manager       │◄──── Custom rules
              │   (SIEM / Log Analysis) │      Active response
              └────────────┬────────────┘
                           │ alerts.json
              ┌────────────▼────────────┐
              │    SOAR-lite Daemon     │──── Classifies alerts
              │  (froxward-response.sh) │     Bans IPs by severity
              └────────────┬────────────┘
                           │
              ┌────────────▼────────────┐
              │      Fail2ban           │◄──── Backup enforcement
              │  (custom jails)         │      SSH, ModSec, nginx, Wazuh
              └─────────────────────────┘
```

### How the SOAR Daemon Works

The SOAR daemon (`froxward-response.sh`) runs as a systemd service, tailing Wazuh's `alerts.json` in real time. When an alert arrives:

1. **Classifies by severity level:**
   - Level ≥ 13 (critical) → ban 24h
   - Level ≥ 10 (high) → ban 2h
   - Level ≥ 7 (medium) → pattern-match on attack type

2. **Pattern-matches attack descriptions:**
   - SQLi / XSS → ban 1h
   - Brute force / port scan → ban 2h
   - Log4Shell / RCE / privilege escalation / malware → ban 24h
   - Scanner detection → ban 1h
   - Unknown medium-severity → rate limit

3. **Rule ID fallback** for lower severity alerts (auth failures, rootcheck, web rules)

4. **Deduplication** — tracks processed alert IDs to avoid double-banning, with automatic file rotation at 50k entries

---

## What Gets Configured

### ModSecurity (WAF)

- OWASP Core Rule Set 4.7 at **Paranoia Level 2**
- Anomaly scoring: inbound threshold 5, outbound threshold 4
- Custom rules on top of CRS: scanner UA blocking, extra SQLi detection, Shellshock, Log4Shell (multi-encoding), path traversal, HTTP smuggling, SSRF, XXE
- Audit logging to `/var/log/modsec_audit.log`

### Firewall (DDoS L3/L4)

- SYN cookies, SYN flood rate limiting
- ICMP rate limiting (10/sec)
- Anti-spoofing (reverse path filtering)
- No source routing, no redirects
- SSH brute force protection (5 attempts/min)
- HTTP/HTTPS connection rate limiting (150/min burst 250)
- UDP amplification port blocking (chargen, NTP, SSDP, memcached, etc.)
- Fragmented packet dropping
- Dynamic `banned_ips` set for SOAR integration (nftables) or `FROXWARD_BANNED` chain (iptables)

### Kernel Hardening (sysctl)

- TCP SYN cookies, reduced retries/backlog
- Conntrack tuning (1M max, reduced timeouts)
- TCP keepalive optimization
- Large socket buffers (16MB)
- TCP TIME-WAIT reuse

### Fail2ban

Six jails out of the box:

| Jail | Trigger | Ban Time |
|------|---------|----------|
| `sshd` | 3 failed auths | 24h |
| `nginx-http-auth` | HTTP auth failures | 1h |
| `nginx-botsearch` | 2 bot/scanner hits | 24h |
| `nginx-req-limit` | 10 rate limit violations | 30m |
| `modsec` | 3 WAF triggers | 6h |
| `wazuh-high-alerts` | 1 high-severity alert | 2h |

### SSH Hardening

- Root login disabled
- Max 3 auth tries, 30s login grace
- No X11/agent/TCP forwarding
- 5-minute idle timeout
- Max 3 sessions per connection
- Keepalive and compression disabled

### nginx Security

- All standard security headers (CSP, HSTS, X-Frame-Options, etc.)
- Server version hidden
- L7 rate limiting zones (global 30r/m, API 10r/m, login 5r/m)
- Slowloris mitigation (10s body/header timeout)
- Request body limits (10MB max)
- Scanner UA map + bad HTTP method blocking (TRACE, TRACK, CONNECT)

---

## Audit Report

`checksec.sh` produces output like this:

```
[ Security Audit Results ]

  Wazuh SIEM             95% [███████████████████░] 95/100
  ModSecurity + CRS      87% [█████████████████░░░] 87/100
  DDoS Protection        90% [██████████████████░░] 90/100
  SOAR Response         100% [████████████████████] 100/100
  Fail2ban              100% [████████████████████] 100/100
  HTTP Headers           85% [█████████████████░░░] 85/100
  SSH Hardening         100% [████████████████████] 100/100
  Port Security         100% [████████████████████] 100/100
  TLS/SSL                80% [████████████████░░░░] 80/100
  OS Hardening           85% [█████████████████░░░] 85/100

  Total: 922/1000 points
  Score: 92%
  Grade: A+
  Checks: 42 passed / 2 failed / 3 warnings
```

### Live Tests Performed

The audit doesn't just check configs — it actively tests defenses:

| Test | What Happens |
|------|-------------|
| SQLi probe | Sends `?id=1' OR '1'='1` — expects 403 |
| XSS probe | Sends `?q=<script>alert(1)</script>` — expects 403 |
| Log4Shell probe | Sends `${jndi:ldap://...}` in header — expects 403 |
| Path traversal | Sends `/../../etc/passwd` — expects 403 |
| Scanner UA | Sends `User-Agent: sqlmap/1.0` — expects 403 |
| Rate limiting | 60 rapid requests — expects throttling |
| Slowloris | Incomplete HTTP request — expects timeout |
| Wazuh detection | Fake SSH failure — checks alert generated |
| SOAR response | Injects level-13 alert — checks IP banned within 4s |
| Fail2ban SSH | 5 fake auth failures in log — checks IP banned |
| Port scan | Checks 16 dangerous ports not exposed |
| TLS versions | Verifies SSLv3/TLSv1.0 disabled, TLS 1.2/1.3 enabled |

---

## File Locations

| File | Purpose |
|------|---------|
| `/var/log/froxward_soar.log` | SOAR daemon activity log |
| `/var/log/froxward_setup.log` | Installation log |
| `/var/log/modsec_audit.log` | ModSecurity audit events |
| `/var/ossec/logs/alerts/alerts.json` | Wazuh alerts (SOAR input) |
| `/var/ossec/etc/rules/*.xml` | Custom Wazuh detection rules |
| `/etc/modsecurity/` | ModSecurity config + CRS rules |
| `/etc/modsecurity/custom_rules.conf` | Custom WAF rules |
| `/etc/modsecurity/bad_agents.txt` | Blocked scanner user-agents |
| `/etc/fail2ban/jail.local` | Fail2ban jail configuration |
| `/etc/sysctl.d/99-froxward.conf` | Kernel hardening parameters |
| `/etc/nginx/conf.d/froxward_security.conf` | nginx security config |
| `/usr/local/bin/froxward-response.sh` | SOAR daemon script |
| `/tmp/froxward_banned.db` | Currently banned IPs |
| `/tmp/froxward_checksec_*.txt` | Audit text reports |

## Services

```bash
# SOAR daemon
systemctl status froxward-soar
journalctl -u froxward-soar -f

# Wazuh
systemctl status wazuh-manager

# Fail2ban
fail2ban-client status
fail2ban-client status sshd

# Check banned IPs (nftables)
nft list set inet froxward banned_ips

# Check banned IPs (iptables)
iptables -L FROXWARD_BANNED -n

# Unban an IP manually
# nftables:
nft delete element inet froxward banned_ips "{ 1.2.3.4 }"
# iptables:
iptables -D FROXWARD_BANNED -s 1.2.3.4 -j DROP
# fail2ban:
fail2ban-client set sshd unbanip 1.2.3.4
```

---

## CI/CD Integration

Use `checksec.sh --json` in your pipeline to enforce a minimum security grade:

```bash
#!/bin/bash
RESULT=$(sudo bash checksec.sh --json)
GRADE=$(echo "$RESULT" | jq -r '.grade')
PERCENT=$(echo "$RESULT" | jq -r '.percent')

echo "Security grade: $GRADE ($PERCENT%)"

if (( PERCENT < 80 )); then
    echo "FAIL: Security score below 80%"
    exit 1
fi
```

---

## Requirements

- Root access
- Bash 4.0+
- Internet access (for package downloads, Wazuh repo, OWASP CRS)
- ~500MB disk space for all components

## License

MIT

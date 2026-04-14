# WAF Extension Module

Extension for [wazuh-protection-suite](../README.md). Adds ModSecurity with OWASP Core Rule Set, CrowdSec collective threat intelligence, security headers, rate limiting, and GeoIP country blocking. Integrates with the existing Wazuh active response pipeline — blocked IPs go through the same ipset/iptables/nginx/fail2ban/Cloudflare chain.

## What it adds

**ModSecurity + OWASP CRS** — full WAF with request inspection, anomaly scoring, and blocking. Supports both nginx (libmodsecurity3) and Apache (mod_security2). CRS is pre-tuned at paranoia level 2 with an anomaly threshold of 10 to balance detection and false positives on a fresh install.

**CrowdSec** — community-driven IP reputation engine. Shares threat signals with other CrowdSec users and receives blocklists in return. Installs the appropriate bouncer (nginx or firewall) and sets up log acquisition for your web server and ModSecurity audit logs.

**Security headers** — HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and Cross-Origin policies. Applied via include files so you can customize per virtual host.

**Rate limiting** — zone-based rate limiting for nginx (general, login, API, upload, static) and mod_evasive for Apache. More granular than the basic rate limiting in the base installer.

**GeoIP blocking** — country-level allow/deny using MaxMind or DB-IP databases. Supports both deny mode (block specific countries) and allow mode (allow only specific countries). Weekly auto-update via cron.

**Wazuh rules** — custom rules (0120-modsec-waf.xml) that detect ModSecurity blocks, CRS anomaly events, CrowdSec bans, rate limit hits, and correlate WAF + reputation signals. All tied to the existing auto-mitigate.py active response.

## Prerequisites

The base wazuh-protection-suite must be installed first (`install.sh`). This module extends it.

## Installation

Full install (interactive):
```
cd waf/
sudo bash install-waf.sh
```

Full install (non-interactive):
```
sudo bash install-waf.sh --all
```

Single module:
```
sudo bash install-waf.sh --module modsec
sudo bash install-waf.sh --module crowdsec
sudo bash install-waf.sh --module headers
sudo bash install-waf.sh --module ratelimit
sudo bash install-waf.sh --module geoip --geoip-mode deny
```

## Structure

```
waf/
├── install-waf.sh              # main installer
├── lib.sh                      # shared functions
├── modules/
│   ├── modsec-nginx.sh         # ModSecurity v3 for nginx
│   ├── modsec-apache.sh        # mod_security2 for Apache
│   ├── owasp-crs.sh            # OWASP CRS download and setup
│   ├── crowdsec.sh             # CrowdSec + bouncer
│   ├── security-headers.sh     # HTTP security headers
│   ├── rate-limit.sh           # rate limiting
│   └── geoip.sh                # GeoIP country blocking
├── conf/
│   ├── modsecurity.conf        # ModSecurity engine config
│   ├── crs-setup.conf          # CRS tuning (paranoia, thresholds)
│   ├── crowdsec-whitelist.yaml # CrowdSec IP whitelist
│   └── geoip-countries.conf    # country codes to block/allow
└── wazuh-rules/
    └── 0120-modsec-waf.xml     # Wazuh detection rules for WAF events
```

## Configuration

**ModSecurity tuning** — edit `conf/modsecurity.conf` and `conf/crs-setup.conf`. The main knobs are paranoia level (1-4) and anomaly score threshold. Start at PL2/threshold 10, monitor `/var/log/modsec_audit.log` for false positives, then tighten.

**CrowdSec** — the whitelist is in `conf/crowdsec-whitelist.yaml`. CrowdSec decisions and metrics are available via `cscli decisions list` and `cscli metrics`.

**Security headers** — the CSP header is restrictive by default. You will almost certainly need to adjust it for your application. Edit the include file directly on the server after installation.

**GeoIP** — add country codes (ISO 3166-1 alpha-2) to `conf/geoip-countries.conf`, one per line. Set mode with `--geoip-mode deny` or `--geoip-mode allow`.

## Testing

ModSecurity:
```
curl -I 'http://localhost/?id=1 OR 1=1'
# Should return 403

curl -I 'http://localhost/?page=../../etc/passwd'
# Should return 403
```

Security headers:
```
curl -I https://your-domain.com
# Check for Strict-Transport-Security, X-Frame-Options, etc.
```

CrowdSec:
```
cscli metrics
cscli alerts list
cscli decisions list
```

## Notes

- ModSecurity from source takes 5-10 minutes to build. On Debian 12+ / Ubuntu 22.04+, the prebuilt package is used instead.
- CRS false positives are normal on a fresh install. Monitor the audit log, add exclusions to `crs-setup.conf`, then lower the threshold.
- The GeoIP module falls back to DB-IP Lite (free, no registration) if MaxMind credentials are not configured.
- All WAF events feed into the same auto-mitigate.py from the base suite. No separate blocking logic.

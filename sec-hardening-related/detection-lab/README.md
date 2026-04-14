# froxward-detection-lab

```
██████╗ ███████╗████████╗███████╗ ██████╗████████╗
██╔══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
██║  ██║█████╗     ██║   █████╗  ██║        ██║   
██║  ██║██╔══╝     ██║   ██╔══╝  ██║        ██║   
██████╔╝███████╗   ██║   ███████╗╚██████╗   ██║   
╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   
                        L A B
```

**Adversary simulation + real-time SOAR response for Wazuh.**  
Attack your own infrastructure → see what gets detected → auto-respond.

---

## What's in here

| File | Purpose |
|---|---|
| `simulator.py` | Runs attack simulations across 5 categories, checks Wazuh detection |
| `soar.py` | Real-time Wazuh alert processor — classifies, bans IPs, notifies Telegram |

---

## simulator.py

Simulates real attacks across 5 categories and validates whether Wazuh caught them.

### Categories

| Category | What it simulates |
|---|---|
| **WEB** | SQLi (basic + UNION), XSS, LFI, Log4Shell, RCE, path traversal, SSRF, XXE, scanner UA |
| **NETWORK** | Port scan, SSH brute force (log injection), SYN flood |
| **PRIVESC** | SUID enum, sudo -l, /etc/shadow read, cron abuse, LD_PRELOAD, capabilities enum |
| **LATERAL** | Pass-the-Hash, SMB recon, credential dump, ARP scan |
| **EVASION** | Log clearing, history wipe, timestomp, base64 payload, firewall disable attempt |

### Usage

```bash
# full simulation against local target
sudo python3 simulator.py

# specific target
sudo python3 simulator.py --target http://10.0.0.5 --ip 10.0.0.5

# specific categories only
sudo python3 simulator.py --categories web,privesc

# run without Wazuh (just fire the attacks)
sudo python3 simulator.py --no-wazuh

# JSON report output
sudo python3 simulator.py --json
```

### Example output

```
[10:45:01] [INFO] Web attacks → http://localhost
[10:45:03] [PASS] SQLi Basic → DETECTED (1 alert(s))
[10:45:05] [PASS] SQLi UNION → DETECTED (1 alert(s))
[10:45:07] [PASS] XSS → DETECTED (2 alert(s))
[10:45:09] [FAIL] SSRF → NOT DETECTED (0 alert(s))
...

──────────────────────────────────────────────────────────────
  SIMULATION REPORT  2026-04-10 10:47:22

  WEB          ████████████████░░░░  80%  (8/10)
  NETWORK      ████████████████████ 100%  (3/3)
  PRIVESC      ████████████░░░░░░░░  60%  (5/8)
  LATERAL      ████████████████░░░░  75%  (3/4)
  EVASION      ████████░░░░░░░░░░░░  40%  (2/5)

  Total:        21/30 detected (70%)

  Missed detections:
    [WEB] SSRF
    [WEB] XXE
    [PRIVESC] LD_PRELOAD
    [EVASION] Base64 payload
    [EVASION] Firewall disable attempt
```

Full report saved to `/tmp/froxward_sim_<timestamp>.json`

---

## soar.py

Real-time Wazuh SOAR daemon. Tails `alerts.json`, classifies every alert, and responds automatically.

### How it classifies

1. **Rule ID lookup** — known rule IDs mapped directly to severity + action
2. **Pattern matching** — regex against alert description + data fields
3. **Level fallback** — level ≥ 13 → critical, ≥ 10 → high, ≥ 7 → medium

### Response actions

| Severity | Auto-action | Ban duration |
|---|---|---|
| Critical (≥13 or pattern) | Ban IP | 24h |
| High (≥10) | Ban IP | 2h |
| Medium (≥7) | Ban IP | 1h |
| Low (≥4) | Alert only | — |

**Escalation:** If the same IP triggers 5+ alerts regardless of severity, it gets force-banned for 24h.

### Supported patterns

SQLi, XSS, Log4Shell, LFI/Traversal, Brute Force, Port Scan, Pass-the-Hash, PrivEsc, RCE, Malware, Log Tampering, Lateral Movement, Credential Dump, Defense Evasion, SSRF, XXE, DDoS

### Usage

```bash
# run as daemon (requires root for firewall)
sudo TELEGRAM_TOKEN=xxx TELEGRAM_CHAT=yyy python3 soar.py

# dry run — no actual bans
sudo python3 soar.py --dry-run

# show currently banned IPs
python3 soar.py --status
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `ALERTS_JSON` | `/var/ossec/logs/alerts/alerts.json` | Wazuh alerts file |
| `TELEGRAM_TOKEN` | — | Bot token for notifications |
| `TELEGRAM_CHAT` | — | Chat ID for notifications |
| `SOAR_LOG` | `/var/log/froxward_soar.log` | SOAR log file |
| `BANNED_DB` | `/tmp/froxward_banned.db` | Banned IP persistence |
| `DRY_RUN` | `0` | Set to `1` to disable actual bans |

### Run as systemd service

```ini
[Unit]
Description=Froxward SOAR Daemon
After=wazuh-manager.service

[Service]
ExecStart=/usr/bin/python3 /opt/froxward/soar.py
Environment=TELEGRAM_TOKEN=your_token
Environment=TELEGRAM_CHAT=your_chat_id
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo cp froxward-soar.service /etc/systemd/system/
sudo systemctl enable --now froxward-soar
sudo journalctl -u froxward-soar -f
```

### Telegram notification example

```
🔴 FROXWARD SOAR ALERT
Type: Log4Shell
Severity: CRITICAL (level 13)
Description: Log4Shell JNDI injection attempt
Agent: web-server-01
Source IP: 185.220.101.45
Action: BAN
Time: 2026-04-10 10:45:33
```

---

## Architecture

```
                 ┌─────────────────────┐
                 │   simulator.py      │
                 │  (attack generator) │
                 └──────────┬──────────┘
                            │ fires attacks
                 ┌──────────▼──────────┐
                 │   Your Server       │
                 │  nginx + ModSec     │
                 │  + Wazuh agent      │
                 └──────────┬──────────┘
                            │ generates alerts
                 ┌──────────▼──────────┐
                 │  alerts.json        │
                 │  (Wazuh output)     │
                 └──────────┬──────────┘
                 ┌──────────┴──────────┐
                 │                     │
    ┌────────────▼──────┐   ┌──────────▼──────────┐
    │  simulator.py     │   │    soar.py           │
    │  (reads alerts,   │   │  (real-time tail,    │
    │   reports missed  │   │   classify, ban,     │
    │   detections)     │   │   notify Telegram)   │
    └───────────────────┘   └─────────────────────┘
```

---

## Requirements

- Python 3.8+
- Wazuh Manager running (for detection checks)
- Root (for network attacks + firewall bans)
- `curl`, `nmap` (optional), `hping3` (optional)

## Related repos

- [froxward-security-stack](https://github.com/root-froxward/webapp-server-sec-related) — full server hardening suite this lab tests against
- [wazuh-rules](https://github.com/root-froxward/wazuh-rules) — custom detection rules
- [wazuh-soar](https://github.com/root-froxward/wazuh-SOAR) — standalone SOAR

## License

MIT

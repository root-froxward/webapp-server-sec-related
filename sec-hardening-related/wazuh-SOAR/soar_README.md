# 🛡️ SOAR — Security Orchestration, Automation & Response

Lightweight self-written SOAR for Wazuh, built specifically around the
[wazuh-rules](https://github.com/root-froxward/wazuh-rules) rule set
(web-attacks `100100–100999`, MITRE ATT&CK `101000–101999`).
Recommended to use with honeypot (shared IPset)
[honeypot](https://github.com/root-froxward/webapp-server-sec-related/tree/main/sec-hardening-related/honeypot)
Polls the Wazuh API, classifies alerts by rule ID, and automatically:
- **Bans attacker IPs** via ipset/iptables (+ /24 subnet)
- **Sends Telegram notifications** with full alert context

---

## Architecture

```
Wazuh Manager API (polling every 15s)
        │
        ▼
   SOAREngine
   ├── WazuhClient     — JWT auth, pagination, cursor-based polling
   ├── Deduplicator    — suppresses duplicate alerts (5 min window)
   ├── classify_rule() — maps rule ID → category
   │       100100–100999 → web_attack
   │       101000–101999 → mitre_attack
   │
   └── Playbook Dispatch
       ├── BanPlaybook     — ipset add IP + /24 subnet
       └── TelegramPlaybook — sends formatted alert message
```

---

## Installation

```bash
git clone https://github.com/root-froxward/wazuh-rules /tmp/wazuh-soar
cd /tmp/wazuh-soar/soar
sudo bash install.sh
```

The installer will ask whether to share the ban list with the honeypot.

---

## Configuration

Edit `/etc/soar/config.yaml` before starting the service:

```yaml
wazuh:
  url: "https://127.0.0.1:55000"
  username: "wazuh"
  password: "YOUR_PASSWORD"

telegram:
  enabled: true
  bot_token: "123456:ABC-..."
  chat_id: "-100xxxxxxxxx"

ban:
  enabled: true
  min_level: 6
  use_honeypot_ipset: false   # true = share ban list with honeypot
```

Then start:

```bash
systemctl start soar
systemctl status soar
```

---

## Honeypot Integration

If you have the [honeypot](../honeypot/) installed on the same machine,
you can share a single ban list between both tools.

Set in `/etc/soar/config.yaml`:

```yaml
ban:
  use_honeypot_ipset: true
```

With this enabled:
- IPs caught by the **honeypot** are instantly blocked for **SOAR** too
- IPs caught by **Wazuh rules** are instantly blocked for the **honeypot** too
- Both use the same `honeypot-banned-ips` and `honeypot-banned-nets` ipsets

The installer will ask about this automatically.

---

## Alert Classification

| Rule ID Range | Category      | Action                      |
|---------------|---------------|-----------------------------|
| 100100–100999 | `web_attack`  | Ban IP + /24 subnet, Notify |
| 101000–101999 | `mitre_attack`| Ban IP + /24 subnet, Notify |
| Other         | `generic`     | Notify only (no subnet ban) |

---

## Telegram Message Format

```
🔴 🌐 SOAR Alert
━━━━━━━━━━━━━━━━━━━━
📋 Rule: 100312 — SQL injection attempt detected
⚡ Level: 10
🖥️ Agent: web-server-01
🌍 Source IP: 185.220.101.45
🔗 URL: /wp-admin/admin-ajax.php?action=...
📡 Method: POST
━━━━━━━━━━━━━━━━━━━━
🕐 2026-04-14 11:23:05 UTC
```

For MITRE alerts, tactic and technique IDs are included:
```
🎯 Tactic: Lateral Movement
🔗 Technique: T1021.001
```

---

## Management Commands

```bash
# Service control
systemctl start soar
systemctl stop soar
systemctl restart soar
systemctl status soar

# Live logs
tail -f /var/log/soar/soar.log

# All processed events (JSON)
tail -f /var/log/soar/events.jsonl | jq .

# All banned IPs
cat /var/log/soar/banned.txt

# View ipset (standalone mode)
ipset list soar-banned-ips

# View ipset (honeypot shared mode)
ipset list honeypot-banned-ips

# Manually unban
ipset del soar-banned-ips 1.2.3.4
ipset del soar-banned-nets 1.2.3.0/24
```

---

## File Locations

| Path | Description |
|------|-------------|
| `/opt/soar/soar.py` | Main engine |
| `/opt/soar/wazuh_client.py` | Wazuh API client |
| `/opt/soar/playbooks/ban.py` | IP ban playbook |
| `/opt/soar/playbooks/telegram.py` | Telegram playbook |
| `/etc/soar/config.yaml` | Configuration |
| `/var/log/soar/soar.log` | Engine log |
| `/var/log/soar/events.jsonl` | Processed events (JSON) |
| `/var/log/soar/banned.txt` | Plain text ban log |

---

## Tuning

### Change minimum alert level

In `config.yaml`:
```yaml
min_alert_level: 8   # only process level 8+
```

### Add more rule ID ranges

In `soar.py`, edit `classify_rule()`:
```python
def classify_rule(rule_id: int) -> str:
    if 100100 <= rule_id <= 100999:
        return "web_attack"
    if 101000 <= rule_id <= 101999:
        return "mitre_attack"
    if 102000 <= rule_id <= 102999:   # ← your new category
        return "my_category"
    return "generic"
```

### Whitelist an IP from banning

In `playbooks/ban.py`, add to `ALWAYS_ALLOW`:
```python
ALWAYS_ALLOW = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "1.2.3.4/32",   # ← your IP
]
```

---

## Uninstall

```bash
systemctl stop soar
systemctl disable soar
rm /etc/systemd/system/soar.service
systemctl daemon-reload

# Remove standalone ipsets (if not using honeypot shared mode)
for s in soar-banned-ips soar-banned-nets; do
    iptables -D INPUT -m set --match-set $s src -j DROP 2>/dev/null || true
    iptables -D FORWARD -m set --match-set $s src -j DROP 2>/dev/null || true
    ipset destroy $s 2>/dev/null || true
done

rm -rf /opt/soar /etc/soar /var/log/soar
rm -f /etc/logrotate.d/soar
```

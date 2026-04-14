#!/usr/bin/env bash
# ============================================================
#  install.sh — SOAR installer
#  Совместимость: Ubuntu 20.04/22.04/24.04, Debian 11/12
#  Запуск: sudo bash install.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; RST='\033[0m'; BLD='\033[1m'

SOAR_DIR="/opt/soar"
LOG_DIR="/var/log/soar"
CFG_DIR="/etc/soar"
VENV="$SOAR_DIR/venv"
SERVICE="soar"

cat <<'EOF'

  ███████╗ ██████╗  █████╗ ██████╗
  ██╔════╝██╔═══██╗██╔══██╗██╔══██╗
  ███████╗██║   ██║███████║██████╔╝
  ╚════██║██║   ██║██╔══██║██╔══██╗
  ███████║╚██████╔╝██║  ██║██║  ██║
  ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

  Security Orchestration, Automation & Response
  Wazuh API → Playbooks → Ban + Telegram
EOF
echo

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Run as root: sudo bash install.sh${RST}"
    exit 1
fi

ok()  { echo -e "${GRN}[✓]${RST} $*"; }
inf() { echo -e "${CYN}[→]${RST} $*"; }
warn(){ echo -e "${YEL}[!]${RST} $*"; }
step(){ echo -e "\n${BLD}${CYN}══ $* ══${RST}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── 1. Зависимости ─────────────────────────────────────────
step "1. System dependencies"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-pip python3-venv \
    ipset iptables iptables-persistent \
    curl 2>/dev/null || true
ok "Packages installed"

# ── 2. Директории ──────────────────────────────────────────
step "2. Directories"
mkdir -p "$SOAR_DIR/playbooks" "$LOG_DIR" "$CFG_DIR"
ok "Directories created"

# ── 3. Копирование файлов ───────────────────────────────────
step "3. Copying SOAR files"
cp "$SCRIPT_DIR/soar.py"             "$SOAR_DIR/"
cp "$SCRIPT_DIR/wazuh_client.py"     "$SOAR_DIR/"
cp "$SCRIPT_DIR/playbooks/ban.py"    "$SOAR_DIR/playbooks/"
cp "$SCRIPT_DIR/playbooks/telegram.py" "$SOAR_DIR/playbooks/"
cp "$SCRIPT_DIR/playbooks/__init__.py" "$SOAR_DIR/playbooks/"
chmod +x "$SOAR_DIR/soar.py"
ok "Files copied to $SOAR_DIR"

# ── 4. Python venv ─────────────────────────────────────────
step "4. Python virtual environment"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet \
    aiohttp \
    pyyaml
ok "Python dependencies installed"

# ── 5. Config ──────────────────────────────────────────────
step "5. Configuration"
if [[ ! -f "$CFG_DIR/config.yaml" ]]; then
    cp "$SCRIPT_DIR/config.yaml" "$CFG_DIR/config.yaml"
    ok "Config installed: $CFG_DIR/config.yaml"
    warn "Edit the config before starting: nano $CFG_DIR/config.yaml"
else
    ok "Config already exists — not overwritten"
fi

# ── 6. Honeypot integration? ───────────────────────────────
step "6. Honeypot integration (shared ipset)"
echo
echo -e "  Do you want to share the ban list with the honeypot?"
echo -e "  This requires the honeypot to be installed on the same machine."
echo -e "  (uses shared ipset 'honeypot-banned-ips')"
echo
read -rp "  Integrate with honeypot? [y/N]: " HONEYPOT_CHOICE
HONEYPOT_CHOICE="${HONEYPOT_CHOICE,,}"

if [[ "$HONEYPOT_CHOICE" == "y" || "$HONEYPOT_CHOICE" == "yes" ]]; then
    # Check if honeypot ipsets exist
    if ipset list honeypot-banned-ips &>/dev/null; then
        # Patch config to use shared ipset
        sed -i 's/use_honeypot_ipset: false/use_honeypot_ipset: true/' "$CFG_DIR/config.yaml"
        ok "Honeypot integration ENABLED — using shared ipset 'honeypot-banned-ips'"
    else
        warn "Honeypot ipset 'honeypot-banned-ips' not found!"
        warn "Install honeypot first, then re-run this installer OR"
        warn "manually set 'use_honeypot_ipset: true' in $CFG_DIR/config.yaml"
    fi
else
    ok "Standalone mode — SOAR will use its own ipset 'soar-banned-ips'"
    # Ensure standalone ipsets exist
    ipset create soar-banned-ips hash:ip timeout 0 maxelem 1000000 2>/dev/null || true
    ipset create soar-banned-nets hash:net timeout 0 maxelem 1000000 2>/dev/null || true
    for chain in INPUT FORWARD; do
        for ipset in soar-banned-ips soar-banned-nets; do
            if ! iptables -C "$chain" -m set --match-set "$ipset" src -j DROP 2>/dev/null; then
                iptables -I "$chain" 1 -m set --match-set "$ipset" src -j DROP
            fi
        done
    done
    netfilter-persistent save 2>/dev/null || true
    ok "Standalone ipset rules installed"
fi

# ── 7. systemd service ─────────────────────────────────────
step "7. systemd service"
cat > /etc/systemd/system/${SERVICE}.service <<EOF
[Unit]
Description=SOAR — Wazuh alert response engine
After=network.target

[Service]
Type=simple
ExecStart=${VENV}/bin/python3 ${SOAR_DIR}/soar.py
Restart=always
RestartSec=10
User=root
WorkingDirectory=${SOAR_DIR}
StandardOutput=append:${LOG_DIR}/soar.log
StandardError=append:${LOG_DIR}/soar.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
ok "Service registered (not started yet — configure first)"

# ── 8. logrotate ───────────────────────────────────────────
step "8. logrotate"
cat > /etc/logrotate.d/soar <<'LOGROTATE'
/var/log/soar/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
LOGROTATE
ok "logrotate configured"

# ── Done ───────────────────────────────────────────────────
echo
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════════╗${RST}"
echo -e "${GRN}${BLD}║   🛡️  SOAR installed successfully!               ║${RST}"
echo -e "${GRN}${BLD}╚══════════════════════════════════════════════════╝${RST}"
echo
echo -e "  ${YEL}NEXT STEPS:${RST}"
echo -e "  ${CYN}1.${RST} Edit config:   nano $CFG_DIR/config.yaml"
echo -e "  ${CYN}2.${RST} Set Wazuh credentials + Telegram bot_token + chat_id"
echo -e "  ${CYN}3.${RST} Start SOAR:    systemctl start soar"
echo
echo -e "  ${CYN}Logs:${RST}       tail -f $LOG_DIR/soar.log"
echo -e "  ${CYN}Events:${RST}     tail -f $LOG_DIR/events.jsonl"
echo -e "  ${CYN}Banned IPs:${RST} cat $LOG_DIR/banned.txt"
echo -e "  ${CYN}ipset:${RST}      ipset list soar-banned-ips"
echo

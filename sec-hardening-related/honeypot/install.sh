#!/usr/bin/env bash
# ============================================================
#  install.sh — Honeypot installer
#  Совместимость: Ubuntu 20.04/22.04/24.04, Debian 11/12
#  Запуск: sudo bash install.sh
# ============================================================
set -euo pipefail

RED='\033[0;31m'; YEL='\033[1;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; RST='\033[0m'; BLD='\033[1m'

HP_DIR="/opt/honeypot"
LOG_DIR="/var/log/honeypot"
LIB_DIR="/var/lib/honeypot"
CACHE_DIR="/var/cache/honeypot"
VENV="$HP_DIR/venv"
GEOIP_DIR="/usr/share/GeoIP"
SERVICE="honeypot"

# ── Баннер ─────────────────────────────────────────────────
cat <<'EOF'

  ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
  ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║
  ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║
  ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝

  Самописный Honeypot — автобан сканеров + блокировка датацентров
EOF
echo

# ── Проверка root ───────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Запусти от root: sudo bash install.sh${RST}"
    exit 1
fi

ok()  { echo -e "${GRN}[✓]${RST} $*"; }
inf() { echo -e "${CYN}[→]${RST} $*"; }
warn(){ echo -e "${YEL}[!]${RST} $*"; }
die() { echo -e "${RED}[✗]${RST} $*"; exit 1; }
step(){ echo -e "\n${BLD}${CYN}══ $* ══${RST}"; }

# ── 1. Зависимости ─────────────────────────────────────────
step "1. Установка системных зависимостей"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-pip python3-venv \
    ipset iptables iptables-persistent \
    curl wget net-tools \
    mmdb-bin \
    2>/dev/null || true
ok "Системные пакеты установлены"

# ── 2. Создание директорий ──────────────────────────────────
step "2. Создание директорий"
mkdir -p "$HP_DIR" "$LOG_DIR" "$LIB_DIR" "$CACHE_DIR" "$GEOIP_DIR"
ok "Директории созданы"

# ── 3. Копирование файлов ───────────────────────────────────
step "3. Копирование файлов проекта"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/honeypot.py"    "$HP_DIR/"
cp "$SCRIPT_DIR/dc_blocklist.py" "$HP_DIR/"
chmod +x "$HP_DIR/honeypot.py" "$HP_DIR/dc_blocklist.py"
ok "Файлы скопированы в $HP_DIR"

# ── 4. Python virtualenv + pip зависимости ─────────────────
step "4. Python окружение"
python3 -m venv "$VENV"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet \
    aiohttp \
    geoip2
ok "Python зависимости установлены"

# ── 5. GeoLite2 ASN база ────────────────────────────────────
step "5. GeoIP ASN база (MaxMind GeoLite2)"
GEOIP_URL="https://raw.githubusercontent.com/P3TERX/GeoLite.mmdb/download/GeoLite2-ASN.mmdb"
GEOIP_FILE="$GEOIP_DIR/GeoLite2-ASN.mmdb"

if [[ ! -f "$GEOIP_FILE" ]]; then
    inf "Загружаем GeoLite2-ASN.mmdb..."
    if wget -q -O "$GEOIP_FILE" "$GEOIP_URL"; then
        ok "GeoIP ASN база загружена"
    else
        warn "Не удалось загрузить GeoIP, ASN-проверка будет недоступна"
        warn "Скачайте вручную: https://www.maxmind.com/en/geolite2/signup"
    fi
else
    ok "GeoIP база уже существует"
fi

# ── 6. sysctl — харденинг ядра ─────────────────────────────
step "6. sysctl — харденинг сети"
cat > /etc/sysctl.d/99-honeypot.conf <<'SYSCTL'
# === Honeypot network hardening ===

# Защита от IP-спуфинга
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Игнорировать ICMP broadcast (Smurf attacks)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Игнорировать bogus ICMP ответы
net.ipv4.icmp_ignore_bogus_error_responses = 1

# SYN flood защита (SYN cookies)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Не принимать source-routed пакеты
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Не принимать ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Не отправлять ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Логировать martian пакеты
net.ipv4.conf.all.log_martians = 1

# TIME_WAIT оптимизация
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Увеличить очередь соединений для honeypot
net.core.somaxconn = 65535
net.ipv4.tcp_max_tw_buckets = 1440000

# Увеличить лимит файловых дескрипторов
fs.file-max = 2097152
SYSCTL

sysctl -p /etc/sysctl.d/99-honeypot.conf >/dev/null
ok "sysctl применён"

# ── 7. ipset инициализация ──────────────────────────────────
step "7. ipset — создание таблиц"
for name_type in \
    "honeypot-banned-ips hash:ip" \
    "honeypot-banned-nets hash:net" \
    "honeypot-dc-drop hash:net"
do
    name=$(echo "$name_type" | awk '{print $1}')
    type=$(echo "$name_type" | awk '{print $2}')
    ipset create "$name" "$type" timeout 0 maxelem 2000000 2>/dev/null || true
    ok "ipset '$name' готов"
done

# Восстановить сохранённые правила если есть
if [[ -f "$LIB_DIR/ipset.rules" ]]; then
    ipset restore -f "$LIB_DIR/ipset.rules" 2>/dev/null || true
    ok "Сохранённые правила ipset восстановлены"
fi

# ── 8. iptables правила ─────────────────────────────────────
step "8. iptables — установка правил DROP"
_ipt_add() {
    local chain=$1 ipset=$2
    if ! iptables -C "$chain" -m set --match-set "$ipset" src -j DROP 2>/dev/null; then
        iptables -I "$chain" 1 -m set --match-set "$ipset" src -j DROP
        ok "iptables $chain DROP ← $ipset"
    else
        ok "iptables $chain правило уже есть: $ipset"
    fi
}

for ipset in honeypot-banned-ips honeypot-banned-nets honeypot-dc-drop; do
    _ipt_add INPUT "$ipset"
    _ipt_add FORWARD "$ipset"
done

# Сохранить iptables (iptables-persistent)
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
ok "iptables правила сохранены"

# ── 9. systemd сервис ───────────────────────────────────────
step "9. systemd сервис"
cat > /etc/systemd/system/${SERVICE}.service <<EOF
[Unit]
Description=Honeypot — автобан сканеров
After=network.target

[Service]
Type=simple
ExecStart=${VENV}/bin/python3 ${HP_DIR}/honeypot.py
Restart=always
RestartSec=5
User=root
LimitNOFILE=1048576
StandardOutput=append:${LOG_DIR}/honeypot.log
StandardError=append:${LOG_DIR}/honeypot.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
ok "Сервис $SERVICE запущен"

# ── 10. Таймер обновления DC-листа ────────────────────────────
step "10. Таймер обновления DC blocklist (каждые 6ч)"
cat > /etc/systemd/system/honeypot-dc-update.service <<EOF
[Unit]
Description=Honeypot DC blocklist updater

[Service]
Type=oneshot
ExecStart=${VENV}/bin/python3 ${HP_DIR}/dc_blocklist.py
User=root
StandardOutput=append:${LOG_DIR}/dc_update.log
StandardError=append:${LOG_DIR}/dc_update.log
EOF

cat > /etc/systemd/system/honeypot-dc-update.timer <<EOF
[Unit]
Description=Запуск обновления DC blocklist каждые 6 часов

[Timer]
OnBootSec=2min
OnUnitActiveSec=6h
Unit=honeypot-dc-update.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable honeypot-dc-update.timer
systemctl start honeypot-dc-update.timer
ok "DC-blocklist таймер активен (каждые 6 часов)"

# Первый запуск обновления прямо сейчас (фоново)
inf "Первичная загрузка DC blocklist (фоново)..."
"$VENV/bin/python3" "$HP_DIR/dc_blocklist.py" >> "$LOG_DIR/dc_update.log" 2>&1 &

# ── 11. Логротейт ──────────────────────────────────────────
step "11. logrotate"
cat > /etc/logrotate.d/honeypot <<'LOGROTATE'
/var/log/honeypot/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    postrotate
        systemctl kill --signal=USR1 honeypot.service 2>/dev/null || true
    endscript
}
LOGROTATE
ok "logrotate настроен (30 дней ротация)"

# ── Финал ──────────────────────────────────────────────────
echo
echo -e "${GRN}${BLD}╔══════════════════════════════════════════════╗${RST}"
echo -e "${GRN}${BLD}║   🍯  Honeypot успешно установлен!           ║${RST}"
echo -e "${GRN}${BLD}╚══════════════════════════════════════════════╝${RST}"
echo
echo -e "  ${CYN}Статус:${RST}     systemctl status honeypot"
echo -e "  ${CYN}Логи:${RST}       tail -f /var/log/honeypot/honeypot.log"
echo -e "  ${CYN}События:${RST}    tail -f /var/log/honeypot/events.jsonl"
echo -e "  ${CYN}Забаненные:${RST} ipset list honeypot-banned-ips | head -20"
echo -e "  ${CYN}DC-блок:${RST}    ipset list honeypot-dc-drop | wc -l"
echo
PORTS="21 22 23 25 445 1433 3306 3389 5432 6379 8080 27017 ..."
echo -e "  ${YEL}Honeypot слушает порты:${RST} $PORTS"
echo

#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

BACKUP_DIR="/var/backup/cis-hardening/user-policy"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/cis-hardening-userpolicy-${TIMESTAMP}.log"

mkdir -p "$BACKUP_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${BACKUP_DIR}/$(basename "$file").${TIMESTAMP}.bak"
        log "BACKUP: $file"
    fi
}

set_login_defs() {
    local key="$1"
    local value="$2"
    local file="/etc/login.defs"
    if grep -qE "^\s*#?\s*${key}\s+" "$file"; then
        sed -i "s|^\s*#*\s*${key}\s.*|${key}\t${value}|" "$file"
    else
        echo -e "${key}\t${value}" >> "$file"
    fi
    log "SET: ${key} = ${value} in login.defs"
}

log "Starting user/password policy hardening based on CIS Benchmark 5.4.x"

backup_file "/etc/login.defs"
backup_file "/etc/pam.d/common-password"
backup_file "/etc/pam.d/common-auth"
backup_file "/etc/security/pwquality.conf"
backup_file "/etc/default/useradd"

set_login_defs "PASS_MAX_DAYS" "365"
set_login_defs "PASS_MIN_DAYS" "1"
set_login_defs "PASS_WARN_AGE" "7"
set_login_defs "PASS_MIN_LEN" "14"
set_login_defs "LOGIN_RETRIES" "5"
set_login_defs "LOGIN_TIMEOUT" "60"
set_login_defs "ENCRYPT_METHOD" "SHA512"
set_login_defs "UMASK" "027"

if [[ -f /etc/default/useradd ]]; then
    sed -i 's|^INACTIVE=.*|INACTIVE=30|' /etc/default/useradd
    if ! grep -q "^INACTIVE=" /etc/default/useradd; then
        echo "INACTIVE=30" >> /etc/default/useradd
    fi
    log "SET: INACTIVE=30 in useradd defaults"
fi

if command -v apt &>/dev/null; then
    apt install -y libpam-pwquality &>/dev/null || true
fi

PWQUALITY="/etc/security/pwquality.conf"
if [[ -f "$PWQUALITY" ]]; then
    cat > "$PWQUALITY" <<'PWEOF'
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 4
maxrepeat = 3
maxclassrepeat = 4
gecoscheck = 1
dictcheck = 1
enforcing = 1
PWEOF
    log "SET: pwquality.conf configured"
fi

COMMON_AUTH="/etc/pam.d/common-auth"
if [[ -f "$COMMON_AUTH" ]]; then
    if ! grep -q "pam_faillock" "$COMMON_AUTH"; then
        sed -i '/^auth.*pam_unix.so/i auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900' "$COMMON_AUTH"
        sed -i '/^auth.*pam_unix.so/a auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900' "$COMMON_AUTH"
        log "SET: pam_faillock configured (5 attempts, 900s lockout)"
    else
        log "SKIP: pam_faillock already configured"
    fi
fi

log "Checking for users with UID 0 besides root"
awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | while read -r user; do
    log "WARNING: Non-root user with UID 0 found: $user"
done

log "Checking for users without passwords"
awk -F: '($2 == "" || $2 == "!") {print $1}' /etc/shadow 2>/dev/null | while read -r user; do
    if [[ "$user" != "root" ]]; then
        log "WARNING: User without proper password: $user"
    fi
done

log "Locking system accounts"
for user in $(awk -F: '($3 < 1000 && $1 != "root") {print $1}' /etc/passwd); do
    current_shell=$(getent passwd "$user" | cut -d: -f7)
    if [[ "$current_shell" != "/usr/sbin/nologin" && "$current_shell" != "/bin/false" ]]; then
        usermod -s /usr/sbin/nologin "$user" 2>/dev/null || true
        log "SET: $user shell -> /usr/sbin/nologin"
    fi
done

if [[ ! -f /etc/securetty ]]; then
    touch /etc/securetty
    log "CREATED: /etc/securetty (empty — no direct root console login)"
fi

log "User/password policy hardening complete. Log: $LOG_FILE"

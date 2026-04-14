#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

BACKUP_DIR="/var/backup/cis-hardening/ssh"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
SSHD_CONFIG="/etc/ssh/sshd_config"
LOG_FILE="/var/log/cis-hardening-ssh-${TIMESTAMP}.log"

mkdir -p "$BACKUP_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp "$file" "${BACKUP_DIR}/$(basename "$file").${TIMESTAMP}.bak"
        log "BACKUP: $file -> ${BACKUP_DIR}/$(basename "$file").${TIMESTAMP}.bak"
    fi
}

apply_sshd_setting() {
    local key="$1"
    local value="$2"
    if grep -qE "^\s*#?\s*${key}\s+" "$SSHD_CONFIG"; then
        sed -i "s|^\s*#*\s*${key}\s.*|${key} ${value}|" "$SSHD_CONFIG"
    else
        echo "${key} ${value}" >> "$SSHD_CONFIG"
    fi
    log "SET: ${key} ${value}"
}

log "Starting SSH hardening based on CIS Benchmark 5.2.x"

backup_file "$SSHD_CONFIG"

apply_sshd_setting "Protocol" "2"
apply_sshd_setting "LogLevel" "VERBOSE"
apply_sshd_setting "MaxAuthTries" "4"
apply_sshd_setting "IgnoreRhosts" "yes"
apply_sshd_setting "HostbasedAuthentication" "no"
apply_sshd_setting "PermitRootLogin" "no"
apply_sshd_setting "PermitEmptyPasswords" "no"
apply_sshd_setting "PermitUserEnvironment" "no"
apply_sshd_setting "ClientAliveInterval" "300"
apply_sshd_setting "ClientAliveCountMax" "3"
apply_sshd_setting "LoginGraceTime" "60"
apply_sshd_setting "MaxStartups" "10:30:60"
apply_sshd_setting "MaxSessions" "10"
apply_sshd_setting "Banner" "/etc/issue.net"
apply_sshd_setting "X11Forwarding" "no"
apply_sshd_setting "AllowTcpForwarding" "no"
apply_sshd_setting "AllowAgentForwarding" "no"
apply_sshd_setting "DisableForwarding" "yes"

apply_sshd_setting "Ciphers" "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
apply_sshd_setting "MACs" "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
apply_sshd_setting "KexAlgorithms" "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512"

chmod 600 "$SSHD_CONFIG"
log "SET: sshd_config permissions to 600"

if [[ ! -f /etc/issue.net ]] || [[ ! -s /etc/issue.net ]]; then
    echo "Authorized access only. All activity is monitored and logged." > /etc/issue.net
    log "CREATED: /etc/issue.net warning banner"
fi

sshd -t 2>/dev/null
if [[ $? -eq 0 ]]; then
    log "SSHD config validation: PASSED"
    systemctl restart sshd
    log "SSHD service restarted"
else
    log "SSHD config validation: FAILED — restoring backup"
    cp "${BACKUP_DIR}/sshd_config.${TIMESTAMP}.bak" "$SSHD_CONFIG"
    log "RESTORED: sshd_config from backup"
    exit 1
fi

log "SSH hardening complete. Log: $LOG_FILE"

#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

BACKUP_DIR="/var/backup/cis-hardening/audit"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/cis-hardening-audit-${TIMESTAMP}.log"
AUDIT_RULES_FILE="/etc/audit/rules.d/cis-hardening.rules"

mkdir -p "$BACKUP_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting audit/logging hardening based on CIS Benchmark 4.1.x"

if ! command -v auditd &>/dev/null; then
    log "Installing auditd"
    apt install -y auditd audispd-plugins &>/dev/null || yum install -y audit audit-libs &>/dev/null
fi

if [[ -f "$AUDIT_RULES_FILE" ]]; then
    cp "$AUDIT_RULES_FILE" "${BACKUP_DIR}/cis-hardening.rules.${TIMESTAMP}.bak"
    log "BACKUP: existing audit rules"
fi

if [[ -f /etc/audit/auditd.conf ]]; then
    cp /etc/audit/auditd.conf "${BACKUP_DIR}/auditd.conf.${TIMESTAMP}.bak"
    sed -i 's|^max_log_file\s*=.*|max_log_file = 50|' /etc/audit/auditd.conf
    sed -i 's|^max_log_file_action\s*=.*|max_log_file_action = keep_logs|' /etc/audit/auditd.conf
    sed -i 's|^space_left_action\s*=.*|space_left_action = email|' /etc/audit/auditd.conf
    sed -i 's|^action_mail_acct\s*=.*|action_mail_acct = root|' /etc/audit/auditd.conf
    sed -i 's|^admin_space_left_action\s*=.*|admin_space_left_action = halt|' /etc/audit/auditd.conf
    log "SET: auditd.conf parameters"
fi

cat > "$AUDIT_RULES_FILE" <<'RULESEOF'
-D
-b 8192

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/hostname -p wa -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale

-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /etc/selinux/ -p wa -k MAC-policy

-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions

-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

-e 2
RULESEOF

log "CREATED: $AUDIT_RULES_FILE with CIS rules"

if [[ -f /etc/rsyslog.conf ]]; then
    cp /etc/rsyslog.conf "${BACKUP_DIR}/rsyslog.conf.${TIMESTAMP}.bak"

    if ! grep -q '^\$FileCreateMode' /etc/rsyslog.conf; then
        echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
        log "SET: rsyslog FileCreateMode 0640"
    fi
fi

chmod -R g-wx,o-rwx /var/log/audit/ 2>/dev/null || true
log "SET: /var/log/audit/ permissions restricted"

systemctl enable auditd 2>/dev/null || true
systemctl restart auditd 2>/dev/null || true
augenrules --load 2>/dev/null || true
log "Audit rules loaded and auditd restarted"

log "Audit/logging hardening complete. Log: $LOG_FILE"

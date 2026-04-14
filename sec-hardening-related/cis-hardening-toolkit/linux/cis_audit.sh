#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_FILE="/var/log/cis-audit-report-${TIMESTAMP}.txt"
PASS=0
FAIL=0
WARN=0

result() {
    local status="$1"
    local control="$2"
    local detail="$3"
    echo "[${status}] ${control} — ${detail}" | tee -a "$REPORT_FILE"
    case "$status" in
        PASS) ((PASS++)) ;;
        FAIL) ((FAIL++)) ;;
        WARN) ((WARN++)) ;;
    esac
}

echo "=============================================" | tee "$REPORT_FILE"
echo "  CIS Benchmark Compliance Audit Report" | tee -a "$REPORT_FILE"
echo "  Date: $(date)" | tee -a "$REPORT_FILE"
echo "  Host: $(hostname)" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

echo "--- SSH Configuration (CIS 5.2.x) ---" | tee -a "$REPORT_FILE"

check_sshd() {
    local key="$1"
    local expected="$2"
    local control="$3"
    local actual
    actual=$(sshd -T 2>/dev/null | grep -i "^${key} " | awk '{print $2}' | head -1)
    if [[ "${actual,,}" == "${expected,,}" ]]; then
        result "PASS" "$control" "${key} = ${actual}"
    else
        result "FAIL" "$control" "${key} = ${actual:-not set} (expected: ${expected})"
    fi
}

check_sshd "permitrootlogin" "no" "CIS 5.2.10"
check_sshd "permitemptypasswords" "no" "CIS 5.2.11"
check_sshd "maxauthtries" "4" "CIS 5.2.7"
check_sshd "x11forwarding" "no" "CIS 5.2.6"
check_sshd "ignorerhosts" "yes" "CIS 5.2.8"
check_sshd "hostbasedauthentication" "no" "CIS 5.2.9"
check_sshd "permituserenvironment" "no" "CIS 5.2.12"
check_sshd "clientaliveinterval" "300" "CIS 5.2.16"
check_sshd "clientalivecountmax" "3" "CIS 5.2.16"
check_sshd "loglevel" "verbose" "CIS 5.2.5"
check_sshd "banner" "/etc/issue.net" "CIS 5.2.17"

echo "" | tee -a "$REPORT_FILE"
echo "--- Firewall (CIS 3.5.x) ---" | tee -a "$REPORT_FILE"

if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        result "PASS" "CIS 3.5.1.1" "UFW is active"
    else
        result "FAIL" "CIS 3.5.1.1" "UFW is not active"
    fi
    if ufw status verbose | grep -q "Default: deny (incoming)"; then
        result "PASS" "CIS 3.5.1.3" "Default incoming policy: deny"
    else
        result "FAIL" "CIS 3.5.1.3" "Default incoming policy is not deny"
    fi
elif command -v iptables &>/dev/null; then
    input_policy=$(iptables -L INPUT -n | head -1 | awk '{print $4}' | tr -d ')')
    if [[ "$input_policy" == "DROP" ]]; then
        result "PASS" "CIS 3.5.2.1" "iptables INPUT default: DROP"
    else
        result "FAIL" "CIS 3.5.2.1" "iptables INPUT default: $input_policy (expected DROP)"
    fi
fi

echo "" | tee -a "$REPORT_FILE"
echo "--- User/Password Policies (CIS 5.4.x) ---" | tee -a "$REPORT_FILE"

check_login_defs() {
    local key="$1"
    local expected="$2"
    local control="$3"
    local actual
    actual=$(grep -E "^\s*${key}\s+" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ "$actual" == "$expected" ]]; then
        result "PASS" "$control" "${key} = ${actual}"
    else
        result "FAIL" "$control" "${key} = ${actual:-not set} (expected: ${expected})"
    fi
}

check_login_defs "PASS_MAX_DAYS" "365" "CIS 5.4.1.1"
check_login_defs "PASS_MIN_DAYS" "1" "CIS 5.4.1.2"
check_login_defs "PASS_WARN_AGE" "7" "CIS 5.4.1.3"
check_login_defs "ENCRYPT_METHOD" "SHA512" "CIS 5.4.4"

uid0_users=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [[ -z "$uid0_users" ]]; then
    result "PASS" "CIS 6.2.2" "No non-root users with UID 0"
else
    result "FAIL" "CIS 6.2.2" "Non-root UID 0 users found: $uid0_users"
fi

echo "" | tee -a "$REPORT_FILE"
echo "--- Audit and Logging (CIS 4.1.x) ---" | tee -a "$REPORT_FILE"

if systemctl is-active auditd &>/dev/null; then
    result "PASS" "CIS 4.1.1.1" "auditd is running"
else
    result "FAIL" "CIS 4.1.1.1" "auditd is not running"
fi

if systemctl is-enabled auditd &>/dev/null; then
    result "PASS" "CIS 4.1.1.2" "auditd is enabled at boot"
else
    result "FAIL" "CIS 4.1.1.2" "auditd is not enabled at boot"
fi

for watch_path in /etc/passwd /etc/shadow /etc/group /etc/sudoers; do
    if auditctl -l 2>/dev/null | grep -q "$watch_path"; then
        result "PASS" "CIS 4.1.x" "Audit watch on $watch_path"
    else
        result "FAIL" "CIS 4.1.x" "No audit watch on $watch_path"
    fi
done

if auditctl -s 2>/dev/null | grep -q "enabled 2"; then
    result "PASS" "CIS 4.1.18" "Audit configuration is immutable"
else
    result "WARN" "CIS 4.1.18" "Audit configuration is not immutable (requires reboot after setting)"
fi

echo "" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"
echo "  RESULTS: ${PASS} PASS / ${FAIL} FAIL / ${WARN} WARN" | tee -a "$REPORT_FILE"
echo "  Total checks: $((PASS + FAIL + WARN))" | tee -a "$REPORT_FILE"
echo "  Report saved: $REPORT_FILE" | tee -a "$REPORT_FILE"
echo "=============================================" | tee -a "$REPORT_FILE"

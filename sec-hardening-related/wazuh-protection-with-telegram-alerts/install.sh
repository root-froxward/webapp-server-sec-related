#!/usr/bin/env bash
set -euo pipefail

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="/tmp/wazuh-install.log"
CONFIG_FILE="/var/ossec/etc/auto-mitigate.conf"

print()  { echo -e "${BOLD}${CYAN}[*]${RESET} $*"; }
ok()     { echo -e "${BOLD}${GREEN}[✓]${RESET} $*"; }
warn()   { echo -e "${BOLD}${YELLOW}[!]${RESET} $*"; }
die()    { echo -e "${BOLD}${RED}[✗]${RESET} $*"; exit 1; }
section(){ echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${RESET}"; }

log_cmd() { "$@" >> "$LOG" 2>&1; }

check_root() {
    [[ $EUID -eq 0 ]] || die "Run as root: sudo bash install.sh"
}

check_wazuh() {
    [[ -d /var/ossec ]] || die "Wazuh not found at /var/ossec. Install Wazuh first."
    [[ -f /var/ossec/bin/wazuh-control ]] || die "wazuh-control not found"
}

detect_webserver() {
    if command -v nginx &>/dev/null && systemctl is-active nginx &>/dev/null; then
        echo "nginx"
    elif command -v apache2 &>/dev/null && systemctl is-active apache2 &>/dev/null; then
        echo "apache2"
    elif command -v httpd &>/dev/null && systemctl is-active httpd &>/dev/null; then
        echo "httpd"
    else
        echo "none"
    fi
}

detect_os() {
    if [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    else
        echo "unknown"
    fi
}

install_deps() {
    section "Installing dependencies"
    local os
    os=$(detect_os)

    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get update -q
        log_cmd apt-get install -y -q ipset iptables iptables-persistent python3 python3-pip fail2ban
    elif [[ "$os" == "rhel" ]]; then
        log_cmd yum install -y -q ipset iptables-services python3 python3-pip fail2ban
        log_cmd systemctl enable --now iptables
    else
        warn "Unknown OS — please install ipset, python3, python3-pip, fail2ban manually"
    fi

    log_cmd pip3 install requests --quiet
    ok "Dependencies installed"
}

collect_config() {
    section "Configuration"

    echo -e "\n${BOLD}Whitelist IPs (your admin/management IPs — comma separated)${RESET}"
    echo -e "Example: 1.2.3.4,5.6.7.8/24  (leave empty to skip)"
    read -rp "Whitelist: " USER_WHITELIST

    echo -e "\n${BOLD}Cloudflare Edge Blocking (optional)${RESET}"
    read -rp "Enable Cloudflare? [y/N]: " CF_ANSWER
    CF_ENABLED="false"
    CF_TOKEN=""
    CF_ZONE=""
    if [[ "${CF_ANSWER,,}" == "y" ]]; then
        read -rp "  API Token: " CF_TOKEN
        read -rp "  Zone ID:   " CF_ZONE
        CF_ENABLED="true"
        ok "Cloudflare enabled"
    fi

    echo -e "\n${BOLD}Web server detected:${RESET} $(detect_webserver)"
    echo -e "${BOLD}Wazuh log sources will be auto-detected${RESET}"
}

write_config() {
    section "Writing config"
    cat > "$CONFIG_FILE" <<EOF
CF_ENABLED=${CF_ENABLED}
CF_API_TOKEN=${CF_TOKEN}
CF_ZONE_ID=${CF_ZONE}
WHITELIST=${USER_WHITELIST}
EOF
    chmod 640 "$CONFIG_FILE"
    chown root:wazuh "$CONFIG_FILE"
    ok "Config written to $CONFIG_FILE"
}

install_rules() {
    section "Installing Wazuh rules"
    local rules_dir="/var/ossec/etc/rules"

    cp "$SCRIPT_DIR/0100-ddos-detection.xml"    "$rules_dir/"
    cp "$SCRIPT_DIR/0110-web-vuln-detection.xml" "$rules_dir/"
    chown wazuh:wazuh "$rules_dir"/0100-ddos-detection.xml
    chown wazuh:wazuh "$rules_dir"/0110-web-vuln-detection.xml
    chmod 640 "$rules_dir"/0100-ddos-detection.xml
    chmod 640 "$rules_dir"/0110-web-vuln-detection.xml
    ok "Rules installed to $rules_dir"
}

install_ar_script() {
    section "Installing active response script"
    local ar_dir="/var/ossec/active-response/bin"

    cp "$SCRIPT_DIR/auto-mitigate.py" "$ar_dir/"
    chown root:wazuh "$ar_dir/auto-mitigate.py"
    chmod 750 "$ar_dir/auto-mitigate.py"

    mkdir -p /var/log/wazuh /var/ossec/logs/critical-incidents
    touch /var/log/wazuh/auto-mitigate.log
    chmod 640 /var/log/wazuh/auto-mitigate.log
    chown root:wazuh /var/log/wazuh/auto-mitigate.log
    ok "Active response script installed"
}

patch_ossec_conf() {
    section "Patching ossec.conf"
    local conf="/var/ossec/etc/ossec.conf"
    local marker="<!-- wazuh-ar-ddos-vuln -->"

    if grep -q "$marker" "$conf"; then
        warn "Active response blocks already present in ossec.conf — skipping"
        return
    fi

    local ar_block
    ar_block=$(cat <<'AREOF'

  <!-- wazuh-ar-ddos-vuln -->
  <command>
    <n>auto-mitigate</n>
    <executable>auto-mitigate.py</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>100102,100110,100111,100113,100114,100115,100116,100117,100118</rules_id>
    <timeout>3600</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>100121,100122,100123,100124,100125,100126,100127,100132</rules_id>
    <timeout>1800</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>100130,100131</rules_id>
    <timeout>7200</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110100,110101,110103,110104</rules_id>
    <timeout>86400</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110102</rules_id>
    <timeout>0</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110110,110111</rules_id>
    <timeout>7200</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110120,110121</rules_id>
    <timeout>86400</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110130,110140</rules_id>
    <timeout>86400</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110150</rules_id>
    <timeout>0</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110160</rules_id>
    <timeout>0</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110161,110162</rules_id>
    <timeout>0</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110170,110180</rules_id>
    <timeout>86400</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110201,110202,110203</rules_id>
    <timeout>3600</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110220,110221</rules_id>
    <timeout>0</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110230,110231</rules_id>
    <timeout>7200</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>110300,110301</rules_id>
    <timeout>0</timeout>
  </active-response>
AREOF
)

    sed -i "s|</ossec_config>|${ar_block}\n</ossec_config>|" "$conf"
    ok "ossec.conf patched"
}

add_log_sources() {
    section "Adding log sources to ossec.conf"
    local conf="/var/ossec/etc/ossec.conf"
    local ws
    ws=$(detect_webserver)
    local log_marker="<!-- wazuh-ar-logs -->"

    if grep -q "$log_marker" "$conf"; then
        warn "Log sources already present — skipping"
        return
    fi

    local log_block="  $log_marker\n"
    log_block+="  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/kern.log</location>\n  </localfile>\n"
    log_block+="  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>\n"

    if [[ "$ws" == "nginx" ]]; then
        log_block+="  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/access.log</location>\n  </localfile>\n"
        log_block+="  <localfile>\n    <log_format>apache</log_format>\n    <location>/var/log/nginx/error.log</location>\n  </localfile>\n"
    elif [[ "$ws" == "apache2" || "$ws" == "httpd" ]]; then
        local alog="/var/log/apache2/access.log"
        [[ "$ws" == "httpd" ]] && alog="/var/log/httpd/access_log"
        log_block+="  <localfile>\n    <log_format>apache</log_format>\n    <location>${alog}</location>\n  </localfile>\n"
    fi

    if [[ -f /var/log/modsec_audit.log ]]; then
        log_block+="  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/modsec_audit.log</location>\n  </localfile>\n"
    fi

    sed -i "s|</ossec_config>|${log_block}\n</ossec_config>|" "$conf"
    ok "Log sources added for: ${ws}"
}

setup_ipset() {
    section "Setting up ipset and iptables"

    modprobe ip_set 2>/dev/null || true
    modprobe ip_set_hash_ip 2>/dev/null || true
    modprobe xt_set 2>/dev/null || true

    ipset create wazuh_blocked hash:ip timeout 3600 -exist
    ipset create wazuh_ddos    hash:ip timeout 3600 -exist

    iptables -C INPUT   -m set --match-set wazuh_blocked src -j DROP 2>/dev/null || \
        iptables -I INPUT   1 -m set --match-set wazuh_blocked src -j DROP
    iptables -C FORWARD -m set --match-set wazuh_blocked src -j DROP 2>/dev/null || \
        iptables -I FORWARD 1 -m set --match-set wazuh_blocked src -j DROP
    iptables -t raw -C PREROUTING -m set --match-set wazuh_ddos src -j DROP 2>/dev/null || \
        iptables -t raw -I PREROUTING 1 -m set --match-set wazuh_ddos src -j DROP

    iptables -C INPUT -p tcp --syn -m limit --limit 1000/s --limit-burst 5000 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p tcp --syn -m limit --limit 1000/s --limit-burst 5000 -j ACCEPT
    iptables -C INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -C INPUT -p tcp --tcp-flags ALL ALL -j DROP 2>/dev/null || \
        iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -C INPUT -p icmp -m limit --limit 10/s --limit-burst 20 -j ACCEPT 2>/dev/null || \
        iptables -A INPUT -p icmp -m limit --limit 10/s --limit-burst 20 -j ACCEPT

    if command -v netfilter-persistent &>/dev/null; then
        log_cmd netfilter-persistent save
    elif [[ -d /etc/iptables ]]; then
        iptables-save > /etc/iptables/rules.v4
    fi

    ipset save > /etc/ipset.conf 2>/dev/null || true

    ok "ipset and iptables configured"
}

apply_sysctl() {
    section "Applying kernel anti-DDoS settings"
    local sysctl_file="/etc/sysctl.d/99-wazuh-antiddos.conf"
    cat > "$sysctl_file" <<'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 3
net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 1800
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.netdev_max_backlog = 65536
EOF
    sysctl -p "$sysctl_file" >> "$LOG" 2>&1 || warn "Some sysctl params may not apply on this kernel"
    ok "Kernel parameters applied"
}

setup_nginx_ratelimit() {
    local ws
    ws=$(detect_webserver)
    [[ "$ws" != "nginx" ]] && return

    section "Configuring nginx rate limiting"

    local rate_conf="/etc/nginx/conf.d/wazuh-ratelimit.conf"
    if [[ ! -f "$rate_conf" ]]; then
        cat > "$rate_conf" <<'EOF'
limit_req_zone  $binary_remote_addr zone=wazuh_global:10m rate=100r/s;
limit_req_zone  $binary_remote_addr zone=wazuh_login:10m  rate=5r/m;
limit_req_zone  $binary_remote_addr zone=wazuh_api:10m    rate=50r/s;
limit_conn_zone $binary_remote_addr zone=wazuh_conn:10m;
EOF
        ok "nginx rate limit zones created"
    else
        warn "nginx rate limit config already exists — skipping"
    fi

    touch /etc/nginx/conf.d/wazuh-blocked.conf
    touch /etc/nginx/conf.d/wazuh-waf-block.conf

    if nginx -t >> "$LOG" 2>&1; then
        nginx -s reload >> "$LOG" 2>&1
        ok "nginx reloaded"
    else
        warn "nginx config test failed — check $LOG"
    fi
}

setup_fail2ban() {
    section "Configuring fail2ban"
    if ! systemctl is-active fail2ban &>/dev/null; then
        systemctl enable fail2ban >> "$LOG" 2>&1
        systemctl start  fail2ban >> "$LOG" 2>&1
    fi

    cat > /etc/fail2ban/jail.d/wazuh-auto.conf <<'EOF'
[wazuh-auto]
enabled  = true
bantime  = 3600
findtime = 60
maxretry = 1
action   = iptables-multiport[name=wazuh, port="http,https,8080,8443", protocol=tcp]
filter   = wazuh-auto
logpath  = /var/ossec/logs/alerts/alerts.log
EOF

    cat > /etc/fail2ban/filter.d/wazuh-auto.conf <<'EOF'
[Definition]
failregex = \[BLOCK\] <HOST>
            \[DDOS-BLOCK\] <HOST>
            \[WAF-RULE\] <HOST>
ignoreregex =
EOF

    systemctl reload fail2ban >> "$LOG" 2>&1 || systemctl restart fail2ban >> "$LOG" 2>&1
    ok "fail2ban configured"
}

validate_config() {
    section "Validating Wazuh config"
    if /var/ossec/bin/wazuh-control configtest >> "$LOG" 2>&1; then
        ok "Wazuh config is valid"
    else
        warn "Config test returned warnings — check $LOG"
    fi
}

restart_wazuh() {
    section "Restarting Wazuh"
    systemctl restart wazuh-manager >> "$LOG" 2>&1
    sleep 3
    if systemctl is-active wazuh-manager &>/dev/null; then
        ok "Wazuh manager restarted successfully"
    else
        die "Wazuh failed to start — check: journalctl -u wazuh-manager"
    fi
}

print_summary() {
    local ws
    ws=$(detect_webserver)
    echo -e "\n${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}${GREEN}  Installation complete!${RESET}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e ""
    echo -e "  ${BOLD}Rules installed:${RESET}    /var/ossec/etc/rules/0100-*.xml"
    echo -e "                      /var/ossec/etc/rules/0110-*.xml"
    echo -e "  ${BOLD}AR script:${RESET}          /var/ossec/active-response/bin/auto-mitigate.py"
    echo -e "  ${BOLD}Config:${RESET}             $CONFIG_FILE"
    echo -e "  ${BOLD}Mitigation log:${RESET}     /var/log/wazuh/auto-mitigate.log"
    echo -e "  ${BOLD}Incident alerts:${RESET}    /var/ossec/logs/critical-incidents/"
    echo -e "  ${BOLD}Blocked IPs:${RESET}        ipset list wazuh_blocked"
    echo -e "  ${BOLD}Web server:${RESET}         $ws"
    echo -e "  ${BOLD}Cloudflare:${RESET}         $CF_ENABLED"
    echo -e ""
    echo -e "  ${BOLD}Live alerts:${RESET}"
    echo -e "    tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool"
    echo -e ""
    echo -e "  ${BOLD}Live mitigation log:${RESET}"
    echo -e "    tail -f /var/log/wazuh/auto-mitigate.log"
    echo -e ""
    echo -e "  ${BOLD}Full install log:${RESET}   $LOG"
    echo -e ""
}

main() {
    echo -e "${BOLD}${CYAN}"
    echo -e "  ╔══════════════════════════════════════════════╗"
    echo -e "  ║   Wazuh DDoS + Web Attack Protection Suite  ║"
    echo -e "  ║   Auto-installer v2.0                        ║"
    echo -e "  ╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"

    > "$LOG"

    check_root
    check_wazuh
    install_deps
    collect_config
    write_config
    install_rules
    install_ar_script
    patch_ossec_conf
    add_log_sources
    setup_ipset
    apply_sysctl
    setup_nginx_ratelimit
    setup_fail2ban
    validate_config
    restart_wazuh
    print_summary
}

main "$@"

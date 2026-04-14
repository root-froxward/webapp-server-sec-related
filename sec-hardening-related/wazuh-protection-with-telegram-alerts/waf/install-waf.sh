#!/usr/bin/env bash
# install-waf.sh — Main installer for the WAF extension module
# Part of wazuh-protection-suite
#
# Usage:
#   sudo bash install-waf.sh              # interactive, installs all modules
#   sudo bash install-waf.sh --module modsec    # only ModSecurity + CRS
#   sudo bash install-waf.sh --module crowdsec  # only CrowdSec
#   sudo bash install-waf.sh --module headers   # only security headers
#   sudo bash install-waf.sh --module ratelimit # only rate limiting
#   sudo bash install-waf.sh --module geoip     # only GeoIP
#   sudo bash install-waf.sh --all              # non-interactive, all modules

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export LOG="/tmp/wazuh-waf-install.log"

source "$SCRIPT_DIR/lib.sh"

# GeoIP mode: deny = block listed countries, allow = allow only listed
export GEOIP_MODE="deny"

check_root() {
    [[ $EUID -eq 0 ]] || die "Run as root: sudo bash install-waf.sh"
}

check_prereqs() {
    [[ -d /var/ossec ]] || die "Wazuh not found. Run the base install.sh first."

    local ws
    ws=$(detect_webserver)
    if [[ "$ws" == "none" ]]; then
        warn "No web server detected (nginx/apache). Some modules will be skipped."
    else
        ok "Web server detected: $ws"
    fi
}

run_module() {
    local mod="$1"
    local script="$SCRIPT_DIR/modules/${mod}.sh"
    if [[ -f "$script" ]]; then
        bash "$script"
    else
        die "Module not found: $script"
    fi
}

install_modsec() {
    local ws
    ws=$(detect_webserver)

    if [[ "$ws" == "nginx" ]]; then
        run_module "modsec-nginx"
    elif [[ "$ws" == "apache2" || "$ws" == "httpd" ]]; then
        run_module "modsec-apache"
    else
        warn "No web server — skipping ModSecurity"
        return
    fi

    run_module "owasp-crs"
}

install_wazuh_rules() {
    section "Installing WAF Wazuh rules"
    local rules_dir="/var/ossec/etc/rules"

    cp "$SCRIPT_DIR/wazuh-rules/0120-modsec-waf.xml" "$rules_dir/"
    chown wazuh:wazuh "$rules_dir/0120-modsec-waf.xml"
    chmod 640 "$rules_dir/0120-modsec-waf.xml"

    ok "WAF rules installed to $rules_dir"
}

patch_ossec_conf_waf() {
    section "Patching ossec.conf for WAF active response"
    local conf="/var/ossec/etc/ossec.conf"
    local marker="<!-- wazuh-ar-waf -->"

    if grep -q "$marker" "$conf"; then
        warn "WAF active response blocks already present — skipping"
        return
    fi

    local ar_block
    ar_block=$(cat <<'AREOF'

  <!-- wazuh-ar-waf -->
  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>120101,120110,120111,120112,120113,120130</rules_id>
    <timeout>3600</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>120117,120500</rules_id>
    <timeout>0</timeout>
  </active-response>

  <active-response>
    <command>auto-mitigate</command>
    <location>server</location>
    <rules_id>120401</rules_id>
    <timeout>1800</timeout>
  </active-response>
AREOF
)

    # Add modsec audit log source if not present
    local log_marker="<!-- wazuh-ar-waf-logs -->"
    local log_block=""
    if ! grep -q "$log_marker" "$conf"; then
        log_block=$(cat <<'LOGEOF'

  <!-- wazuh-ar-waf-logs -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/modsec_audit.log</location>
  </localfile>
LOGEOF
)
    fi

    sed -i "s|</ossec_config>|${ar_block}\n${log_block}\n</ossec_config>|" "$conf"
    ok "ossec.conf patched for WAF"
}

add_modsec_log_source() {
    local conf="/var/ossec/etc/ossec.conf"
    if ! grep -q "modsec_audit.log" "$conf"; then
        local block='  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/modsec_audit.log</location>\n  </localfile>'
        sed -i "s|</ossec_config>|${block}\n</ossec_config>|" "$conf"
        ok "ModSecurity audit log added to ossec.conf"
    fi
}

restart_wazuh() {
    section "Restarting Wazuh"
    if /var/ossec/bin/wazuh-control configtest >> "$LOG" 2>&1; then
        ok "Wazuh config valid"
    else
        warn "Wazuh config test returned warnings — check $LOG"
    fi
    systemctl restart wazuh-manager >> "$LOG" 2>&1
    sleep 3
    if systemctl is-active wazuh-manager &>/dev/null; then
        ok "Wazuh manager restarted"
    else
        die "Wazuh failed to start — check: journalctl -u wazuh-manager"
    fi
}

reload_webserver() {
    local ws
    ws=$(detect_webserver)
    if [[ "$ws" == "nginx" ]]; then
        nginx -t >> "$LOG" 2>&1 && nginx -s reload >> "$LOG" 2>&1
    elif [[ "$ws" == "apache2" ]]; then
        apache2ctl configtest >> "$LOG" 2>&1 && systemctl reload apache2 >> "$LOG" 2>&1
    elif [[ "$ws" == "httpd" ]]; then
        httpd configtest >> "$LOG" 2>&1 && systemctl reload httpd >> "$LOG" 2>&1
    fi
}

print_summary() {
    local ws
    ws=$(detect_webserver)
    echo -e "\n${BOLD}${GREEN}=================================================${RESET}"
    echo -e "${BOLD}${GREEN}  WAF module installation complete${RESET}"
    echo -e "${BOLD}${GREEN}=================================================${RESET}"
    echo ""
    echo -e "  ${BOLD}Web server:${RESET}      $ws"
    echo -e "  ${BOLD}WAF rules:${RESET}       /var/ossec/etc/rules/0120-modsec-waf.xml"
    echo -e "  ${BOLD}ModSec audit:${RESET}    /var/log/modsec_audit.log"
    echo -e "  ${BOLD}Install log:${RESET}     $LOG"
    echo ""
    echo -e "  ${BOLD}Test ModSecurity:${RESET}"
    echo -e "    curl -I 'http://localhost/?id=1 OR 1=1'"
    echo ""
    echo -e "  ${BOLD}CrowdSec status:${RESET}"
    echo -e "    cscli metrics"
    echo -e "    cscli decisions list"
    echo ""
    echo -e "  ${BOLD}Check headers:${RESET}"
    echo -e "    curl -I https://your-domain.com"
    echo ""
}

interactive_menu() {
    echo -e "${BOLD}${CYAN}"
    echo -e "  +----------------------------------------------+"
    echo -e "  |  Wazuh Protection Suite — WAF Module         |"
    echo -e "  |  Extension installer v1.0                    |"
    echo -e "  +----------------------------------------------+"
    echo -e "${RESET}"

    echo -e "\n${BOLD}Available modules:${RESET}"
    echo "  1) ModSecurity + OWASP CRS"
    echo "  2) CrowdSec (collective IP reputation)"
    echo "  3) Security headers (HSTS, CSP, X-Frame, etc.)"
    echo "  4) Rate limiting (nginx / Apache)"
    echo "  5) GeoIP country blocking"
    echo "  A) All of the above"
    echo ""

    read -rp "Select modules to install (e.g. 1,2,3 or A for all): " choice

    if [[ "${choice,,}" == "a" ]]; then
        INSTALL_MODSEC=true
        INSTALL_CROWDSEC=true
        INSTALL_HEADERS=true
        INSTALL_RATELIMIT=true
        INSTALL_GEOIP=true
    else
        INSTALL_MODSEC=false
        INSTALL_CROWDSEC=false
        INSTALL_HEADERS=false
        INSTALL_RATELIMIT=false
        INSTALL_GEOIP=false

        IFS=',' read -ra choices <<< "$choice"
        for c in "${choices[@]}"; do
            c=$(echo "$c" | xargs)
            case "$c" in
                1) INSTALL_MODSEC=true ;;
                2) INSTALL_CROWDSEC=true ;;
                3) INSTALL_HEADERS=true ;;
                4) INSTALL_RATELIMIT=true ;;
                5) INSTALL_GEOIP=true ;;
                *) warn "Unknown option: $c" ;;
            esac
        done
    fi

    # GeoIP mode
    if $INSTALL_GEOIP; then
        echo ""
        read -rp "GeoIP mode — (d)eny listed countries or (a)llow only listed? [d/a]: " geo_mode
        if [[ "${geo_mode,,}" == "a" ]]; then
            export GEOIP_MODE="allow"
        fi
    fi
}

main() {
    > "$LOG"
    check_root
    check_prereqs

    local single_module=""

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --module)
                single_module="$2"
                shift 2
                ;;
            --all)
                INSTALL_MODSEC=true
                INSTALL_CROWDSEC=true
                INSTALL_HEADERS=true
                INSTALL_RATELIMIT=true
                INSTALL_GEOIP=true
                shift
                ;;
            --geoip-mode)
                export GEOIP_MODE="$2"
                shift 2
                ;;
            *)
                die "Unknown argument: $1"
                ;;
        esac
    done

    # Single module mode
    if [[ -n "$single_module" ]]; then
        case "$single_module" in
            modsec)    install_modsec ;;
            crowdsec)  run_module "crowdsec" ;;
            headers)   run_module "security-headers" ;;
            ratelimit) run_module "rate-limit" ;;
            geoip)     run_module "geoip" ;;
            *)         die "Unknown module: $single_module" ;;
        esac
        reload_webserver
        print_summary
        exit 0
    fi

    # Interactive mode if no --all flag
    if [[ -z "${INSTALL_MODSEC:-}" ]]; then
        interactive_menu
    fi

    # Run selected modules
    $INSTALL_MODSEC    && install_modsec
    $INSTALL_CROWDSEC  && run_module "crowdsec"
    $INSTALL_HEADERS   && run_module "security-headers"
    $INSTALL_RATELIMIT && run_module "rate-limit"
    $INSTALL_GEOIP     && run_module "geoip"

    # Wazuh integration
    install_wazuh_rules
    patch_ossec_conf_waf
    reload_webserver
    restart_wazuh
    print_summary
}

main "$@"

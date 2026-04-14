#!/usr/bin/env bash
# Module: CrowdSec + bouncer
# Called by install-waf.sh

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

install_crowdsec() {
    section "CrowdSec"

    local os
    os=$(detect_os)

    # Install CrowdSec engine
    print "Installing CrowdSec..."
    if [[ "$os" == "debian" ]]; then
        if ! command -v cscli &>/dev/null; then
            curl -s https://install.crowdsec.net | bash >> "$LOG" 2>&1
            log_cmd apt-get install -y -q crowdsec
        else
            ok "CrowdSec already installed"
        fi
    elif [[ "$os" == "rhel" ]]; then
        if ! command -v cscli &>/dev/null; then
            curl -s https://install.crowdsec.net | bash >> "$LOG" 2>&1
            log_cmd yum install -y -q crowdsec
        else
            ok "CrowdSec already installed"
        fi
    fi

    # Install collections for web detection
    print "Installing CrowdSec collections..."
    log_cmd cscli collections install crowdsecurity/linux
    log_cmd cscli collections install crowdsecurity/nginx 2>/dev/null || true
    log_cmd cscli collections install crowdsecurity/apache2 2>/dev/null || true
    log_cmd cscli collections install crowdsecurity/http-cve 2>/dev/null || true
    log_cmd cscli collections install crowdsecurity/modsecurity 2>/dev/null || true

    # Install bouncer
    install_crowdsec_bouncer

    # Apply whitelist
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    local wl_conf="$script_dir/conf/crowdsec-whitelist.yaml"
    if [[ -f "$wl_conf" ]]; then
        local cs_dir="/etc/crowdsec/parsers/s02-enrich"
        mkdir -p "$cs_dir"
        cp "$wl_conf" "$cs_dir/wazuh-whitelist.yaml"
        ok "Whitelist applied"
    fi

    # Configure log sources
    configure_crowdsec_acquis

    # Enable and start
    systemctl enable crowdsec >> "$LOG" 2>&1
    systemctl restart crowdsec >> "$LOG" 2>&1

    ok "CrowdSec installed and running"
    print "Dashboard: cscli metrics"
    print "Decisions:  cscli decisions list"
    print "Alerts:     cscli alerts list"
}

install_crowdsec_bouncer() {
    local ws
    ws=$(detect_webserver)

    if [[ "$ws" == "nginx" ]]; then
        print "Installing nginx bouncer..."
        log_cmd cscli bouncers add wazuh-nginx-bouncer -o raw > /tmp/cs-bouncer-key.txt 2>/dev/null || true
        local os
        os=$(detect_os)
        if [[ "$os" == "debian" ]]; then
            log_cmd apt-get install -y -q crowdsec-nginx-bouncer 2>/dev/null || \
                install_bouncer_openresty
        elif [[ "$os" == "rhel" ]]; then
            log_cmd yum install -y -q crowdsec-nginx-bouncer 2>/dev/null || \
                install_bouncer_openresty
        fi
    else
        # Firewall bouncer works with anything
        print "Installing firewall bouncer..."
        log_cmd cscli bouncers add wazuh-fw-bouncer -o raw > /tmp/cs-bouncer-key.txt 2>/dev/null || true
        local os
        os=$(detect_os)
        if [[ "$os" == "debian" ]]; then
            log_cmd apt-get install -y -q crowdsec-firewall-bouncer-iptables
        elif [[ "$os" == "rhel" ]]; then
            log_cmd yum install -y -q crowdsec-firewall-bouncer-iptables
        fi
    fi

    # Configure bouncer with the key
    if [[ -f /tmp/cs-bouncer-key.txt ]]; then
        local key
        key=$(cat /tmp/cs-bouncer-key.txt)
        if [[ -f /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml ]]; then
            sed -i "s/^api_key:.*/api_key: $key/" /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
        fi
        if [[ -f /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf ]]; then
            sed -i "s/^API_KEY=.*/API_KEY=$key/" /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf
        fi
        rm -f /tmp/cs-bouncer-key.txt
    fi

    ok "Bouncer installed"
}

install_bouncer_openresty() {
    warn "Pre-built nginx bouncer not available, falling back to firewall bouncer"
    local os
    os=$(detect_os)
    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get install -y -q crowdsec-firewall-bouncer-iptables
    elif [[ "$os" == "rhel" ]]; then
        log_cmd yum install -y -q crowdsec-firewall-bouncer-iptables
    fi
}

configure_crowdsec_acquis() {
    local acquis="/etc/crowdsec/acquis.yaml"

    # Don't duplicate entries
    local marker="# wazuh-protection-suite"
    if grep -q "$marker" "$acquis" 2>/dev/null; then
        warn "CrowdSec acquis already configured — skipping"
        return
    fi

    cat >> "$acquis" <<EOF

$marker
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
  - /var/log/apache2/access.log
  - /var/log/apache2/error.log
  - /var/log/httpd/access_log
  - /var/log/httpd/error_log
labels:
  type: syslog
---
$marker modsec
filenames:
  - /var/log/modsec_audit.log
labels:
  type: modsecurity
EOF

    ok "CrowdSec log sources configured"
}

install_crowdsec

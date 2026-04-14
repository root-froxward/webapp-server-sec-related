#!/usr/bin/env bash
# Module: OWASP Core Rule Set
# Called by install-waf.sh after modsec-nginx.sh or modsec-apache.sh

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

CRS_VERSION="4.8.0"
CRS_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"

install_owasp_crs() {
    section "OWASP Core Rule Set v${CRS_VERSION}"

    local ws
    ws=$(detect_webserver)

    local crs_dest=""
    if [[ "$ws" == "nginx" ]]; then
        crs_dest="/etc/nginx/modsecurity/crs"
    else
        crs_dest="/etc/modsecurity/crs"
    fi

    mkdir -p "$crs_dest"

    # Download and extract
    print "Downloading CRS v${CRS_VERSION}..."
    local tmp_tar="/tmp/crs-${CRS_VERSION}.tar.gz"
    wget -q -O "$tmp_tar" "$CRS_URL"
    tar -xzf "$tmp_tar" -C /tmp/

    local extracted="/tmp/coreruleset-${CRS_VERSION}"
    if [[ ! -d "$extracted" ]]; then
        # Handle possible naming differences
        extracted=$(ls -d /tmp/coreruleset-* 2>/dev/null | head -1)
    fi

    if [[ -z "$extracted" || ! -d "$extracted" ]]; then
        die "CRS extraction failed"
    fi

    # Install rules
    cp -r "$extracted/rules" "$crs_dest/"
    cp "$extracted/crs-setup.conf.example" "$crs_dest/crs-setup.conf.example"

    # Copy our tuned setup
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cp "$script_dir/conf/crs-setup.conf" "$crs_dest/crs-setup.conf"

    # Plugins (optional — install if present)
    if [[ -d "$extracted/plugins" ]]; then
        cp -r "$extracted/plugins" "$crs_dest/"
    fi

    # Cleanup
    rm -rf "$tmp_tar" "$extracted"

    # Verify config
    if [[ "$ws" == "nginx" ]]; then
        if nginx -t >> "$LOG" 2>&1; then
            ok "CRS installed and nginx config valid"
        else
            warn "CRS installed but nginx config test failed — check $LOG"
        fi
    else
        local apache_bin="apache2ctl"
        command -v httpd &>/dev/null && apache_bin="httpd"
        if $apache_bin configtest >> "$LOG" 2>&1; then
            ok "CRS installed and Apache config valid"
        else
            warn "CRS installed but Apache config test failed — check $LOG"
        fi
    fi

    print "Rules installed to: $crs_dest"
    print "Paranoia level: 2, Anomaly threshold: 10"
    print "Edit $crs_dest/crs-setup.conf to tune"
}

install_owasp_crs

#!/usr/bin/env bash
# Module: GeoIP country-based blocking
# Called by install-waf.sh
# Uses MaxMind GeoLite2 database

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

GEOIP_DB_DIR="/usr/share/GeoIP"
GEOIP_DB="$GEOIP_DB_DIR/GeoLite2-Country.mmdb"

install_geoip() {
    section "GeoIP country blocking"

    install_geoip_deps
    download_geoip_db
    configure_geoip
    setup_geoip_update

    ok "GeoIP blocking configured"
}

install_geoip_deps() {
    local os
    os=$(detect_os)

    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get install -y -q geoipupdate libmaxminddb0 libmaxminddb-dev mmdb-bin
        # nginx geoip2 module
        if command -v nginx &>/dev/null; then
            log_cmd apt-get install -y -q libnginx-mod-http-geoip2 2>/dev/null || \
                warn "nginx geoip2 module not in repos — may need to build from source"
        fi
    elif [[ "$os" == "rhel" ]]; then
        log_cmd yum install -y -q libmaxminddb libmaxminddb-devel
    fi
}

download_geoip_db() {
    mkdir -p "$GEOIP_DB_DIR"

    if [[ -f "$GEOIP_DB" ]]; then
        ok "GeoIP database already exists"
        return
    fi

    # Try geoipupdate first (requires MaxMind account)
    if command -v geoipupdate &>/dev/null; then
        local geoip_conf="/etc/GeoIP.conf"
        if [[ -f "$geoip_conf" ]] && grep -q "AccountID" "$geoip_conf"; then
            print "Running geoipupdate..."
            if geoipupdate >> "$LOG" 2>&1; then
                ok "GeoIP database updated via geoipupdate"
                return
            fi
        fi
    fi

    # If no MaxMind credentials, try the free DB-IP database (no key required)
    print "No MaxMind credentials found. Downloading DB-IP Lite database..."
    local month
    month=$(date +%Y-%m)
    local dbip_url="https://download.db-ip.com/free/dbip-country-lite-${month}.mmdb.gz"

    if wget -q -O /tmp/geoip.mmdb.gz "$dbip_url" 2>/dev/null; then
        gunzip -f /tmp/geoip.mmdb.gz
        mv /tmp/geoip.mmdb "$GEOIP_DB"
        ok "DB-IP Lite database installed"
    else
        warn "Could not download GeoIP database."
        warn "For MaxMind: register at maxmind.com, put credentials in /etc/GeoIP.conf"
        warn "Then run: geoipupdate"
        return
    fi
}

configure_geoip() {
    local ws
    ws=$(detect_webserver)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    # Read country list
    local countries_file="$script_dir/conf/geoip-countries.conf"
    local countries=()
    if [[ -f "$countries_file" ]]; then
        while IFS= read -r line; do
            line=$(echo "$line" | xargs)
            [[ -z "$line" || "$line" == \#* ]] && continue
            countries+=("$line")
        done < "$countries_file"
    fi

    if [[ ${#countries[@]} -eq 0 ]]; then
        warn "No countries in geoip-countries.conf — GeoIP module installed but no blocking active"
        warn "Edit conf/geoip-countries.conf and re-run, or configure manually"
        return
    fi

    local mode="${GEOIP_MODE:-deny}"

    if [[ "$ws" == "nginx" ]]; then
        configure_geoip_nginx "$mode" "${countries[@]}"
    elif [[ "$ws" == "apache2" || "$ws" == "httpd" ]]; then
        configure_geoip_apache "$mode" "${countries[@]}"
    fi
}

configure_geoip_nginx() {
    local mode="$1"
    shift
    local countries=("$@")

    local conf="/etc/nginx/conf.d/wazuh-geoip.conf"
    local inc="/etc/nginx/conf.d/wazuh-geoip-include.conf"

    # Load module if needed
    if ! grep -q "ngx_http_geoip2_module" /etc/nginx/nginx.conf 2>/dev/null; then
        local mod_path=""
        for p in /usr/lib/nginx/modules/ngx_http_geoip2_module.so \
                 /usr/lib64/nginx/modules/ngx_http_geoip2_module.so \
                 /etc/nginx/modules/ngx_http_geoip2_module.so; do
            [[ -f "$p" ]] && mod_path="$p" && break
        done
        if [[ -n "$mod_path" ]]; then
            sed -i "1i load_module $mod_path;" /etc/nginx/nginx.conf
        fi
    fi

    # GeoIP2 map (http context)
    cat > "$conf" <<EOF
# wazuh-protection-suite GeoIP blocking
geoip2 $GEOIP_DB {
    auto_reload 24h;
    \$geoip2_data_country_code country iso_code;
}

map \$geoip2_data_country_code \$wazuh_geoip_blocked {
    default $([ "$mode" = "allow" ] && echo "1" || echo "0");
EOF

    for cc in "${countries[@]}"; do
        if [[ "$mode" == "deny" ]]; then
            echo "    $cc 1;" >> "$conf"
        else
            echo "    $cc 0;" >> "$conf"
        fi
    done

    echo "}" >> "$conf"

    # Include file for server blocks
    cat > "$inc" <<'EOF'
# Include inside server {} blocks:
#   include /etc/nginx/conf.d/wazuh-geoip-include.conf;

if ($wazuh_geoip_blocked) {
    return 403;
}
EOF

    if nginx -t >> "$LOG" 2>&1; then
        nginx -s reload >> "$LOG" 2>&1
        ok "nginx GeoIP blocking active (mode=$mode, countries=${#countries[@]})"
    else
        warn "nginx config test failed with GeoIP — check $LOG"
    fi
}

configure_geoip_apache() {
    local mode="$1"
    shift
    local countries=("$@")

    # Apache needs mod_maxminddb
    local os
    os=$(detect_os)
    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get install -y -q libapache2-mod-maxminddb 2>/dev/null || \
            warn "mod_maxminddb not available — install manually"
        log_cmd a2enmod maxminddb 2>/dev/null || true
    fi

    local conf=""
    if [[ -d /etc/apache2/conf-available ]]; then
        conf="/etc/apache2/conf-available/wazuh-geoip.conf"
    elif [[ -d /etc/httpd/conf.d ]]; then
        conf="/etc/httpd/conf.d/wazuh-geoip.conf"
    fi

    cat > "$conf" <<EOF
# wazuh-protection-suite GeoIP blocking for Apache

<IfModule mod_maxminddb.c>
    MaxMindDBEnable On
    MaxMindDBFile COUNTRY_DB $GEOIP_DB
    MaxMindDBEnv COUNTRY_CODE COUNTRY_DB/country/iso_code
</IfModule>

# Block/allow by country
<IfModule mod_rewrite.c>
    RewriteEngine On
EOF

    if [[ "$mode" == "deny" ]]; then
        for cc in "${countries[@]}"; do
            echo "    RewriteCond %{ENV:COUNTRY_CODE} ^${cc}$" >> "$conf"
            echo "    RewriteRule .* - [F,L]" >> "$conf"
        done
    else
        # Allow mode: block everything except listed
        local cond_line="    RewriteCond %{ENV:COUNTRY_CODE} !^("
        cond_line+=$(IFS='|'; echo "${countries[*]}")
        cond_line+=")$"
        echo "$cond_line" >> "$conf"
        echo "    RewriteRule .* - [F,L]" >> "$conf"
    fi

    echo "</IfModule>" >> "$conf"

    if [[ -d /etc/apache2/conf-available ]]; then
        log_cmd a2enmod rewrite
        log_cmd a2enconf wazuh-geoip
    fi

    local apache_bin="apache2ctl"
    command -v httpd &>/dev/null && apache_bin="httpd"
    if $apache_bin configtest >> "$LOG" 2>&1; then
        systemctl reload "$( [[ -f /etc/debian_version ]] && echo apache2 || echo httpd )" >> "$LOG" 2>&1
        ok "Apache GeoIP blocking active"
    else
        warn "Apache config test failed — check $LOG"
    fi
}

setup_geoip_update() {
    # Weekly cron to update the database
    cat > /etc/cron.weekly/wazuh-geoip-update <<'EOF'
#!/bin/bash
if command -v geoipupdate &>/dev/null; then
    geoipupdate 2>/dev/null
else
    MONTH=$(date +%Y-%m)
    wget -q -O /tmp/geoip.mmdb.gz "https://download.db-ip.com/free/dbip-country-lite-${MONTH}.mmdb.gz" 2>/dev/null && \
        gunzip -f /tmp/geoip.mmdb.gz && \
        mv /tmp/geoip.mmdb /usr/share/GeoIP/GeoLite2-Country.mmdb
fi
EOF
    chmod +x /etc/cron.weekly/wazuh-geoip-update
    ok "Weekly GeoIP database update cron installed"
}

install_geoip

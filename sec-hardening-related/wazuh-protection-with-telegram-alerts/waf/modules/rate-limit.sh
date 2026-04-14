#!/usr/bin/env bash
# Module: Rate limiting for nginx and Apache
# Called by install-waf.sh
# Extends the basic rate limiting from install.sh with WAF-aware zones

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

install_rate_limiting() {
    section "Rate limiting"

    local ws
    ws=$(detect_webserver)

    if [[ "$ws" == "nginx" ]]; then
        setup_ratelimit_nginx
    elif [[ "$ws" == "apache2" || "$ws" == "httpd" ]]; then
        setup_ratelimit_apache
    else
        warn "No web server detected — skipping rate limiting"
        return
    fi

    ok "Rate limiting configured"
}

setup_ratelimit_nginx() {
    local conf="/etc/nginx/conf.d/wazuh-waf-ratelimit.conf"
    local inc="/etc/nginx/conf.d/wazuh-waf-ratelimit-include.conf"

    if [[ -f "$conf" ]]; then
        warn "WAF rate limit config already exists — skipping"
        return
    fi

    # Zone definitions (http context)
    cat > "$conf" <<'EOF'
# wazuh-protection-suite WAF-aware rate limiting
# Zone definitions — placed in http {} context via conf.d

# General request rate
limit_req_zone $binary_remote_addr zone=waf_general:20m rate=50r/s;

# Login / auth endpoints
limit_req_zone $binary_remote_addr zone=waf_login:10m rate=3r/m;

# API endpoints
limit_req_zone $binary_remote_addr zone=waf_api:20m rate=100r/s;

# File upload endpoints
limit_req_zone $binary_remote_addr zone=waf_upload:10m rate=5r/m;

# Static assets (higher limit)
limit_req_zone $binary_remote_addr zone=waf_static:10m rate=200r/s;

# Connection limits
limit_conn_zone $binary_remote_addr zone=waf_conn_ip:10m;

# Custom status for rate-limited requests (429 Too Many Requests)
limit_req_status 429;
limit_conn_status 429;
EOF

    # Include file for server/location blocks
    cat > "$inc" <<'EOF'
# Include inside server {} or specific location {} blocks:
#   include /etc/nginx/conf.d/wazuh-waf-ratelimit-include.conf;

# General rate limit — apply to all locations
limit_req zone=waf_general burst=100 nodelay;

# Connection limit per IP
limit_conn waf_conn_ip 50;

# For login endpoints, add inside location /login { } etc:
#   limit_req zone=waf_login burst=5 nodelay;
#
# For API endpoints:
#   limit_req zone=waf_api burst=200 nodelay;
#
# For upload endpoints:
#   limit_req zone=waf_upload burst=3 nodelay;
EOF

    # Auto-include in server blocks
    for site in /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf; do
        [[ -f "$site" ]] || continue
        [[ "$site" == *wazuh* ]] && continue
        if grep -q "server {" "$site" && ! grep -q "waf-ratelimit-include" "$site"; then
            sed -i '0,/server\s*{/s/server\s*{/server {\n        include \/etc\/nginx\/conf.d\/wazuh-waf-ratelimit-include.conf;/' "$site"
            print "Rate limiting added to $(basename "$site")"
        fi
    done

    if nginx -t >> "$LOG" 2>&1; then
        nginx -s reload >> "$LOG" 2>&1
        ok "nginx reloaded with rate limiting"
    else
        warn "nginx config test failed — check $LOG"
    fi
}

setup_ratelimit_apache() {
    # Apache rate limiting via mod_ratelimit and mod_evasive

    local os
    os=$(detect_os)

    # Install mod_evasive
    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get install -y -q libapache2-mod-evasive
        log_cmd a2enmod evasive
        log_cmd a2enmod ratelimit
    elif [[ "$os" == "rhel" ]]; then
        log_cmd yum install -y -q mod_evasive
    fi

    local conf=""
    if [[ -d /etc/apache2/conf-available ]]; then
        conf="/etc/apache2/conf-available/wazuh-ratelimit.conf"
    elif [[ -d /etc/httpd/conf.d ]]; then
        conf="/etc/httpd/conf.d/wazuh-ratelimit.conf"
    fi

    if [[ -f "$conf" ]]; then
        warn "Rate limit config already exists — skipping"
        return
    fi

    cat > "$conf" <<'EOF'
# wazuh-protection-suite rate limiting for Apache

<IfModule mod_evasive24.c>
    DOSHashTableSize    3097
    DOSPageCount        10
    DOSSiteCount        100
    DOSPageInterval     1
    DOSSiteInterval     1
    DOSBlockingPeriod   300
    DOSEmailNotify      root@localhost
    DOSLogDir           "/var/log/mod_evasive"
</IfModule>

# Rate limit for specific locations
<IfModule mod_ratelimit.c>
    <Location /login>
        SetOutputFilter RATE_LIMIT
        SetEnv rate-limit 512
    </Location>
    <Location /api>
        SetOutputFilter RATE_LIMIT
        SetEnv rate-limit 1024
    </Location>
</IfModule>
EOF

    mkdir -p /var/log/mod_evasive
    chown www-data:www-data /var/log/mod_evasive 2>/dev/null || \
        chown apache:apache /var/log/mod_evasive 2>/dev/null || true

    if [[ -d /etc/apache2/conf-available ]]; then
        log_cmd a2enconf wazuh-ratelimit
    fi

    local apache_bin="apache2ctl"
    command -v httpd &>/dev/null && apache_bin="httpd"
    if $apache_bin configtest >> "$LOG" 2>&1; then
        systemctl reload "$( [[ -f /etc/debian_version ]] && echo apache2 || echo httpd )" >> "$LOG" 2>&1
        ok "Apache reloaded with rate limiting"
    else
        warn "Apache config test failed — check $LOG"
    fi
}

install_rate_limiting

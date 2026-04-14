#!/usr/bin/env bash
# Module: Security headers (CSP, HSTS, X-Frame, etc.)
# Called by install-waf.sh

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

install_security_headers() {
    section "Security headers"

    local ws
    ws=$(detect_webserver)

    if [[ "$ws" == "nginx" ]]; then
        setup_headers_nginx
    elif [[ "$ws" == "apache2" || "$ws" == "httpd" ]]; then
        setup_headers_apache
    else
        warn "No web server detected — skipping security headers"
        return
    fi

    ok "Security headers configured"
}

setup_headers_nginx() {
    local conf="/etc/nginx/conf.d/wazuh-security-headers.conf"
    local marker="# wazuh-protection-suite security headers"

    if [[ -f "$conf" ]]; then
        warn "Security headers config already exists — skipping"
        return
    fi

    cat > "$conf" <<'EOF'
# wazuh-protection-suite security headers
# Add these inside server{} blocks, or use include from here.
# This file defines a map + header block usable globally.

# -- Headers applied via add_header in server blocks --
# To use: include /etc/nginx/conf.d/wazuh-security-headers-include.conf;
# inside each server {} block.
EOF

    # The actual include file for server blocks
    local inc="/etc/nginx/conf.d/wazuh-security-headers-include.conf"
    cat > "$inc" <<'INCEOF'
# Include this inside server {} blocks:
#   include /etc/nginx/conf.d/wazuh-security-headers-include.conf;

# HSTS — force HTTPS for 1 year, include subdomains
# Remove includeSubDomains if you have HTTP-only subdomains
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Prevent MIME type sniffing
add_header X-Content-Type-Options "nosniff" always;

# Clickjacking protection
add_header X-Frame-Options "SAMEORIGIN" always;

# XSS filter (legacy, but still useful for older browsers)
add_header X-XSS-Protection "1; mode=block" always;

# Referrer policy — send origin only on cross-origin
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Permissions policy — restrict browser features
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;

# Content Security Policy — EDIT THIS for your application
# Default is restrictive. Loosen as needed.
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';" always;

# Prevent caching of sensitive pages (optional — uncomment if needed)
# add_header Cache-Control "no-store, no-cache, must-revalidate" always;
# add_header Pragma "no-cache" always;

# Cross-Origin policies
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
INCEOF

    # Try to auto-include in existing server blocks
    local main_conf="/etc/nginx/nginx.conf"
    if grep -q "server {" "$main_conf" && ! grep -q "wazuh-security-headers-include" "$main_conf"; then
        # Only add to the first server block as an example
        sed -i '0,/server\s*{/s/server\s*{/server {\n        include \/etc\/nginx\/conf.d\/wazuh-security-headers-include.conf;/' "$main_conf"
        print "Auto-included in nginx.conf server block"
    fi

    # Also check sites-enabled
    for site in /etc/nginx/sites-enabled/*; do
        [[ -f "$site" ]] || continue
        if ! grep -q "wazuh-security-headers-include" "$site"; then
            sed -i '0,/server\s*{/s/server\s*{/server {\n        include \/etc\/nginx\/conf.d\/wazuh-security-headers-include.conf;/' "$site"
            print "Auto-included in $(basename "$site")"
        fi
    done

    if nginx -t >> "$LOG" 2>&1; then
        nginx -s reload >> "$LOG" 2>&1
        ok "nginx reloaded with security headers"
    else
        warn "nginx config test failed after adding headers — check $LOG"
    fi
}

setup_headers_apache() {
    local conf=""
    if [[ -d /etc/apache2/conf-available ]]; then
        conf="/etc/apache2/conf-available/wazuh-security-headers.conf"
    elif [[ -d /etc/httpd/conf.d ]]; then
        conf="/etc/httpd/conf.d/wazuh-security-headers.conf"
    else
        warn "Cannot find Apache config directory"
        return
    fi

    if [[ -f "$conf" ]]; then
        warn "Security headers config already exists — skipping"
        return
    fi

    # Ensure headers module is loaded
    if command -v a2enmod &>/dev/null; then
        log_cmd a2enmod headers
    fi

    cat > "$conf" <<'EOF'
# wazuh-protection-suite security headers

<IfModule mod_headers.c>
    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    # Prevent MIME sniffing
    Header always set X-Content-Type-Options "nosniff"

    # Clickjacking
    Header always set X-Frame-Options "SAMEORIGIN"

    # XSS filter (legacy)
    Header always set X-XSS-Protection "1; mode=block"

    # Referrer
    Header always set Referrer-Policy "strict-origin-when-cross-origin"

    # Permissions
    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"

    # CSP — EDIT for your application
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"

    # Cross-Origin policies
    Header always set Cross-Origin-Opener-Policy "same-origin"
    Header always set Cross-Origin-Resource-Policy "same-origin"
    Header always set Cross-Origin-Embedder-Policy "require-corp"

    # Strip server version
    Header always unset X-Powered-By
    Header always unset Server
</IfModule>
EOF

    if [[ -d /etc/apache2/conf-available ]]; then
        log_cmd a2enconf wazuh-security-headers
    fi

    local apache_bin="apache2ctl"
    command -v httpd &>/dev/null && apache_bin="httpd"
    if $apache_bin configtest >> "$LOG" 2>&1; then
        systemctl reload "$( [[ -f /etc/debian_version ]] && echo apache2 || echo httpd )" >> "$LOG" 2>&1
        ok "Apache reloaded with security headers"
    else
        warn "Apache config test failed — check $LOG"
    fi
}

install_security_headers

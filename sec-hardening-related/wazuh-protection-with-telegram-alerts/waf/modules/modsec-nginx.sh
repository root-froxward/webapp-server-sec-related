#!/usr/bin/env bash
# Module: ModSecurity v3 (libmodsecurity) for nginx
# Called by install-waf.sh — not meant to run standalone

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

install_modsec_nginx() {
    section "ModSecurity v3 for nginx"

    local os
    os=$(detect_os)

    if [[ "$os" == "debian" ]]; then
        # Try the prebuilt package first (available on Ubuntu 22.04+ / Debian 12+)
        if apt-cache show libnginx-mod-http-modsecurity &>/dev/null 2>&1; then
            print "Installing from package..."
            log_cmd apt-get install -y -q libnginx-mod-http-modsecurity libmodsecurity3
        else
            print "Package not available, building from source..."
            build_modsec_nginx_source
        fi
    elif [[ "$os" == "rhel" ]]; then
        print "Building from source on RHEL..."
        build_modsec_nginx_source
    else
        die "Unsupported OS for ModSecurity nginx module"
    fi

    configure_modsec_nginx
    ok "ModSecurity v3 for nginx installed"
}

build_modsec_nginx_source() {
    local build_dir="/tmp/modsec-build"
    mkdir -p "$build_dir"

    local os
    os=$(detect_os)

    # Build dependencies
    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get install -y -q \
            build-essential git libpcre3-dev zlib1g-dev libssl-dev \
            libxml2-dev libyajl-dev libcurl4-openssl-dev \
            libgeoip-dev liblmdb-dev libfuzzy-dev \
            pkg-config automake libtool
    elif [[ "$os" == "rhel" ]]; then
        log_cmd yum groupinstall -y -q "Development Tools"
        log_cmd yum install -y -q \
            pcre-devel zlib-devel openssl-devel libxml2-devel \
            yajl-devel curl-devel GeoIP-devel lmdb-devel \
            ssdeep-devel pkgconfig automake libtool
    fi

    # Build libmodsecurity
    print "Building libmodsecurity3 (this takes a few minutes)..."
    cd "$build_dir"
    if [[ ! -d ModSecurity ]]; then
        git clone --depth 1 -b v3/master https://github.com/owasp-modsecurity/ModSecurity.git
    fi
    cd ModSecurity
    git submodule init && git submodule update
    ./build.sh >> "$LOG" 2>&1
    ./configure >> "$LOG" 2>&1
    make -j"$(nproc)" >> "$LOG" 2>&1
    make install >> "$LOG" 2>&1
    ldconfig

    # Build nginx connector
    print "Building nginx ModSecurity connector..."
    cd "$build_dir"
    if [[ ! -d ModSecurity-nginx ]]; then
        git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git
    fi

    # Get current nginx version and build as dynamic module
    local nginx_ver
    nginx_ver=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
    cd "$build_dir"
    if [[ ! -d "nginx-${nginx_ver}" ]]; then
        wget -q "http://nginx.org/download/nginx-${nginx_ver}.tar.gz"
        tar -xzf "nginx-${nginx_ver}.tar.gz"
    fi
    cd "nginx-${nginx_ver}"

    local nginx_args
    nginx_args=$(nginx -V 2>&1 | grep -oP '(?<=configure arguments: ).*' || true)
    # Build only the dynamic module
    ./configure --with-compat --add-dynamic-module="$build_dir/ModSecurity-nginx" >> "$LOG" 2>&1
    make modules -j"$(nproc)" >> "$LOG" 2>&1
    cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules/ 2>/dev/null || \
        cp objs/ngx_http_modsecurity_module.so /usr/lib64/nginx/modules/ 2>/dev/null || \
        cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/

    ok "Built from source"
    rm -rf "$build_dir"
}

configure_modsec_nginx() {
    local modsec_dir="/etc/nginx/modsecurity"
    mkdir -p "$modsec_dir" /tmp/modsecurity/{tmp,data,upload}

    # Copy our config
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cp "$script_dir/conf/modsecurity.conf" "$modsec_dir/modsecurity.conf"

    # Unicode mapping file
    if [[ -f /usr/share/modsecurity-crs/unicode.mapping ]]; then
        cp /usr/share/modsecurity-crs/unicode.mapping "$modsec_dir/"
    elif [[ -f /usr/local/modsecurity/unicode.mapping ]]; then
        cp /usr/local/modsecurity/unicode.mapping "$modsec_dir/"
    else
        # Download if not found
        wget -q -O "$modsec_dir/unicode.mapping" \
            "https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping" 2>/dev/null || true
    fi

    # Main include file
    cat > "$modsec_dir/main.conf" <<'EOF'
Include /etc/nginx/modsecurity/modsecurity.conf
Include /etc/nginx/modsecurity/crs/crs-setup.conf
Include /etc/nginx/modsecurity/crs/rules/*.conf
EOF

    # Ensure load_module directive exists
    local nginx_conf="/etc/nginx/nginx.conf"
    if ! grep -q "modsecurity_module" "$nginx_conf"; then
        # Find the module path
        local mod_path=""
        for p in /etc/nginx/modules/ngx_http_modsecurity_module.so \
                 /usr/lib64/nginx/modules/ngx_http_modsecurity_module.so \
                 /usr/lib/nginx/modules/ngx_http_modsecurity_module.so; do
            [[ -f "$p" ]] && mod_path="$p" && break
        done
        if [[ -n "$mod_path" ]]; then
            sed -i "1i load_module $mod_path;" "$nginx_conf"
        fi
    fi

    # Add modsecurity directives to http block if not present
    if ! grep -q "modsecurity on" "$nginx_conf"; then
        sed -i '/http\s*{/a\    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsecurity/main.conf;' "$nginx_conf"
    fi

    ok "nginx ModSecurity configured"
}

install_modsec_nginx

#!/usr/bin/env bash
# Module: mod_security2 for Apache
# Called by install-waf.sh

set -euo pipefail
source "$(dirname "$0")/../lib.sh"

install_modsec_apache() {
    section "mod_security2 for Apache"

    local os
    os=$(detect_os)

    if [[ "$os" == "debian" ]]; then
        log_cmd apt-get install -y -q libapache2-mod-security2
        log_cmd a2enmod security2
    elif [[ "$os" == "rhel" ]]; then
        log_cmd yum install -y -q mod_security mod_security_crs
    else
        die "Unsupported OS for Apache ModSecurity"
    fi

    configure_modsec_apache
    ok "mod_security2 for Apache installed"
}

configure_modsec_apache() {
    local modsec_dir="/etc/modsecurity"
    mkdir -p "$modsec_dir" /tmp/modsecurity/{tmp,data,upload}

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    # Copy our config
    cp "$script_dir/conf/modsecurity.conf" "$modsec_dir/modsecurity.conf"

    # Unicode mapping
    local crs_base="/usr/share/modsecurity-crs"
    if [[ -f "$crs_base/unicode.mapping" ]]; then
        cp "$crs_base/unicode.mapping" "$modsec_dir/"
    fi

    # Apache module config
    local apache_modsec_conf=""
    for f in /etc/apache2/mods-available/security2.conf \
             /etc/httpd/conf.d/mod_security.conf; do
        [[ -f "$f" ]] && apache_modsec_conf="$f" && break
    done

    if [[ -n "$apache_modsec_conf" ]]; then
        # Rewrite to point at our config
        cat > "$apache_modsec_conf" <<'EOF'
<IfModule security2_module>
    SecDataDir /tmp/modsecurity/data
    IncludeOptional /etc/modsecurity/modsecurity.conf
    IncludeOptional /etc/modsecurity/crs/crs-setup.conf
    IncludeOptional /etc/modsecurity/crs/rules/*.conf
</IfModule>
EOF
    fi

    # Enable audit log destination that Wazuh can read
    local audit_log="/var/log/modsec_audit.log"
    touch "$audit_log"
    chmod 640 "$audit_log"

    ok "Apache ModSecurity configured"
}

install_modsec_apache

#!/usr/bin/env bash
# =============================================================================
#  FROXWARD SECURITY STACK — setup.sh
#  Wazuh + OWASP ModSecurity + DDoS L3/L4/L7 + SOAR-lite
#  Supports: Ubuntu 20/22/24, Debian 11/12, CentOS 7/8, RHEL 8/9, Fedora
# =============================================================================
set -euo pipefail
IFS=$'\n\t'

# ─── COLORS ───────────────────────────────────────────────────────────────────
R='\033[0;31m'; Y='\033[1;33m'; G='\033[0;32m'
C='\033[0;36m'; B='\033[1m'; DIM='\033[2m'; N='\033[0m'

# ─── CONFIG (override via env) ────────────────────────────────────────────────
WAZUH_VERSION="${WAZUH_VERSION:-4.9.2}"
WAZUH_RULES_REPO="${WAZUH_RULES_REPO:-https://github.com/root-froxward/wazuh-rules}"
CRS_VERSION="${CRS_VERSION:-4.7.0}"
APP_PORT="${APP_PORT:-80}"
APP_SSL_PORT="${APP_SSL_PORT:-443}"
# Flag: was APP_PORT explicitly set via env? (even if set to 80)
[[ -n "${APP_PORT+set}" && "${APP_PORT}" != "80" ]] || [[ "${FROXWARD_PORT_SET:-}" == "1" ]] \
    && APP_PORT_SET=1 || APP_PORT_SET=0
SOAR_LOG="${SOAR_LOG:-/var/log/froxward_soar.log}"
SETUP_LOG="/var/log/froxward_setup.log"
MODSEC_DIR="/etc/modsecurity"
SOAR_SCRIPT="/usr/local/bin/froxward-response.sh"
FIREWALL="iptables"

# ─── HELPERS ──────────────────────────────────────────────────────────────────
log()    { echo -e "${G}[+]${N} $*" | tee -a "$SETUP_LOG"; }
warn()   { echo -e "${Y}[!]${N} $*" | tee -a "$SETUP_LOG"; }
err()    { echo -e "${R}[x]${N} $*" | tee -a "$SETUP_LOG"; exit 1; }
section(){ echo -e "\n${C}${B}== $* ==${N}" | tee -a "$SETUP_LOG"; }

require_root() {
    [[ $EUID -eq 0 ]] || err "Run as root: sudo bash $0"
}

# ─── OS DETECTION ─────────────────────────────────────────────────────────────
detect_os() {
    section "OS Detection"
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="${ID,,}"
        OS_VER="${VERSION_ID%%.*}"
        OS_LIKE="${ID_LIKE:+${ID_LIKE,,}}"
    else
        err "Cannot detect OS"
    fi

    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop)
            PKG_INSTALL="apt-get install -y -q"
            PKG_UPDATE="apt-get update -q"
            PKG_MANAGER="apt"
            ;;
        centos|rhel|rocky|almalinux|ol)
            if command -v dnf &>/dev/null; then
                PKG_INSTALL="dnf install -y -q"
                PKG_UPDATE="dnf makecache -q"
                PKG_MANAGER="dnf"
            else
                PKG_INSTALL="yum install -y -q"
                PKG_UPDATE="yum makecache -q"
                PKG_MANAGER="yum"
            fi
            ;;
        fedora)
            PKG_INSTALL="dnf install -y -q"
            PKG_UPDATE="dnf makecache -q"
            PKG_MANAGER="dnf"
            ;;
        *)
            if [[ "${OS_LIKE:-}" == *"debian"* ]]; then
                PKG_INSTALL="apt-get install -y -q"
                PKG_UPDATE="apt-get update -q"
                PKG_MANAGER="apt"
            elif [[ "${OS_LIKE:-}" == *"rhel"* ]] || [[ "${OS_LIKE:-}" == *"fedora"* ]]; then
                PKG_INSTALL="dnf install -y -q"
                PKG_UPDATE="dnf makecache -q"
                PKG_MANAGER="dnf"
            else
                err "Unsupported OS: $OS_ID. Supported: Ubuntu/Debian/CentOS/RHEL/Rocky/Fedora"
            fi
            ;;
    esac

    log "Detected: ${PRETTY_NAME:-$OS_ID $OS_VER}"
    log "Package manager: $PKG_MANAGER"
}

# ─── APP PORT AUTODETECT ──────────────────────────────────────────────────────
detect_app_port() {
    section "App Port Detection"


    SKIP_PORTS="22 25 53 111 443 1514 1515 3306 5432 6379 27017 55000"


    LISTENING_PORTS=()
    while IFS= read -r port; do
        skip=0
        for sp in $SKIP_PORTS; do
            [[ "$port" == "$sp" ]] && skip=1 && break
        done
        [[ $skip -eq 0 ]] && LISTENING_PORTS+=("$port")
    done < <(ss -tlnp 2>/dev/null | grep -oP '(?<=\*:|0\.0\.0\.0:|:::)\d+' | sort -un)


    if [[ "${APP_PORT_SET:-0}" == "1" ]]; then
        log "App port (from env): $APP_PORT"
        return
    fi

    if [[ ${#LISTENING_PORTS[@]} -eq 0 ]]; then
        warn "No listening ports rightnow,using default $APP_PORT"
        return
    fi

    if [[ ${#LISTENING_PORTS[@]} -eq 1 ]]; then
        APP_PORT="${LISTENING_PORTS[0]}"
        log "Detected webapp port $APP_PORT — using it automaticly"
        return
    fi

    echo ""
    echo -e "${Y}Current ports detected:${N}"
    for i in "${!LISTENING_PORTS[@]}"; do
        SVC=$(ss -tlnp 2>/dev/null | grep ":${LISTENING_PORTS[$i]} " | grep -oP '"[^"]*"' | head -1 | tr -d '"')
        [[ -z "$SVC" ]] && SVC="?"
        echo -e "  ${B}$((i+1))${N}) ${LISTENING_PORTS[$i]}  ${DIM}($SVC)${N}"
    done
    echo -e "  ${B}0${N}) Enter manually"
    echo ""

    while true; do
        read -rp "$(echo -e "${C}Pick your webapp port [1-${#LISTENING_PORTS[@]}]: ${N}")" choice
        if [[ "$choice" == "0" ]]; then
            read -rp "$(echo -e "${C}Enter your port${N}")" manual_port
            if [[ "$manual_port" =~ ^[0-9]+$ ]] && (( manual_port > 0 && manual_port < 65536 )); then
                APP_PORT="$manual_port"
                break
            else
                echo -e "${R}Invalid port. ${N}"
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#LISTENING_PORTS[@]} )); then
            APP_PORT="${LISTENING_PORTS[$((choice-1))]}"
            break
        else
            echo -e "${R}Pick a number from 1 to ${#LISTENING_PORTS[@]}.${N}"
        fi
    done

    log "Webapp Port: $APP_PORT"
}

# ─── WEB SERVER DETECTION ─────────────────────────────────────────────────────
detect_webserver() {
    section "Web Server Detection"
    WEB_SERVER=""
    WEB_CONF_DIR=""
    INSTALL_NGINX=0

    if command -v nginx &>/dev/null || systemctl is-active --quiet nginx 2>/dev/null; then
        WEB_SERVER="nginx"
        WEB_CONF_DIR="/etc/nginx"
    elif command -v apache2 &>/dev/null || command -v httpd &>/dev/null; then
        WEB_SERVER="apache"
        [[ -d /etc/apache2 ]] && WEB_CONF_DIR="/etc/apache2" || WEB_CONF_DIR="/etc/httpd"
    else
        warn "No web server found — will install nginx"
        WEB_SERVER="nginx"
        WEB_CONF_DIR="/etc/nginx"
        INSTALL_NGINX=1
    fi

    log "Web server: $WEB_SERVER"
}

# ─── DEPENDENCIES ─────────────────────────────────────────────────────────────
install_deps() {
    section "Installing Dependencies"
    $PKG_UPDATE 2>&1 | tail -3 | tee -a "$SETUP_LOG"

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        DEPS="curl wget git jq tar make gcc g++ libpcre3-dev libssl-dev \
              libyajl-dev pkgconf automake libtool libxml2-dev \
              libcurl4-openssl-dev python3 net-tools iptables ipset \
              fail2ban apt-transport-https gnupg2 lsb-release ca-certificates \
              liblmdb-dev libfuzzy-dev"
    else
        [[ "$PKG_MANAGER" == "dnf" ]] && dnf install -y epel-release &>/dev/null || true
        DEPS="curl wget git jq tar make gcc gcc-c++ pcre-devel openssl-devel \
              libyajl-devel pkgconf automake libtool libxml2-devel \
              libcurl-devel python3 net-tools iptables ipset \
              fail2ban lmdb-devel pcre2-devel"
    fi

    # shellcheck disable=SC2086
    $PKG_INSTALL $DEPS 2>&1 | grep -v "^Get\|^Hit\|^Reading\|^Building" | tee -a "$SETUP_LOG" || true

    # Detect firewall backend
    if command -v nft &>/dev/null && nft list tables &>/dev/null 2>&1; then
        FIREWALL="nftables"
    else
        FIREWALL="iptables"
    fi

    log "Firewall backend: $FIREWALL"
    log "Dependencies installed"
}

# ─── NGINX (if needed) ────────────────────────────────────────────────────────
install_nginx() {
    [[ "$INSTALL_NGINX" == "0" ]] && return
    section "Installing nginx"
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        curl -fsSL https://nginx.org/keys/nginx_signing.key \
            | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] \
http://nginx.org/packages/$(lsb_release -is | tr '[:upper:]' '[:lower:]') \
$(lsb_release -cs) nginx" > /etc/apt/sources.list.d/nginx.list
        apt-get update -q && apt-get install -y nginx
    else
        $PKG_INSTALL nginx
    fi
    systemctl enable --now nginx
    log "nginx installed"
}

# ─── MODSECURITY + OWASP CRS ──────────────────────────────────────────────────
install_modsecurity() {
    section "ModSecurity + OWASP CRS $CRS_VERSION"
    mkdir -p "$MODSEC_DIR/crs"

    if [[ "$WEB_SERVER" == "nginx" ]]; then
        _build_modsec_nginx
    else
        _install_modsec_apache
    fi

    _install_owasp_crs
    log "ModSecurity + CRS installed"
}

_build_modsec_nginx() {
    log "Building ModSecurity v3 for nginx..."
    BUILD_DIR=$(mktemp -d)

    cd "$BUILD_DIR"

    if [[ ! -f /usr/local/lib/libmodsecurity.so ]]; then
        git clone --depth=1 https://github.com/owasp-modsecurity/ModSecurity.git modsec
        cd modsec
        git submodule update --init --recursive --depth=1
        ./build.sh
        ./configure --disable-examples 2>&1 | tail -2
        make -j"$(nproc)" 2>&1 | tail -3
        make install
        cd "$BUILD_DIR"
    else
        log "libmodsecurity already present"
    fi

    NGINX_VER=$(nginx -v 2>&1 | grep -oP '\d+\.\d+\.\d+')
    git clone --depth=1 https://github.com/owasp-modsecurity/ModSecurity-nginx.git modsec-nginx
    wget -q "http://nginx.org/download/nginx-${NGINX_VER}.tar.gz"
    tar xf "nginx-${NGINX_VER}.tar.gz"
    cd "nginx-${NGINX_VER}"
    ./configure --with-compat --add-dynamic-module=../modsec-nginx 2>&1 | tail -2
    make -j"$(nproc)" modules 2>&1 | tail -2
    mkdir -p /etc/nginx/modules
    cp objs/ngx_http_modsecurity_module.so /etc/nginx/modules/

    if ! grep -q "modsecurity_module" /etc/nginx/nginx.conf; then
        sed -i '1s;^;load_module modules/ngx_http_modsecurity_module.so;\n;' /etc/nginx/nginx.conf
    fi

    rm -rf "$BUILD_DIR"
    log "ModSecurity nginx module built"
}

_install_modsec_apache() {
    log "Installing ModSecurity for Apache..."
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        apt-get install -y libapache2-mod-security2
        a2enmod security2
    else
        $PKG_INSTALL mod_security
    fi
}

_install_owasp_crs() {
    log "Downloading OWASP CRS $CRS_VERSION..."
    CRS_URL="https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz"
    CRS_TMP=$(mktemp -d)
    wget -q "$CRS_URL" -O "$CRS_TMP/crs.tar.gz"
    tar xf "$CRS_TMP/crs.tar.gz" -C "$CRS_TMP"
    CRS_SRC=$(find "$CRS_TMP" -maxdepth 1 -type d -name "coreruleset*" | head -1)

    cp -r "$CRS_SRC/rules" "$MODSEC_DIR/crs/"
    cp "$CRS_SRC/crs-setup.conf.example" "$MODSEC_DIR/crs/crs-setup.conf"
    rm -rf "$CRS_TMP"

    # modsecurity.conf
    cat > "$MODSEC_DIR/modsecurity.conf" <<'MODSECCONF'
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
SecPcreMatchLimit 500000
SecPcreMatchLimitRecursion 500000
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLog /var/log/modsec_audit.log
SecAuditLogType Serial
SecDefaultAction "phase:1,log,auditlog,deny,status:403"
SecDefaultAction "phase:2,log,auditlog,deny,status:403"

# Paranoia Level 2
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=2"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.executing_paranoia_level=2"
# Anomaly thresholds
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5"
SecAction "id:900111,phase:1,nolog,pass,t:none,setvar:tx.outbound_anomaly_score_threshold=4"
MODSECCONF

    # Custom rules
    cat > "$MODSEC_DIR/custom_rules.conf" <<'CUSTOMRULES'
# Block known scanner UAs
SecRule REQUEST_HEADERS:User-Agent "@pmf /etc/modsecurity/bad_agents.txt" \
    "id:9001,phase:1,deny,status:403,log,msg:'Blocked scanner UA',tag:'SCANNER'"

# Extra SQLi
SecRule ARGS "@detectSQLi" \
    "id:9010,phase:2,deny,status:403,log,msg:'SQLi detected',logdata:'%{MATCHED_VAR}',tag:'SQLI'"

# Shellshock
SecRule REQUEST_HEADERS "@contains () {" \
    "id:9020,phase:1,deny,status:403,log,msg:'Shellshock attempt',tag:'RCE'"

# Log4Shell (multi-encoding)
SecRule ARGS|REQUEST_HEADERS "@rx \$\{[jJ][nN][dD][iI]:" \
    "id:9030,phase:1,deny,status:403,log,msg:'Log4Shell attempt',t:urlDecodeUni,t:htmlEntityDecode,tag:'RCE'"

# Path traversal
SecRule REQUEST_URI "@rx \.\./" \
    "id:9040,phase:1,deny,status:403,log,msg:'Path traversal',tag:'LFI'"

# HTTP request smuggling — block if TE present with non-standard value
SecRule REQUEST_HEADERS:Transfer-Encoding "!@rx ^(?:chunked|identity)$" \
    "id:9050,phase:1,deny,status:400,log,msg:'Suspicious TE header',tag:'PROTO',chain"
SecRule REQUEST_HEADERS:Transfer-Encoding "!^$"

# SSRF patterns
SecRule ARGS "@rx (localhost|127\.0\.0\.1|169\.254\.169\.254|::1|0\.0\.0\.0)" \
    "id:9060,phase:2,deny,status:403,log,msg:'Potential SSRF',tag:'SSRF'"

# XXE
SecRule REQUEST_BODY "@rx <!ENTITY" \
    "id:9070,phase:2,deny,status:403,log,msg:'XXE attempt',tag:'XXE'"
CUSTOMRULES

    # Scanner UA blocklist
    cat > "$MODSEC_DIR/bad_agents.txt" <<'AGENTS'
sqlmap
nikto
nmap
masscan
zgrab
dirbuster
gobuster
wfuzz
nuclei
hydra
medusa
metasploit
havij
acunetix
nessus
openvas
w3af
skipfish
arachni
commix
jbrofuzz
grabber
whatweb
xspider
jaeles
AGENTS

    # Main include
    cat > "$MODSEC_DIR/main.conf" <<EOF
Include "$MODSEC_DIR/modsecurity.conf"
Include "$MODSEC_DIR/crs/crs-setup.conf"
Include "$MODSEC_DIR/crs/rules/*.conf"
Include "$MODSEC_DIR/custom_rules.conf"
EOF

    [[ "$WEB_SERVER" == "nginx" ]] && _configure_nginx_modsec
    log "OWASP CRS deployed (PL2)"
}

_configure_nginx_modsec() {
    mkdir -p /etc/nginx/conf.d

    # ModSec + security headers + rate limiting
    cat > /etc/nginx/conf.d/froxward_security.conf <<NGINXSEC
# ModSecurity
modsecurity on;
modsecurity_rules_file $MODSEC_DIR/main.conf;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
server_tokens off;

# L7 DDoS rate limiting zones
limit_req_zone \$binary_remote_addr zone=global_limit:20m rate=30r/m;
limit_req_zone \$binary_remote_addr zone=api_limit:10m rate=10r/m;
limit_req_zone \$binary_remote_addr zone=login_limit:10m rate=5r/m;
limit_conn_zone \$binary_remote_addr zone=conn_limit:10m;

# Slowloris mitigation
client_body_timeout    10s;
client_header_timeout  10s;
keepalive_timeout      15s;
send_timeout           10s;
reset_timedout_connection on;

# Body limits
client_max_body_size   10m;
client_body_buffer_size 128k;
client_header_buffer_size 1k;
large_client_header_buffers 4 4k;

# Scanner UA blocking
map \$http_user_agent \$bad_agent {
    default         0;
    ~*sqlmap        1;
    ~*nikto         1;
    ~*nmap          1;
    ~*masscan       1;
    ~*dirbuster     1;
    ~*gobuster      1;
    ~*wfuzz         1;
    ~*nuclei        1;
    ~*hydra         1;
    ~*acunetix      1;
    ~*nessus        1;
    ~*openvas       1;
    ~*w3af          1;
    ~*havij         1;
    ~*arachni       1;
    ""              1;
}

# Block bad HTTP methods
map \$request_method \$bad_method {
    default 0;
    TRACE   1;
    TRACK   1;
    CONNECT 1;
}
NGINXSEC

    log "nginx security config written"
}

# ─── WAZUH MANAGER ────────────────────────────────────────────────────────────
install_wazuh() {
    section "Wazuh Manager $WAZUH_VERSION"

    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        warn "Wazuh already running — skipping install, updating rules"
        _deploy_wazuh_rules
        return
    fi

    if [[ "$PKG_MANAGER" == "apt" ]]; then
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
            | gpg --no-default-keyring \
              --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] \
https://packages.wazuh.com/4.x/apt/ stable main" \
            > /etc/apt/sources.list.d/wazuh.list
        apt-get update -q
        apt-get install -y wazuh-manager
    else
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo <<EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
        $PKG_INSTALL wazuh-manager
    fi

    systemctl daemon-reload
    systemctl enable --now wazuh-manager
    log "Wazuh manager installed"
    _deploy_wazuh_rules
}

_deploy_wazuh_rules() {
    section "Deploying Froxward Wazuh Rules"
    RULES_TMP=$(mktemp -d)
    RULES_DEST="/var/ossec/etc/rules"
    mkdir -p "$RULES_DEST"

    git clone --depth=1 "$WAZUH_RULES_REPO" "$RULES_TMP/froxward" 2>&1 | tail -2
    find "$RULES_TMP/froxward" -name "*.xml" -exec cp {} "$RULES_DEST/" \;

    # Fix ownership
    WAZUH_USER="wazuh"
    id "$WAZUH_USER" &>/dev/null || WAZUH_USER="ossec"
    chown -R "${WAZUH_USER}:${WAZUH_USER}" "$RULES_DEST" 2>/dev/null || true

    OSSEC_CONF="/var/ossec/etc/ossec.conf"

    # Add custom rules to ossec.conf
    if [[ -f "$OSSEC_CONF" ]] && ! grep -q "froxward" "$OSSEC_CONF"; then
        INCLUDES=""
        for f in "$RULES_DEST"/*.xml; do
            INCLUDES+="    <include>$(basename "$f")</include>\n"
        done
        sed -i "/<\/rules>/i\\${INCLUDES}" "$OSSEC_CONF"
    fi

    _configure_wazuh_active_response "$OSSEC_CONF"
    _configure_wazuh_log_monitors "$OSSEC_CONF"

    systemctl restart wazuh-manager
    RULE_COUNT=$(find "$RULES_DEST" -maxdepth 1 -name '*.xml' 2>/dev/null | wc -l)
    log "Froxward rules deployed: $RULE_COUNT files"
    rm -rf "$RULES_TMP"
}

_configure_wazuh_active_response() {
    local conf="$1"
    [[ ! -f "$conf" ]] && return
    grep -q "firewall-drop" "$conf" && return

    cat >> "$conf" <<'WAZUH_AR'

  <!-- Froxward Active Response -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <level>7</level>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <command>host-deny</command>
    <location>local</location>
    <level>10</level>
    <timeout>3600</timeout>
  </active-response>

  <logging>
    <log_alert_level>1</log_alert_level>
    <use_jsonout_output>yes</use_jsonout_output>
  </logging>
WAZUH_AR
}

_configure_wazuh_log_monitors() {
    local conf="$1"
    [[ ! -f "$conf" ]] && return
    grep -q "modsec_audit" "$conf" && return

    cat >> "$conf" <<'MONITORS'

  <!-- Froxward log monitors -->
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/modsec_audit.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>
MONITORS
}

# ─── DDOS L3/L4 ───────────────────────────────────────────────────────────────
configure_ddos_l3l4() {
    section "DDoS Protection L3/L4"
    _apply_sysctl_hardening

    if [[ "$FIREWALL" == "nftables" ]]; then
        _setup_nftables
    else
        _setup_iptables
    fi
}

_apply_sysctl_hardening() {
    cat > /etc/sysctl.d/99-froxward.conf <<'SYSCTL'
# SYN flood
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
# ICMP
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Anti-spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
# Conntrack
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
# TCP
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_tw_reuse = 1
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
# Buffer
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
SYSCTL
    sysctl -p /etc/sysctl.d/99-froxward.conf &>/dev/null
    log "Kernel sysctl hardened"
}

_setup_nftables() {
    mkdir -p /etc/nftables.d
    cat > /etc/nftables.d/froxward.nft <<NFTEOF
#!/usr/sbin/nft -f
table inet froxward {

    set banned_ips {
        type ipv4_addr
        flags dynamic,timeout
        timeout 1h
        size 65536
    }

    set ssh_flood {
        type ipv4_addr
        flags dynamic,timeout
        timeout 60s
        size 65536
    }

    chain input {
        type filter hook input priority 0; policy drop;

        iif lo accept
        ip saddr @banned_ips drop
        ct state established,related accept
        ct state invalid drop

        # ICMP rate limit
        ip protocol icmp limit rate 10/second accept
        ip protocol icmp drop
        ip6 nexthdr icmpv6 limit rate 10/second accept
        ip6 nexthdr icmpv6 drop

        # SYN flood protection
        tcp flags syn tcp option maxseg size != 536-65535 drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == fin|syn|rst|psh|ack|urg drop
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop

        # SSH brute force — ban after 5 attempts/min
        tcp dport 22 ct state new \
            add @ssh_flood { ip saddr limit rate over 5/minute burst 10 packets } \
            add @banned_ips { ip saddr timeout 30m } drop
        tcp dport 22 accept

        # HTTP/HTTPS connection rate
        tcp dport { $APP_PORT, $APP_SSL_PORT } ct state new \
            limit rate over 150/minute burst 250 packets drop
        tcp dport { $APP_PORT, $APP_SSL_PORT } accept

        # Wazuh ports
        tcp dport { 1514, 1515, 55000 } accept

        # UDP amplification reflection ports
        udp dport { 19, 69, 111, 123, 137, 161, 389, 1900, 11211 } drop

        # Fragmented packets
        ip frag-off & 0x1fff != 0 drop

        limit rate 5/second log prefix "[FROXWARD-DROP] " flags all
        drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFTEOF

    if [[ -f /etc/nftables.conf ]]; then
        grep -q "froxward" /etc/nftables.conf || \
            echo 'include "/etc/nftables.d/froxward.nft"' >> /etc/nftables.conf
    fi

    nft -f /etc/nftables.d/froxward.nft && log "nftables ruleset applied" \
        || warn "nftables apply failed — check /etc/nftables.d/froxward.nft"
    systemctl enable --now nftables
}

_setup_iptables() {
    IPT="iptables"

    # Safety: save current rules and schedule restore in 5 min
    # If setup completes successfully, we cancel the restore job
    iptables-save > /tmp/froxward_iptables_backup.rules 2>/dev/null || true
    RESTORE_JOB=""
    if command -v at &>/dev/null; then
        RESTORE_JOB=$(echo "iptables-restore < /tmp/froxward_iptables_backup.rules" \
            | at now + 5 minutes 2>&1 | grep -oP 'job \K\d+' || true)
        log "Safety restore scheduled (at job $RESTORE_JOB) — will cancel on success"
    else
        warn "at(1) not found — no safety restore available. Proceed with care."
    fi

    $IPT -P INPUT ACCEPT   # Temporarily allow all during setup
    $IPT -P FORWARD ACCEPT
    $IPT -F; $IPT -X; $IPT -Z
    $IPT -P FORWARD DROP
    $IPT -P OUTPUT ACCEPT

    $IPT -A INPUT -i lo -j ACCEPT
    $IPT -A OUTPUT -o lo -j ACCEPT
    $IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT -A INPUT -m conntrack --ctstate INVALID -j DROP

    # SYN flood
    $IPT -A INPUT -p tcp --syn -m limit --limit 25/s --limit-burst 50 -j ACCEPT
    $IPT -A INPUT -p tcp --syn -j DROP

    # ICMP rate limit
    $IPT -A INPUT -p icmp --icmp-type echo-request -m limit --limit 10/s -j ACCEPT
    $IPT -A INPUT -p icmp --icmp-type echo-request -j DROP

    # SSH brute force
    $IPT -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m recent --set --name SSH_TRACK
    $IPT -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
        -m recent --update --seconds 60 --hitcount 5 --name SSH_TRACK -j DROP
    $IPT -A INPUT -p tcp --dport 22 -j ACCEPT

    # HTTP/HTTPS
    $IPT -A INPUT -p tcp --dport "$APP_PORT" -m conntrack --ctstate NEW \
        -m limit --limit 150/min --limit-burst 250 -j ACCEPT
    $IPT -A INPUT -p tcp --dport "$APP_SSL_PORT" -m conntrack --ctstate NEW \
        -m limit --limit 150/min --limit-burst 250 -j ACCEPT
    $IPT -A INPUT -p tcp -m multiport --dports "$APP_PORT","$APP_SSL_PORT" -j ACCEPT

    # UDP reflection
    $IPT -A INPUT -p udp -m multiport --dports 19,69,111,123,137,161,389,1900,11211 -j DROP

    # Fragmented
    $IPT -A INPUT -f -j DROP

    # Wazuh
    $IPT -A INPUT -p tcp -m multiport --dports 1514,1515,55000 -j ACCEPT

    # SOAR ban chain
    $IPT -N FROXWARD_BANNED 2>/dev/null || $IPT -F FROXWARD_BANNED
    $IPT -I INPUT 1 -j FROXWARD_BANNED

    # Log + drop
    $IPT -A INPUT -m limit --limit 5/min -j LOG --log-prefix "[FROXWARD-DROP] " --log-level 7
    $IPT -A INPUT -j DROP

    # NOW set INPUT to DROP (all ACCEPT rules are already in place)
    $IPT -P INPUT DROP

    # Persist rules
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent -q
        iptables-save > /etc/iptables/rules.v4
    else
        $PKG_INSTALL iptables-services -q
        service iptables save 2>/dev/null || true
        systemctl enable iptables 2>/dev/null || true
    fi

    # Cancel safety restore — setup completed successfully
    if [[ -n "${RESTORE_JOB:-}" ]]; then
        atrm "$RESTORE_JOB" 2>/dev/null || true
    fi
    rm -f /tmp/froxward_iptables_backup.rules

    log "iptables DDoS ruleset applied"
}

# ─── FAIL2BAN ─────────────────────────────────────────────────────────────────
configure_fail2ban() {
    section "Fail2ban"

    cat > /etc/fail2ban/jail.local <<'F2B'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
banaction = iptables-multiport
backend = auto
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled  = true
port     = ssh
logpath  = /var/log/auth.log
maxretry = 3
bantime  = 24h

[nginx-http-auth]
enabled  = true
port     = http,https
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log

[nginx-botsearch]
enabled  = true
port     = http,https
filter   = nginx-botsearch
logpath  = /var/log/nginx/access.log
maxretry = 2
bantime  = 24h

[nginx-req-limit]
enabled  = true
port     = http,https
filter   = nginx-req-limit
logpath  = /var/log/nginx/error.log
maxretry = 10
bantime  = 30m

[modsec]
enabled  = true
port     = http,https
filter   = modsec
logpath  = /var/log/modsec_audit.log
maxretry = 3
bantime  = 6h

[wazuh-high-alerts]
enabled  = true
port     = all
filter   = wazuh-high-alerts
logpath  = /var/ossec/logs/alerts/alerts.log
maxretry = 1
bantime  = 2h
F2B

    cat > /etc/fail2ban/filter.d/modsec.conf <<'EOF'
[Definition]
failregex = ^\S+ \S+ \[.*\] \[client <HOST>\] ModSecurity:.*
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/nginx-req-limit.conf <<'EOF'
[Definition]
failregex = limiting requests, excess:.* by zone .*, client: <HOST>
ignoreregex =
EOF

    cat > /etc/fail2ban/filter.d/wazuh-high-alerts.conf <<'EOF'
[Definition]
failregex = .*"srcip":"<HOST>".*"level":(?:1[0-9]|[7-9]).*
ignoreregex = .*"srcip":"127\.0\.0\.1".*
EOF

    systemctl enable --now fail2ban
    systemctl restart fail2ban
    log "Fail2ban configured"
}

# ─── SOAR-LITE DAEMON ─────────────────────────────────────────────────────────
install_soar() {
    section "SOAR-lite Automated Response Daemon"

    # Export vars needed in the script
    local fw="$FIREWALL"
    local soar_log="$SOAR_LOG"

    cat > "$SOAR_SCRIPT" <<SOAREOF
#!/usr/bin/env bash
# =============================================================================
#  Froxward SOAR-lite — Real-time automated response
#  Reads Wazuh alerts.json stream → classifies → responds
# =============================================================================
set -uo pipefail

ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"
SOAR_LOG="$soar_log"
PROCESSED_IDS="/tmp/froxward_processed_ids.db"
BANNED_IPS="/tmp/froxward_banned.db"
FIREWALL="$fw"

touch "\$SOAR_LOG" "\$PROCESSED_IDS" "\$BANNED_IPS"

log_soar() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [\$1] \$2" >> "\$SOAR_LOG"
}

# ── IP ban function ───────────────────────────────────────────────────────────
ban_ip() {
    local ip="\$1" reason="\$2" duration="\${3:-3600}"

    # Sanity checks
    [[ -z "\$ip" || "\$ip" == "null" ]] && return
    [[ "\$ip" =~ ^127\. || "\$ip" == "::1" || "\$ip" == "0.0.0.0" ]] && return

    # Dedup
    grep -qxF "\$ip" "\$BANNED_IPS" && return
    echo "\$ip" >> "\$BANNED_IPS"

    local ok=0
    if [[ "\$FIREWALL" == "nftables" ]]; then
        nft add element inet froxward banned_ips \
            "{ \$ip timeout \${duration}s }" 2>/dev/null && ok=1
    else
        iptables -I FROXWARD_BANNED -s "\$ip" -j DROP 2>/dev/null && ok=1
        # Schedule unban
        ( sleep "\$duration"
          iptables -D FROXWARD_BANNED -s "\$ip" -j DROP 2>/dev/null
          sed -i "/^\${ip}$/d" "\$BANNED_IPS"
          log_soar "UNBAN" "\$ip (\$reason expired)"
        ) &
    fi

    # Fail2ban as backup
    fail2ban-client set sshd banip "\$ip" 2>/dev/null || true

    if (( ok )); then
        log_soar "BAN" "\$ip | \$reason | \${duration}s"
    else
        log_soar "BAN_FAILED" "\$ip | \$reason | firewall error"
    fi
}

rate_limit_ip() {
    local ip="\$1" reason="\$2"
    [[ -z "\$ip" || "\$ip" == "null" ]] && return
    if [[ "\$FIREWALL" == "nftables" ]]; then
        nft add element inet froxward ssh_flood "{ \$ip }" 2>/dev/null || true
    fi
    log_soar "RATE_LIMIT" "\$ip | \$reason"
}

# ── Alert classification + response ──────────────────────────────────────────
respond() {
    local alert="\$1"
    local level srcip ruleid desc

    level=\$(echo "\$alert" | jq -r '.rule.level // 0' 2>/dev/null)
    srcip=\$(echo "\$alert" | jq -r '.data.srcip // .agent.ip // empty' 2>/dev/null)
    ruleid=\$(echo "\$alert" | jq -r '.rule.id // ""' 2>/dev/null)
    desc=\$(echo "\$alert"  | jq -r '.rule.description // ""' 2>/dev/null | tr '[:upper:]' '[:lower:]')

    [[ -z "\$srcip" || "\$srcip" == "null" ]] && return

    # ── Level-based thresholds ─────────────────────────────────────────────

    if (( level >= 13 )); then
        ban_ip "\$srcip" "critical_l\${level}" 86400   # 24h
        return
    fi

    if (( level >= 10 )); then
        ban_ip "\$srcip" "high_l\${level}" 7200         # 2h
        return
    fi

    if (( level >= 7 )); then
        # Pattern-based response on description
        if [[ "\$desc" == *"sql injection"* || "\$desc" == *"sqli"* ]]; then
            ban_ip "\$srcip" "sqli" 3600
        elif [[ "\$desc" == *"xss"* || "\$desc" == *"cross-site"* ]]; then
            ban_ip "\$srcip" "xss" 3600
        elif [[ "\$desc" == *"brute force"* || "\$desc" == *"multiple failed"* ]]; then
            ban_ip "\$srcip" "brute_force" 3600
        elif [[ "\$desc" == *"port scan"* || "\$desc" == *"portscan"* ]]; then
            ban_ip "\$srcip" "port_scan" 7200
        elif [[ "\$desc" == *"ddos"* || "\$desc" == *"flood"* || "\$desc" == *"dos"* ]]; then
            ban_ip "\$srcip" "ddos" 7200
        elif [[ "\$desc" == *"modsecurity"* || "\$desc" == *"web attack"* ]]; then
            ban_ip "\$srcip" "waf_trigger" 1800
        elif [[ "\$desc" == *"privilege escalation"* || "\$desc" == *"privesc"* ]]; then
            ban_ip "\$srcip" "privesc" 86400
        elif [[ "\$desc" == *"malware"* || "\$desc" == *"rootkit"* || "\$desc" == *"trojan"* ]]; then
            ban_ip "\$srcip" "malware" 86400
        elif [[ "\$desc" == *"scanner"* || "\$desc" == *"nikto"* || "\$desc" == *"sqlmap"* ]]; then
            ban_ip "\$srcip" "scanner" 3600
        elif [[ "\$desc" == *"log4"* || "\$desc" == *"shellshock"* || "\$desc" == *"rce"* ]]; then
            ban_ip "\$srcip" "rce_attempt" 86400
        elif [[ "\$desc" == *"ssrf"* || "\$desc" == *"xxe"* || "\$desc" == *"lfi"* ]]; then
            ban_ip "\$srcip" "injection_\${ruleid}" 3600
        else
            rate_limit_ip "\$srcip" "medium_l\${level}"
        fi
        return
    fi

    # ── Rule ID based response (level < 7) ────────────────────────────────
    case "\$ruleid" in
        5710|5711|5712|5716|5720|5760) ban_ip "\$srcip" "auth_fail_r\${ruleid}" 1800 ;;
        510|511|512|513)               ban_ip "\$srcip" "rootcheck_r\${ruleid}" 3600 ;;
        31[0-9][0-9][0-9])            ban_ip "\$srcip" "web_r\${ruleid}" 1800 ;;
        40[0-9][0-9][0-9])            ban_ip "\$srcip" "app_r\${ruleid}" 1800 ;;
    esac
}

# ── Main loop ────────────────────────────────────────────────────────────────
log_soar "START" "SOAR daemon initializing. Watching: \$ALERTS_JSON"

while [[ ! -f "\$ALERTS_JSON" ]]; do
    log_soar "WAIT" "Alerts file not found yet, retrying in 10s..."
    sleep 10
done

log_soar "START" "Alerts file found. Starting real-time watch."

tail -F "\$ALERTS_JSON" 2>/dev/null | while IFS= read -r line; do
    # Skip non-JSON
    [[ "\$line" != "{"* ]] && continue

    # Dedup by alert ID
    alert_id=\$(echo "\$line" | jq -r '.id // empty' 2>/dev/null)
    if [[ -n "\$alert_id" ]]; then
        grep -qxF "\$alert_id" "\$PROCESSED_IDS" && continue
        echo "\$alert_id" >> "\$PROCESSED_IDS"
        # Trim to last 50k entries
        if (( \$(wc -l < "\$PROCESSED_IDS") > 50000 )); then
            tail -n 25000 "\$PROCESSED_IDS" > "\$PROCESSED_IDS.tmp" \
                && mv "\$PROCESSED_IDS.tmp" "\$PROCESSED_IDS"
        fi
    fi

    respond "\$line"
done
SOAREOF

    chmod +x "$SOAR_SCRIPT"

    cat > /etc/systemd/system/froxward-soar.service <<SVCEOF
[Unit]
Description=Froxward SOAR-lite Automated Response Daemon
After=wazuh-manager.service network.target
Wants=wazuh-manager.service

[Service]
Type=simple
ExecStart=$SOAR_SCRIPT
Restart=always
RestartSec=5
StandardOutput=append:$SOAR_LOG
StandardError=append:$SOAR_LOG
User=root

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable --now froxward-soar
    log "SOAR daemon installed (service: froxward-soar)"
}

# ─── SSH HARDENING ────────────────────────────────────────────────────────────
harden_ssh() {
    section "SSH Hardening"
    SSHD="/etc/ssh/sshd_config"
    cp "$SSHD" "${SSHD}.bak.$(date +%s)"

    declare -A SSH_OPTS=(
        [PermitRootLogin]="no"
        [MaxAuthTries]="3"
        [LoginGraceTime]="30"
        [X11Forwarding]="no"
        [AllowAgentForwarding]="no"
        [AllowTcpForwarding]="no"
        [PrintMotd]="no"
        [ClientAliveInterval]="300"
        [ClientAliveCountMax]="2"
        [MaxStartups]="10:30:60"
        [MaxSessions]="3"
        [TCPKeepAlive]="no"
        [Compression]="no"
    )

    for key in "${!SSH_OPTS[@]}"; do
        val="${SSH_OPTS[$key]}"
        if grep -qE "^#?${key}\s" "$SSHD"; then
            sed -i "s|^#\?${key}.*|${key} ${val}|" "$SSHD"
        else
            echo "${key} ${val}" >> "$SSHD"
        fi
    done

    sshd -t 2>&1 | tee -a "$SETUP_LOG" && systemctl restart sshd \
        && log "SSH hardened" \
        || warn "SSH config has errors — original backed up at ${SSHD}.bak.*"
}

# ─── VALIDATION ───────────────────────────────────────────────────────────────
validate() {
    section "Validation"
    local pass=0 fail=0

    chk() {
        local name="$1" cmd="$2"
        if eval "$cmd" &>/dev/null; then
            echo -e "  ${G}OK${N}  $name"; ((pass++))
        else
            echo -e "  ${R}FAIL${N} $name"; ((fail++))
        fi
    }

    chk "Wazuh manager"          "systemctl is-active wazuh-manager"
    chk "Fail2ban"               "systemctl is-active fail2ban"
    chk "SOAR daemon"            "systemctl is-active froxward-soar"
    chk "ModSec config"          "test -f $MODSEC_DIR/modsecurity.conf"
    chk "OWASP CRS rules"        "ls $MODSEC_DIR/crs/rules/*.conf"
    chk "Custom modsec rules"    "test -f $MODSEC_DIR/custom_rules.conf"
    chk "Froxward wazuh rules"   "ls /var/ossec/etc/rules/*.xml"
    chk "Sysctl syncookies"      "sysctl net.ipv4.tcp_syncookies | grep -q 1"
    chk "Sysctl rp_filter"       "sysctl net.ipv4.conf.all.rp_filter | grep -q 1"

    if [[ "$WEB_SERVER" == "nginx" ]]; then
        chk "nginx config valid" "nginx -t"
        chk "nginx running"      "systemctl is-active nginx"
    fi

    echo ""
    echo -e "  ${B}${G}$pass passed${N} / ${R}$fail failed${N}"
    (( fail > 0 )) && warn "Check $SETUP_LOG for details"
}

# ─── USAGE ────────────────────────────────────────────────────────────────
usage() {
    echo "Usage: sudo bash $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help"
    echo "  --skip-wazuh     Skip Wazuh installation"
    echo "  --skip-modsec    Skip ModSecurity installation"
    echo "  --skip-ssh       Skip SSH hardening"
    echo ""
    echo "Environment variables:"
    echo "  APP_PORT=8080           Application port (autodetected if unset)"
    echo "  APP_SSL_PORT=443        SSL port"
    echo "  WAZUH_VERSION=4.9.2     Wazuh version"
    echo "  CRS_VERSION=4.7.0       OWASP CRS version"
    echo "  FROXWARD_PORT_SET=1     Force port detection skip"
    exit 0
}

cleanup_on_error() {
    local exit_code=$?
    if (( exit_code != 0 )); then
        echo ""
        echo -e "${R}${B}Setup failed (exit code: $exit_code)${N}"
        echo -e "${Y}Check log: $SETUP_LOG${N}"
        echo -e "${Y}Partial installation may need manual cleanup.${N}"
    fi
}

# ─── MAIN ─────────────────────────────────────────────────────────────────
main() {
    # Parse flags
    local skip_wazuh=0 skip_modsec=0 skip_ssh=0
    for arg in "$@"; do
        case "$arg" in
            -h|--help)      usage ;;
            --skip-wazuh)   skip_wazuh=1 ;;
            --skip-modsec)  skip_modsec=1 ;;
            --skip-ssh)     skip_ssh=1 ;;
            *) echo -e "${Y}[!] Unknown option: $arg${N}" ;;
        esac
    done

    trap cleanup_on_error EXIT

    clear
    echo -e "${C}${B}"
    cat <<'BANNER'
    ███████╗██████╗  ██████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ██████╗
    ██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
    █████╗  ██████╔╝██║   ██║ ╚███╔╝ ██║ █╗ ██║███████║██████╔╝██║  ██║
    ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ ██║███╗██║██╔══██║██╔══██╗██║  ██║
    ██║     ██║  ██║╚██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║  ██║██████╔╝
    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
                    ⚙  SECURITY STACK · setup.sh
BANNER
    echo -e "${N}"

    require_root
    mkdir -p "$(dirname "$SETUP_LOG")"
    echo "=== Froxward setup started: $(date) ===" > "$SETUP_LOG"

    detect_os
    install_deps
    detect_app_port
    detect_webserver
    install_nginx
    (( skip_modsec )) || install_modsecurity
    (( skip_wazuh ))  || install_wazuh
    configure_ddos_l3l4
    configure_fail2ban
    (( skip_wazuh ))  || install_soar
    (( skip_ssh ))    || harden_ssh
    validate

    trap - EXIT  # Clear error trap on success

    echo ""
    echo -e "${G}${B}Setup complete.${N}"
    echo -e "  SOAR log  : $SOAR_LOG"
    echo -e "  Setup log : $SETUP_LOG"
    (( skip_wazuh ))  || echo -e "  Wazuh rules: /var/ossec/etc/rules/"
    (( skip_modsec )) || echo -e "  ModSecurity: $MODSEC_DIR/"
    echo ""
    echo -e "${Y}Run: bash checksec.sh  — to audit the full stack${N}"
}

main "$@"

#!/usr/bin/env bash
# lib.sh — shared functions for waf modules
# Sourced by install-waf.sh and all modules

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

LOG="${LOG:-/tmp/wazuh-waf-install.log}"

print()  { echo -e "${BOLD}${CYAN}[*]${RESET} $*"; }
ok()     { echo -e "${BOLD}${GREEN}[+]${RESET} $*"; }
warn()   { echo -e "${BOLD}${YELLOW}[!]${RESET} $*"; }
die()    { echo -e "${BOLD}${RED}[x]${RESET} $*"; exit 1; }
section(){ echo -e "\n${BOLD}${CYAN}--- $* ---${RESET}"; }

log_cmd() { "$@" >> "$LOG" 2>&1; }

detect_os() {
    if [[ -f /etc/debian_version ]]; then
        echo "debian"
    elif [[ -f /etc/redhat-release ]]; then
        echo "rhel"
    else
        echo "unknown"
    fi
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

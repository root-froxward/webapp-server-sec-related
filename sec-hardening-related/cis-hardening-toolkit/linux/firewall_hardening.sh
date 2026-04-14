#!/bin/bash

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

BACKUP_DIR="/var/backup/cis-hardening/firewall"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/cis-hardening-firewall-${TIMESTAMP}.log"

mkdir -p "$BACKUP_DIR"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting firewall hardening based on CIS Benchmark 3.5.x"

if command -v ufw &>/dev/null; then
    log "UFW detected, proceeding with UFW configuration"

    ufw status verbose > "${BACKUP_DIR}/ufw_status.${TIMESTAMP}.bak"
    log "BACKUP: current UFW status saved"

    ufw --force reset
    log "UFW rules reset"

    ufw default deny incoming
    ufw default deny outgoing
    ufw default deny routed
    log "SET: default policies to deny all"

    ufw allow out 53/udp
    ufw allow out 53/tcp
    log "ALLOW OUT: DNS (53/tcp, 53/udp)"

    ufw allow out 80/tcp
    ufw allow out 443/tcp
    log "ALLOW OUT: HTTP/HTTPS (80/tcp, 443/tcp)"

    ufw allow out 123/udp
    log "ALLOW OUT: NTP (123/udp)"

    ufw allow in 22/tcp
    log "ALLOW IN: SSH (22/tcp)"

    ufw logging medium
    log "SET: UFW logging to medium"

    ufw --force enable
    log "UFW enabled"

elif command -v iptables &>/dev/null; then
    log "UFW not found, falling back to iptables"

    iptables-save > "${BACKUP_DIR}/iptables.${TIMESTAMP}.bak"
    ip6tables-save > "${BACKUP_DIR}/ip6tables.${TIMESTAMP}.bak"
    log "BACKUP: current iptables rules saved"

    iptables -F
    iptables -X
    iptables -Z
    ip6tables -F
    ip6tables -X
    ip6tables -Z
    log "Flushed all existing rules"

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    ip6tables -P INPUT DROP
    ip6tables -P FORWARD DROP
    ip6tables -P OUTPUT DROP
    log "SET: default policies to DROP"

    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    iptables -A INPUT -s 127.0.0.0/8 ! -i lo -j DROP
    log "SET: loopback rules"

    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT
    log "SET: stateful connection tracking"

    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
    log "ALLOW IN: SSH (22/tcp)"

    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
    log "ALLOW OUT: DNS (53)"

    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    log "ALLOW OUT: HTTP/HTTPS (80, 443)"

    iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
    log "ALLOW OUT: NTP (123)"

    iptables -A INPUT -j LOG --log-prefix "IPT_DROPPED_IN: " --log-level 4
    iptables -A OUTPUT -j LOG --log-prefix "IPT_DROPPED_OUT: " --log-level 4
    iptables -A FORWARD -j LOG --log-prefix "IPT_DROPPED_FWD: " --log-level 4
    log "SET: logging for dropped packets"

    if command -v netfilter-persistent &>/dev/null; then
        netfilter-persistent save
        log "Rules saved via netfilter-persistent"
    else
        log "WARNING: netfilter-persistent not found, rules will not survive reboot"
    fi
else
    log "ERROR: Neither UFW nor iptables found"
    exit 1
fi

log "Firewall hardening complete. Log: $LOG_FILE"

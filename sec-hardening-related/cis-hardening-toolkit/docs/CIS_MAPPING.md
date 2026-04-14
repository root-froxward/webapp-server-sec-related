# CIS Benchmark Control Mapping

This document maps each script and setting to its corresponding CIS Benchmark control.

Reference: CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0, CIS Microsoft Windows Server 2022 Benchmark v3.0.0

---

## Linux — SSH Hardening (CIS 5.2.x)

| Setting | Value | CIS Control |
|---|---|---|
| Protocol | 2 | 5.2.4 |
| LogLevel | VERBOSE | 5.2.5 |
| X11Forwarding | no | 5.2.6 |
| MaxAuthTries | 4 | 5.2.7 |
| IgnoreRhosts | yes | 5.2.8 |
| HostbasedAuthentication | no | 5.2.9 |
| PermitRootLogin | no | 5.2.10 |
| PermitEmptyPasswords | no | 5.2.11 |
| PermitUserEnvironment | no | 5.2.12 |
| Ciphers | Strong ciphers only | 5.2.13 |
| MACs | Strong MACs only | 5.2.14 |
| KexAlgorithms | Strong KEX only | 5.2.15 |
| ClientAliveInterval | 300 | 5.2.16 |
| ClientAliveCountMax | 3 | 5.2.16 |
| Banner | /etc/issue.net | 5.2.17 |
| MaxStartups | 10:30:60 | 5.2.21 |
| MaxSessions | 10 | 5.2.22 |

## Linux — Firewall (CIS 3.5.x)

| Setting | Value | CIS Control |
|---|---|---|
| UFW/iptables enabled | yes | 3.5.1.1 |
| Default deny incoming | yes | 3.5.1.3 |
| Default deny outgoing | yes | 3.5.1.3 |
| Default deny routed | yes | 3.5.1.3 |
| Logging | medium | 3.5.1.7 |
| Loopback rules | configured | 3.5.2.1 |

## Linux — User and Password Policies (CIS 5.4.x)

| Setting | Value | CIS Control |
|---|---|---|
| PASS_MAX_DAYS | 365 | 5.4.1.1 |
| PASS_MIN_DAYS | 1 | 5.4.1.2 |
| PASS_WARN_AGE | 7 | 5.4.1.3 |
| INACTIVE | 30 | 5.4.1.4 |
| ENCRYPT_METHOD | SHA512 | 5.4.4 |
| minlen (pwquality) | 14 | 5.4.1 |
| dcredit/ucredit/ocredit/lcredit | -1 | 5.4.1 |
| pam_faillock deny | 5 | 5.4.2 |
| pam_faillock unlock_time | 900 | 5.4.2 |
| System accounts locked | nologin shell | 5.4.2 |
| UID 0 check | root only | 6.2.2 |

## Linux — Audit and Logging (CIS 4.1.x)

| Rule | Key | CIS Control |
|---|---|---|
| Time change monitoring | time-change | 4.1.3 |
| User/group file monitoring | identity | 4.1.4 |
| Network config monitoring | system-locale | 4.1.5 |
| MAC policy monitoring | MAC-policy | 4.1.6 |
| Login/logout monitoring | logins | 4.1.7 |
| Session monitoring | session | 4.1.8 |
| Permission modifications | perm_mod | 4.1.9 |
| File deletion | delete | 4.1.14 |
| Sudo usage | scope/actions | 4.1.15 |
| Mount operations | mounts | 4.1.13 |
| Kernel modules | modules | 4.1.17 |
| Immutable audit config | -e 2 | 4.1.18 |

## Windows — Firewall (CIS 9.x)

| Setting | Value | CIS Control |
|---|---|---|
| Domain profile enabled | True | 9.1.1 |
| Domain inbound default | Block | 9.1.2 |
| Domain logging | Enabled | 9.1.5 |
| Private profile enabled | True | 9.2.1 |
| Private inbound default | Block | 9.2.2 |
| Private logging | Enabled | 9.2.5 |
| Public profile enabled | True | 9.3.1 |
| Public inbound default | Block | 9.3.2 |
| Public outbound default | Block | 9.3.3 |
| Public logging | Enabled | 9.3.5 |

## Windows — Account Policies (CIS 1.1.x, 1.2.x)

| Setting | Value | CIS Control |
|---|---|---|
| Password history | 24 | 1.1.1 |
| Minimum password length | 14 | 1.1.2 |
| Maximum password age | 365 | 1.1.3 |
| Minimum password age | 1 | 1.1.4 |
| Password complexity | Enabled | 1.1.5 |
| Reversible encryption | Disabled | 1.1.6 |
| Account lockout threshold | 5 | 1.2.1 |
| Lockout duration | 15 min | 1.2.2 |
| Reset lockout counter | 15 min | 1.2.3 |
| Guest account | Disabled | 1.1.7 |

## Windows — Audit Policy (CIS 17.x)

| Subcategory | Success | Failure | CIS Control |
|---|---|---|---|
| Credential Validation | Yes | Yes | 17.1.1 |
| Application Group Management | Yes | Yes | 17.2.1 |
| Security Group Management | Yes | Yes | 17.2.5 |
| User Account Management | Yes | Yes | 17.2.6 |
| Process Creation | Yes | No | 17.3.1 |
| Account Lockout | Yes | Yes | 17.5.1 |
| Logon | Yes | Yes | 17.5.3 |
| Logoff | Yes | No | 17.5.2 |
| Special Logon | Yes | No | 17.5.6 |
| Removable Storage | Yes | Yes | 17.6.4 |
| Audit Policy Change | Yes | Yes | 17.7.1 |
| Sensitive Privilege Use | Yes | Yes | 17.8.1 |
| System Integrity | Yes | Yes | 17.9.5 |
| Command line auditing | Enabled | — | 17.3.1 |
| PowerShell script block logging | Enabled | — | Custom |
| PowerShell module logging | Enabled | — | Custom |

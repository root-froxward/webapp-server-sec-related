# (c) 2024-2026 thelema-froxward

Licensed under the MIT License
Wazuh Custom Detection Rules
===

A comprehensive collection of Wazuh XML detection rules organized into two categories MITRE ATT&CK & Web Attacks


## &#x20;Installation

1. Copy rule files to `/var/ossec/etc/rules/`
2. Add `<include>filename.xml</include>` to `/var/ossec/etc/ossec.conf` inside `<ruleset>`
3. Restart Wazuh: `systemctl restart wazuh-manager`

## &#x20;Rule ID Ranges

|Category|Rule ID Range|
|-|-|
|Web Attacks|100100 – 100999|
|MITRE ATT\&CK|101000 – 101999|

## &#x20;Notes

* Test rules in a staging environment before deploying to production.
* Tune `frequency` and `timeframe` thresholds to match your traffic patterns.
* Rules reference standard Wazuh decoders (web-accesslog, syslog, json, etc.)


# Wazuh DDoS & Web Attack Protection Suite
#  (c) 2024-2026 thelema-froxward
# Licensed under the MIT License
Автоматическое обнаружение и блокировка сетевых атак и атак на веб-приложения через Wazuh. Кастомные правила детектят угрозу, active response скрипт тут же блокирует источник на нескольких уровнях — от ipset/iptables в ядре до nginx, fail2ban и опционально Cloudflare.

## Что делает

Добавляет в Wazuh два набора правил и скрипт автоматической реакции, который обрабатывает алерты в реальном времени.

Что детектится:

- L3/L4 DDoS: SYN flood, UDP flood, ICMP flood, RST/ACK flood, фрагментация IP
- Amplification-атаки: DNS, NTP, SSDP, Memcached
- L7 DDoS: HTTP flood, Slowloris, slow POST, бот-флуд, распределённые атаки
- SQL-инъекции (union, boolean, time-based, error-based, запись файлов / RCE через SQL)
- XSS, LFI, RFI, SSRF, XXE, SSTI, инъекция команд, десериализация
- Известные CVE: Log4Shell, Spring4Shell, Shellshock
- Доступ к вебшеллам и попытки загрузки
- Брутфорс, обход аутентификации, JWT algorithm none
- Обнаружение сканеров (sqlmap, nikto, nmap, gobuster и т.д.)
- IDOR-перебор, open redirect, пробы чувствительных файлов
- Мультивекторная корреляция (DDoS + эксплуатация как дымовая завеса)

При срабатывании алерта скрипт применяет комбинацию мер в зависимости от типа атаки:

- Блокировка через ipset (на уровне ядра, с настраиваемым таймаутом)
- Rate limiting через iptables (hashlimit на источник)
- nginx deny
- WAF deny-правила
- Интеграция с fail2ban
- Блокировка на Cloudflare edge (опционально, через API)
- Создание файла инцидента для критических угроз (RCE, вебшелл, Log4Shell)

Все правила привязаны к техникам MITRE ATT&CK.

## Состав

| Файл | Назначение |
|------|------------|
| `install.sh` | Интерактивный инсталлер. Ставит зависимости, настраивает ipset/iptables, hardening ядра, rate limiting nginx, fail2ban, деплоит правила Wazuh и патчит ossec.conf. |
| `0100-ddos-detection.xml` | Правила Wazuh для обнаружения DDoS (ID 100100–100132) |
| `0110-web-vuln-detection.xml` | Правила Wazuh для обнаружения веб-атак (ID 110100–110301) |
| `auto-mitigate.py` | Скрипт active response. Читает алерт из stdin, определяет тип атаки, применяет соответствующие контрмеры. |

## Требования

- Wazuh manager (проверено на 4.x)
- Linux (Debian/Ubuntu или RHEL/CentOS)
- nginx или Apache (для детекта веб-атак и L7-митигации)
- Root-доступ
- Python 3 с модулем `requests` (для Cloudflare)

## Установка

```
git clone <repo-url>
sudo bash install.sh
```

Инсталлер спросит IP-адреса для вайтлиста и опционально данные Cloudflare. Всё остальное автоматически.

## Конфигурация

После установки конфиг лежит в `/var/ossec/etc/auto-mitigate.conf`:

```
CF_ENABLED=false
CF_API_TOKEN=
CF_ZONE_ID=
WHITELIST=10.0.0.1,192.168.1.0/24
```

Длительность блокировок задаётся в `auto-mitigate.py` в словаре `BLOCK_DURATIONS`. По умолчанию перманентный бан (timeout 0) стоит для RCE, вебшеллов и Log4Shell.

## Логи и мониторинг

Лог митигации:
```
tail -f /var/log/wazuh/auto-mitigate.log
```

Алерты в реальном времени:
```
tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool
```

Текущие заблокированные IP:
```
ipset list wazuh_blocked
ipset list wazuh_ddos
```

Критические инциденты (требуют ручного разбора):
```
ls /var/ossec/logs/critical-incidents/
```

## Разблокировка IP

Скрипт поддерживает действие `delete`, которое Wazuh вызывает автоматически по истечении таймаута. Для ручной разблокировки:

```
echo '{"data":{"srcip":"1.2.3.4"}}' | /var/ossec/active-response/bin/auto-mitigate.py delete
```

Это удалит IP из ipset, iptables, nginx deny, WAF deny и fail2ban.

## Замечания

- Обязательно добавьте свои управляющие IP в вайтлист перед деплоем на прод. Заблокировать себе доступ к удалённому серверу — удовольствие сомнительное.
- Инсталлер применяет sysctl-hardening (syncookies, тюнинг conntrack и т.д.), настройки переживают ребут.
- Блокировка Cloudflare использует API access rules. При большом количестве блокировок имеет смысл перейти на IP Lists.
- Правила рассчитаны на стандартный формат логов nginx/Apache. Если у вас кастомный формат, возможно, потребуется подправить декодеры.

## Лицензия

MIT

# WAF Extension Module

Расширение для [wazuh-protection-suite](../README.ru.md). Добавляет ModSecurity с OWASP Core Rule Set, CrowdSec для коллективной репутации IP, security headers, rate limiting и GeoIP-блокировку по странам. Интегрируется с существующим пайплайном active response — заблокированные IP проходят через ту же цепочку ipset/iptables/nginx/fail2ban/Cloudflare.

## Что добавляет

**ModSecurity + OWASP CRS** — полноценный WAF с инспекцией запросов, anomaly scoring и блокировкой. Поддерживает nginx (libmodsecurity3) и Apache (mod_security2). CRS предварительно настроен на paranoia level 2 с порогом аномалий 10 — баланс между детектом и ложными срабатываниями на свежей установке.

**CrowdSec** — движок репутации IP на основе сообщества. Обменивается сигналами об угрозах с другими пользователями CrowdSec и получает блоклисты в ответ. Ставит подходящий bouncer (nginx или firewall) и настраивает сбор логов веб-сервера и ModSecurity.

**Security headers** — HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cross-Origin политики. Применяются через include-файлы, можно настроить отдельно для каждого виртуального хоста.

**Rate limiting** — зонный rate limiting для nginx (general, login, API, upload, static) и mod_evasive для Apache. Более гранулярно, чем базовый rate limiting из первого инсталлера.

**GeoIP-блокировка** — блокировка на уровне стран через базы MaxMind или DB-IP. Два режима: deny (блокировать перечисленные страны) и allow (разрешить только перечисленные). Автообновление базы раз в неделю через cron.

**Правила Wazuh** — кастомные правила (0120-modsec-waf.xml), которые детектят блокировки ModSecurity, CRS anomaly, баны CrowdSec, срабатывания rate limit и корреляцию WAF + репутация. Всё завязано на существующий auto-mitigate.py.

## Требования

Сначала должен быть установлен базовый wazuh-protection-suite (`install.sh`). Этот модуль его расширяет.

## Установка

Полная установка (интерактивно):
```
cd waf/
sudo bash install-waf.sh
```

Полная установка (без вопросов):
```
sudo bash install-waf.sh --all
```

Отдельный модуль:
```
sudo bash install-waf.sh --module modsec
sudo bash install-waf.sh --module crowdsec
sudo bash install-waf.sh --module headers
sudo bash install-waf.sh --module ratelimit
sudo bash install-waf.sh --module geoip --geoip-mode deny
```

## Структура

```
waf/
├── install-waf.sh              # главный инсталлер
├── lib.sh                      # общие функции
├── modules/
│   ├── modsec-nginx.sh         # ModSecurity v3 для nginx
│   ├── modsec-apache.sh        # mod_security2 для Apache
│   ├── owasp-crs.sh            # скачивание и настройка OWASP CRS
│   ├── crowdsec.sh             # CrowdSec + bouncer
│   ├── security-headers.sh     # HTTP security headers
│   ├── rate-limit.sh           # rate limiting
│   └── geoip.sh                # GeoIP блокировка по странам
├── conf/
│   ├── modsecurity.conf        # конфиг движка ModSecurity
│   ├── crs-setup.conf          # тюнинг CRS (paranoia, пороги)
│   ├── crowdsec-whitelist.yaml # вайтлист IP для CrowdSec
│   └── geoip-countries.conf    # коды стран для блокировки
└── wazuh-rules/
    └── 0120-modsec-waf.xml     # правила Wazuh для WAF-событий
```

## Настройка

**Тюнинг ModSecurity** — редактировать `conf/modsecurity.conf` и `conf/crs-setup.conf`. Основные ручки: paranoia level (1-4) и порог anomaly score. Начинайте с PL2/threshold 10, мониторьте `/var/log/modsec_audit.log` на ложные срабатывания, потом ужесточайте.

**CrowdSec** — вайтлист в `conf/crowdsec-whitelist.yaml`. Решения и метрики доступны через `cscli decisions list` и `cscli metrics`.

**Security headers** — CSP-заголовок по умолчанию строгий. Почти наверняка придётся подправить под ваше приложение. Редактируйте include-файл на сервере после установки.

**GeoIP** — добавьте коды стран (ISO 3166-1 alpha-2) в `conf/geoip-countries.conf`, по одному на строку. Режим задаётся через `--geoip-mode deny` или `--geoip-mode allow`.

## Проверка

ModSecurity:
```
curl -I 'http://localhost/?id=1 OR 1=1'
# Должен вернуть 403

curl -I 'http://localhost/?page=../../etc/passwd'
# Должен вернуть 403
```

Security headers:
```
curl -I https://your-domain.com
# Проверить наличие Strict-Transport-Security, X-Frame-Options и т.д.
```

CrowdSec:
```
cscli metrics
cscli alerts list
cscli decisions list
```

## Замечания

- Сборка ModSecurity из исходников занимает 5-10 минут. На Debian 12+ / Ubuntu 22.04+ используется готовый пакет.
- Ложные срабатывания CRS на свежей установке — это нормально. Мониторьте audit log, добавляйте исключения в `crs-setup.conf`, потом снижайте порог.
- Модуль GeoIP использует бесплатную базу DB-IP Lite (без регистрации), если не настроены данные MaxMind.
- Все WAF-события уходят в тот же auto-mitigate.py из базового пакета. Отдельной логики блокировки нет.

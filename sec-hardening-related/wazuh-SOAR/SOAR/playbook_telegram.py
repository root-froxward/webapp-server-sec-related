#!/usr/bin/env python3
"""
playbooks/telegram.py — Telegram alert notifications
Sends rich formatted messages with alert context
"""

import logging
from datetime import datetime, timezone

import aiohttp

log = logging.getLogger("soar.telegram")

# Severity emoji map by Wazuh level
LEVEL_EMOJI = {
    range(0, 4):   "⚪",   # low
    range(4, 7):   "🟡",   # medium
    range(7, 10):  "🟠",   # high
    range(10, 16): "🔴",   # critical
}

CATEGORY_EMOJI = {
    "web_attack":   "🌐",
    "mitre_attack": "🎯",
    "generic":      "🔔",
}

MITRE_TACTIC_NAMES = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def _level_emoji(level: int) -> str:
    for r, emoji in LEVEL_EMOJI.items():
        if level in r:
            return emoji
    return "🔔"


def _format_message(alert: dict, category: str, src_ip: str | None) -> str:
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "?")
    level = int(rule.get("level", 0))
    desc = rule.get("description", "N/A")
    agent = alert.get("agent", {}).get("name", "unknown")
    ts = alert.get("timestamp", datetime.now(timezone.utc).isoformat())

    sev_emoji = _level_emoji(level)
    cat_emoji = CATEGORY_EMOJI.get(category, "🔔")

    # Extract MITRE info if present
    mitre_lines = ""
    mitre = rule.get("mitre", {})
    if mitre:
        tactic_ids = mitre.get("tactic", [])
        technique_ids = mitre.get("id", [])
        tactics = [MITRE_TACTIC_NAMES.get(t, t) for t in tactic_ids]
        if tactics:
            mitre_lines += f"\n🎯 *Tactic:* `{', '.join(tactics)}`"
        if technique_ids:
            mitre_lines += f"\n🔗 *Technique:* `{', '.join(technique_ids)}`"

    # Extra data fields
    data = alert.get("data", {})
    url = data.get("url", "") or data.get("request_uri", "")
    method = data.get("method", "") or data.get("http_method", "")
    user_agent = data.get("user_agent", "") or data.get("http_user_agent", "")

    extra = ""
    if url:
        extra += f"\n🔗 *URL:* `{url[:120]}`"
    if method:
        extra += f"\n📡 *Method:* `{method}`"
    if user_agent:
        extra += f"\n🕵️ *UA:* `{user_agent[:80]}`"

    ip_line = f"\n🌍 *Source IP:* `{src_ip}`" if src_ip else ""

    msg = (
        f"{sev_emoji} {cat_emoji} *SOAR Alert*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📋 *Rule:* `{rule_id}` — {desc}\n"
        f"⚡ *Level:* `{level}`\n"
        f"🖥️ *Agent:* `{agent}`"
        f"{ip_line}"
        f"{mitre_lines}"
        f"{extra}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🕐 `{ts[:19].replace('T', ' ')} UTC`"
    )
    return msg


class TelegramPlaybook:
    API_BASE = "https://api.telegram.org"

    def __init__(self, cfg: dict):
        self._token = cfg.get("bot_token", "")
        self._chat_id = cfg.get("chat_id", "")
        self._enabled = cfg.get("enabled", False)
        self._min_level = cfg.get("min_level", 6)

        if not self._token or not self._chat_id:
            log.warning("Telegram: bot_token or chat_id not configured")
            self._enabled = False

    async def notify(self, alert: dict, category: str, src_ip: str | None) -> bool:
        if not self._enabled:
            return False

        level = int(alert.get("rule", {}).get("level", 0))
        if level < self._min_level:
            return False

        text = _format_message(alert, category, src_ip)
        url = f"{self.API_BASE}/bot{self._token}/sendMessage"
        payload = {
            "chat_id": self._chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        log.info(f"📨 Telegram alert sent (level={level})")
                        return True
                    else:
                        body = await resp.text()
                        log.error(f"Telegram API error {resp.status}: {body[:200]}")
                        return False
        except aiohttp.ClientError as e:
            log.error(f"Telegram send failed: {e}")
            return False

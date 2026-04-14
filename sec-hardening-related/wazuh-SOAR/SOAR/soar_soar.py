#!/usr/bin/env python3
"""
SOAR Engine — Wazuh API polling → Playbook dispatch
Supports: web-attacks (100100-100999), MITRE ATT&CK (101000-101999)
"""

import asyncio
import json
import logging
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from playbooks.ban import BanPlaybook
from playbooks.telegram import TelegramPlaybook
from wazuh_client import WazuhClient

# ── Logging ────────────────────────────────────────────────
LOG_DIR = Path("/var/log/soar")
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "soar.log"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger("soar")


# ── Config ─────────────────────────────────────────────────
def load_config(path: str = "/etc/soar/config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


# ── Rule ID → category ────────────────────────────────────
def classify_rule(rule_id: int) -> str:
    if 100100 <= rule_id <= 100999:
        return "web_attack"
    if 101000 <= rule_id <= 101999:
        return "mitre_attack"
    return "generic"


# ── Alert deduplication ───────────────────────────────────
class Deduplicator:
    """Prevents the same alert from firing actions multiple times within TTL"""
    def __init__(self, ttl: int = 300):
        self._seen: dict[str, float] = {}
        self._ttl = ttl

    def is_new(self, key: str) -> bool:
        now = time.time()
        # expire old entries
        self._seen = {k: v for k, v in self._seen.items() if now - v < self._ttl}
        if key in self._seen:
            return False
        self._seen[key] = now
        return True


# ── Event logger ──────────────────────────────────────────
class EventLogger:
    def __init__(self):
        self._path = LOG_DIR / "events.jsonl"

    def write(self, alert: dict, category: str, actions: list[str]):
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "rule_id": alert.get("rule", {}).get("id"),
            "rule_desc": alert.get("rule", {}).get("description"),
            "level": alert.get("rule", {}).get("level"),
            "category": category,
            "agent": alert.get("agent", {}).get("name"),
            "src_ip": alert.get("data", {}).get("srcip") or alert.get("data", {}).get("src_ip"),
            "actions_taken": actions,
        }
        with open(self._path, "a") as f:
            f.write(json.dumps(event) + "\n")


# ── SOAR Core ─────────────────────────────────────────────
class SOAREngine:
    def __init__(self, config: dict):
        self.cfg = config
        self.client = WazuhClient(config["wazuh"])
        self.dedup = Deduplicator(ttl=config.get("dedup_ttl", 300))
        self.event_log = EventLogger()

        # Init playbooks
        self.ban = BanPlaybook(config.get("ban", {}))
        self.telegram = TelegramPlaybook(config.get("telegram", {})) \
            if config.get("telegram", {}).get("enabled") else None

        self._poll_interval = config.get("poll_interval", 15)
        self._last_ts: str | None = None
        self._running = True

    async def run(self):
        log.info("=" * 60)
        log.info("  🛡️  SOAR Engine started")
        log.info(f"  Polling Wazuh every {self._poll_interval}s")
        log.info("=" * 60)

        while self._running:
            try:
                await self._poll_cycle()
            except Exception as e:
                log.error(f"Poll cycle error: {e}", exc_info=True)
            await asyncio.sleep(self._poll_interval)

    async def _poll_cycle(self):
        alerts = await self.client.fetch_alerts(since=self._last_ts)
        if not alerts:
            return

        log.debug(f"Fetched {len(alerts)} alerts")

        for alert in alerts:
            await self._process(alert)

        # Advance cursor to latest timestamp
        last = alerts[-1]
        self._last_ts = last.get("timestamp") or last.get("_source", {}).get("timestamp")

    async def _process(self, alert: dict):
        # Normalize — Wazuh API wraps in _source sometimes
        if "_source" in alert:
            alert = alert["_source"]

        rule_id_raw = alert.get("rule", {}).get("id", "0")
        try:
            rule_id = int(rule_id_raw)
        except (ValueError, TypeError):
            return

        level = int(alert.get("rule", {}).get("level", 0))
        min_level = self.cfg.get("min_alert_level", 6)
        if level < min_level:
            return

        category = classify_rule(rule_id)
        src_ip = (
            alert.get("data", {}).get("srcip")
            or alert.get("data", {}).get("src_ip")
            or alert.get("data", {}).get("attack_srcip")
        )

        # Dedup key: rule_id + src_ip + 5-min window
        dedup_key = f"{rule_id}:{src_ip}"
        if not self.dedup.is_new(dedup_key):
            return

        desc = alert.get("rule", {}).get("description", "")
        agent = alert.get("agent", {}).get("name", "unknown")
        log.warning(
            f"🚨 ALERT rule={rule_id} level={level} cat={category} "
            f"ip={src_ip} agent={agent} — {desc}"
        )

        actions_taken = []

        # ── Playbook dispatch ──────────────────────────────
        # 1. Ban IP (if we have a src_ip)
        if src_ip and self.ban.should_ban(rule_id, level, category):
            ok = await self.ban.execute(src_ip, rule_id, desc)
            if ok:
                actions_taken.append(f"ban:{src_ip}")

        # 2. Telegram notification
        if self.telegram:
            ok = await self.telegram.notify(alert, category, src_ip)
            if ok:
                actions_taken.append("telegram")

        self.event_log.write(alert, category, actions_taken)

    def stop(self):
        self._running = False
        log.info("SOAR stopping...")


# ── Entry point ───────────────────────────────────────────
async def main():
    cfg = load_config()
    engine = SOAREngine(cfg)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, engine.stop)

    await engine.run()


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""
wazuh_client.py — Wazuh REST API v4 client
Polls /security/events or /alerts endpoint with JWT auth
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import aiohttp

log = logging.getLogger("soar.wazuh")


class WazuhClient:
    """
    Async client for Wazuh Manager API v4.
    Handles: JWT auth (auto-refresh), pagination, cursor-based polling.
    """

    def __init__(self, cfg: dict):
        self._base = cfg["url"].rstrip("/")           # e.g. https://127.0.0.1:55000
        self._user = cfg["username"]
        self._password = cfg["password"]
        self._verify_ssl = cfg.get("verify_ssl", False)
        self._token: str | None = None
        self._token_expires: float = 0
        self._page_size = cfg.get("page_size", 500)
        self._lookback_minutes = cfg.get("lookback_minutes", 5)

    # ── Auth ──────────────────────────────────────────────
    async def _get_token(self, session: aiohttp.ClientSession) -> str:
        if self._token and time.time() < self._token_expires - 60:
            return self._token

        url = f"{self._base}/security/user/authenticate"
        async with session.post(
            url,
            auth=aiohttp.BasicAuth(self._user, self._password),
            ssl=self._verify_ssl,
        ) as resp:
            resp.raise_for_status()
            data = await resp.json()
            self._token = data["data"]["token"]
            # Wazuh tokens last 900s by default
            self._token_expires = time.time() + 900
            log.debug("JWT token refreshed")
            return self._token

    def _headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    # ── Fetch alerts ──────────────────────────────────────
    async def fetch_alerts(self, since: str | None = None) -> list[dict]:
        """
        Returns list of alert dicts newer than `since` timestamp.
        `since` is an ISO8601 string (from previous poll).
        Falls back to now - lookback_minutes on first run.
        """
        connector = aiohttp.TCPConnector(ssl=self._verify_ssl)
        async with aiohttp.ClientSession(connector=connector) as session:
            token = await self._get_token(session)
            headers = self._headers(token)

            if since:
                # parse and add 1ms to avoid re-fetching last event
                try:
                    dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
                    dt = dt + timedelta(milliseconds=1)
                except ValueError:
                    dt = datetime.now(timezone.utc) - timedelta(minutes=self._lookback_minutes)
            else:
                dt = datetime.now(timezone.utc) - timedelta(minutes=self._lookback_minutes)

            date_str = dt.strftime("%Y-%m-%dT%H:%M:%S")
            all_alerts: list[dict] = []
            offset = 0

            while True:
                params = {
                    "limit": self._page_size,
                    "offset": offset,
                    "sort": "+timestamp",
                    "q": f"timestamp>{date_str}",
                }

                url = f"{self._base}/alerts"
                try:
                    async with session.get(
                        url,
                        headers=headers,
                        params=params,
                        ssl=self._verify_ssl,
                        timeout=aiohttp.ClientTimeout(total=30),
                    ) as resp:
                        if resp.status == 401:
                            # token expired mid-session
                            self._token = None
                            token = await self._get_token(session)
                            headers = self._headers(token)
                            continue

                        resp.raise_for_status()
                        body = await resp.json()

                except aiohttp.ClientError as e:
                    log.error(f"Wazuh API error: {e}")
                    break

                items = body.get("data", {}).get("affected_items", [])
                total = body.get("data", {}).get("total_affected_items", 0)

                all_alerts.extend(items)
                offset += len(items)

                if offset >= total or not items:
                    break

            if all_alerts:
                log.debug(f"Fetched {len(all_alerts)} alerts since {date_str}")

            return all_alerts

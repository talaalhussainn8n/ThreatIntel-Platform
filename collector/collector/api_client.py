"""Übergibt normalisierte Schwachstellen in Paketen an die ThreatIntel-API."""

from __future__ import annotations

from typing import Any, Iterable

import requests


class ThreatIntelApi:
    def __init__(self, base_url: str, api_key: str, session: requests.Session | None = None, batch_size: int = 200):
        self._url = base_url.rstrip("/") + "/api/vulnerabilities/batch"
        self._api_key = api_key
        self._session = session or requests.Session()
        self._batch_size = batch_size

    def send(self, items: Iterable[dict[str, Any]]) -> dict[str, int]:
        totals = {"created": 0, "updated": 0, "rejected": 0}
        batch: list[dict[str, Any]] = []

        def flush() -> None:
            if not batch:
                return
            response = self._session.post(
                self._url, json=batch, headers={"X-Api-Key": self._api_key}, timeout=120
            )
            response.raise_for_status()
            result = response.json()
            for key in totals:
                totals[key] += int(result.get(key, 0))
            batch.clear()

        for item in items:
            batch.append(item)
            if len(batch) >= self._batch_size:
                flush()
        flush()
        return totals

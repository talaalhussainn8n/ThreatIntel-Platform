"""Abruf neuer Schwachstellen über die NVD CVE API 2.0 mit Seitenweise-Abruf und Ratenbegrenzung."""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
log = logging.getLogger(__name__)


class NvdClient:
    def __init__(
        self,
        api_key: str | None = None,
        session: requests.Session | None = None,
        page_size: int = 500,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._session = session or requests.Session()
        self._api_key = api_key
        self._page_size = page_size
        self._sleep = sleep
        # Ohne API-Schlüssel erlaubt die NVD 5 Anfragen pro 30 Sekunden, mit Schlüssel 50.
        self._delay = 0.6 if api_key else 6.0

    def _get(self, params: dict[str, Any]) -> dict[str, Any]:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        for attempt in range(4):
            response = self._session.get(NVD_URL, params=params, headers=headers, timeout=60)
            if response.status_code in (403, 429, 503):
                wait = self._delay * (attempt + 2)
                log.warning("NVD antwortet %s, neuer Versuch in %.0f s", response.status_code, wait)
                self._sleep(wait)
                continue
            response.raise_for_status()
            return response.json()
        raise RuntimeError("NVD nach mehreren Versuchen nicht erreichbar.")

    def published_between(self, start: datetime, end: datetime) -> Iterator[dict[str, Any]]:
        """Liefert alle Seiten der im Zeitraum veröffentlichten CVEs."""
        start_index = 0
        while True:
            payload = self._get(
                {
                    "pubStartDate": _fmt(start),
                    "pubEndDate": _fmt(end),
                    "resultsPerPage": self._page_size,
                    "startIndex": start_index,
                }
            )
            yield payload

            start_index += payload.get("resultsPerPage", 0)
            if start_index >= payload.get("totalResults", 0) or payload.get("resultsPerPage", 0) == 0:
                break
            self._sleep(self._delay)

    def recent(self, days: int) -> Iterator[dict[str, Any]]:
        end = datetime.now(timezone.utc)
        return self.published_between(end - timedelta(days=days), end)


def _fmt(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

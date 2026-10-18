"""Startpunkt: python -m collector [--days N] [--interval MINUTEN]

Umgebungsvariablen:
  THREATINTEL_URL      Adresse der API (Standard: http://localhost:5000)
  THREATINTEL_API_KEY  Gemeinsamer Schlüssel für die Einlieferung
  NVD_API_KEY          Optionaler NVD-Schlüssel für höhere Abrufraten
"""

from __future__ import annotations

import argparse
import logging
import os
import time

from .api_client import ThreatIntelApi
from .normalize import normalize_page
from .nvd import NvdClient

log = logging.getLogger("collector")


def run_once(nvd: NvdClient, api: ThreatIntelApi, days: int) -> dict[str, int]:
    def items():
        for page in nvd.recent(days):
            yield from normalize_page(page)

    totals = api.send(items())
    log.info("Neu: %(created)s, aktualisiert: %(updated)s, abgelehnt: %(rejected)s", totals)
    return totals


def main() -> None:
    parser = argparse.ArgumentParser(description="Sammelt CVEs von der NVD und liefert sie an die ThreatIntel-API.")
    parser.add_argument("--days", type=int, default=2, help="Zeitraum der Veröffentlichung in Tagen (max. 120)")
    parser.add_argument("--interval", type=int, default=0, help="Wiederholung in Minuten, 0 = einmalig")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    nvd = NvdClient(api_key=os.getenv("NVD_API_KEY"))
    api = ThreatIntelApi(
        os.getenv("THREATINTEL_URL", "http://localhost:5000"),
        os.getenv("THREATINTEL_API_KEY", "lokaler-entwicklungsschluessel"),
    )

    days = max(1, min(args.days, 120))
    while True:
        try:
            run_once(nvd, api, days)
        except Exception:  # Lauf fortsetzen, Fehler protokollieren
            log.exception("Sammellauf fehlgeschlagen")
            if args.interval <= 0:
                raise
        if args.interval <= 0:
            break
        time.sleep(args.interval * 60)


if __name__ == "__main__":
    main()

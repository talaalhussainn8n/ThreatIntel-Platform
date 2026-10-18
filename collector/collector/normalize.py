"""Übersetzt NVD-Datensätze (API 2.0) in das schlanke Eingangsformat der API."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Reihenfolge = Bevorzugung: neuere CVSS-Versionen zuerst.
_CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def _english_description(cve: dict[str, Any]) -> str:
    for entry in cve.get("descriptions", []):
        if entry.get("lang") == "en" and entry.get("value"):
            return entry["value"].strip()
    return ""


def _cvss(cve: dict[str, Any]) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in _CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # "Primary" (von der NVD selbst bewertet) bevorzugen.
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        if score is not None:
            return float(score), severity
    return None, None


def product_from_cpe(cpe: str) -> str | None:
    """cpe:2.3:a:apache:http_server:2.4.58:*:... -> 'Apache Http Server'"""
    parts = cpe.split(":")
    if len(parts) < 5 or parts[0] != "cpe":
        return None
    vendor, product = parts[3], parts[4]
    if product in ("", "*", "-"):
        return None

    def pretty(value: str) -> str:
        return " ".join(word.capitalize() for word in value.replace("\\", "").split("_") if word)

    pretty_vendor, pretty_product = pretty(vendor), pretty(product)
    if pretty_product.lower().startswith(pretty_vendor.lower()):
        return pretty_product
    return f"{pretty_vendor} {pretty_product}".strip()


def _products(cve: dict[str, Any]) -> list[str]:
    found: list[str] = []
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", False):
                    continue
                name = product_from_cpe(match.get("criteria", ""))
                if name and name not in found:
                    found.append(name)
    return found


def _published(value: str | None) -> str:
    """NVD liefert UTC ohne Zeitzonenangabe; für die API als ISO-8601 mit 'Z' ausgeben."""
    if not value:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    parsed = datetime.fromisoformat(value.replace("Z", ""))
    return parsed.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize(item: dict[str, Any]) -> dict[str, Any] | None:
    """Ein Eintrag aus 'vulnerabilities' -> Eingangsformat; None bei unbrauchbaren Daten."""
    cve = item.get("cve", item)
    cve_id = cve.get("id")
    description = _english_description(cve)
    if not cve_id or not description:
        return None

    # Zurückgezogene Meldungen nicht übernehmen.
    if cve.get("vulnStatus") == "Rejected" or description.startswith("** REJECT **"):
        return None

    score, severity = _cvss(cve)
    return {
        "cveId": cve_id,
        "published": _published(cve.get("published")),
        "cvssScore": score,
        "cvssSeverity": severity,
        "description": description,
        "products": _products(cve),
        "source": "NVD",
    }


def normalize_page(payload: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for item in payload.get("vulnerabilities", []):
        normalized = normalize(item)
        if normalized is not None:
            results.append(normalized)
    return results

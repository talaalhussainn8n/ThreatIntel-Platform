import json
from pathlib import Path

import pytest

from collector.api_client import ThreatIntelApi
from collector.normalize import normalize_page, product_from_cpe
from collector.nvd import NvdClient

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "nvd_page.json").read_text(encoding="utf-8"))


def test_normalisiert_gueltige_eintraege_und_ueberspringt_zurueckgezogene():
    items = normalize_page(FIXTURE)
    assert [i["cveId"] for i in items] == ["CVE-2026-11111", "CVE-2026-22222"]


def test_bevorzugt_primaere_cvss_bewertung_und_englische_beschreibung():
    first = normalize_page(FIXTURE)[0]
    assert first["cvssScore"] == 9.8
    assert first["cvssSeverity"] == "CRITICAL"
    assert first["description"].startswith("A remote attacker")
    assert first["published"] == "2026-10-01T10:15:00Z"


def test_nur_verwundbare_produkte_werden_uebernommen():
    first = normalize_page(FIXTURE)[0]
    assert first["products"] == ["Example Vpn Gateway"]


def test_faellt_auf_cvss_v2_zurueck():
    second = normalize_page(FIXTURE)[1]
    assert second["cvssScore"] == 5.0
    assert second["cvssSeverity"] == "MEDIUM"
    assert second["products"] == []


@pytest.mark.parametrize(
    "cpe, expected",
    [
        ("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*", "Apache Http Server"),
        ("cpe:2.3:a:microsoft:microsoft_exchange_server:2019:*:*:*:*:*:*:*", "Microsoft Exchange Server"),
        ("cpe:2.3:a:vendor:*:*:*:*:*:*:*:*:*", None),
        ("kein cpe", None),
    ],
)
def test_produktname_aus_cpe(cpe, expected):
    assert product_from_cpe(cpe) == expected


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(params)
        return self._responses.pop(0)

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append({"url": url, "count": len(json), "key": headers["X-Api-Key"]})
        return FakeResponse({"created": len(json), "updated": 0, "rejected": 0})


def test_nvd_client_blaettert_durch_alle_seiten():
    page1 = {"resultsPerPage": 2, "startIndex": 0, "totalResults": 3, "vulnerabilities": []}
    page2 = {"resultsPerPage": 1, "startIndex": 2, "totalResults": 3, "vulnerabilities": []}
    session = FakeSession([FakeResponse(page1), FakeResponse(page2)])
    client = NvdClient(session=session, page_size=2, sleep=lambda _: None)

    pages = list(client.recent(days=1))

    assert len(pages) == 2
    assert [c["startIndex"] for c in session.calls] == [0, 2]


def test_nvd_client_wiederholt_bei_ratenbegrenzung():
    ok = {"resultsPerPage": 0, "startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    waits = []
    session = FakeSession([FakeResponse({}, status=429), FakeResponse(ok)])
    client = NvdClient(session=session, sleep=waits.append)

    pages = list(client.recent(days=1))

    assert len(pages) == 1
    assert len(waits) == 1


def test_api_client_sendet_in_paketen():
    session = FakeSession([])
    api = ThreatIntelApi("http://api/", "geheim", session=session, batch_size=2)

    totals = api.send({"cveId": f"CVE-2026-{i:05d}"} for i in range(5))

    assert totals["created"] == 5
    assert [c["count"] for c in session.calls] == [2, 2, 1]
    assert session.calls[0]["url"] == "http://api/api/vulnerabilities/batch"
    assert session.calls[0]["key"] == "geheim"

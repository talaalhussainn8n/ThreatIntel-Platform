# Threat Intelligence Lagebild

![CI](https://github.com/talaalhussainn8n/ThreatIntel-Platform/actions/workflows/ci.yml/badge.svg)

Eine Plattform, die öffentliche Schwachstellenmeldungen (CVEs) automatisch sammelt, bewertet und priorisiert.
Sie beantwortet die Frage: **Welche neuen Sicherheitslücken betreffen unsere eigenen Systeme, und welche zuerst?**

## Bausteine

| Teil | Technik | Aufgabe |
| --- | --- | --- |
| `collector/` | Python, requests, pytest | Ruft neue CVEs über die NVD API 2.0 ab (Seitenweise, mit Ratenbegrenzung) und normalisiert sie |
| `api/` | C#, ASP.NET Core, EF Core, PostgreSQL | Nimmt Daten an, bewertet sie, speichert sie und stellt eine REST API bereit |
| `web/` | Vue 3, Vite, Vitest | Lagebild mit Kennzahlen, Filtern, Detailansicht und Beobachtungsliste |
| `docker-compose.yml` | Docker | Startet PostgreSQL, API, Sammler und Oberfläche gemeinsam |

```
NVD API 2.0 --> Python-Sammler --(HTTPS, API-Schlüssel)--> ASP.NET Core API --> PostgreSQL
                                                                 |
                                         Bewertung: Schweregrad, Angriffsmerkmale,
                                         Priorität, Kurzfassung (Sprachmodell optional)
                                                                 |
                                                         Vue-Oberfläche (Lagebild)
```

## Bewertung

- **Schweregrad** aus dem CVSS-Wert (bevorzugt die Primärbewertung der NVD, neueste CVSS-Version zuerst).
- **Angriffsmerkmale** aus der Beschreibung: Codeausführung, aktiv ausgenutzt, ohne Anmeldung, Rechteausweitung, SQL-Injection, XSS und weitere.
- **Priorität 0 bis 100**: CVSS als Basis, Zuschläge für aktiv ausgenutzte Lücken, Codeausführung, fehlende Authentifizierung und Produkte auf der **Beobachtungsliste**.
- **Kurzfassung auf Deutsch**: über ein Sprachmodell (OpenAI-kompatibel, auch lokal mit Ollama) oder regelbasiert, wenn keins konfiguriert ist.

## Starten

### Alles mit Docker

```bash
docker compose up --build
```

Oberfläche: `http://localhost:8080`. Der Sammler lädt die CVEs der letzten 7 Tage und aktualisiert stündlich.

### Einzeln für die Entwicklung

```bash
# API (SQLite, Port 5000)
dotnet run --project api/ThreatIntel.Api

# Sammler
cd collector && pip install -r requirements.txt && python -m collector --days 2

# Oberfläche (leitet /api an Port 5000 weiter)
cd web && npm install && npm run dev
```

Optionale Umgebungsvariablen: `NVD_API_KEY` (höhere Abrufrate), `LLM_BASE_URL` und `LLM_API_KEY` (Kurzfassungen per Sprachmodell).

## Tests

```bash
dotnet test api/ThreatIntel.Tests        # Bewertung und API (End-to-End mit SQLite)
cd collector && python -m pytest          # Normalisierung, Paging, Wiederholversuche
cd web && npm test                        # Anzeigehilfen
```

## API

| Methode | Pfad | Zweck |
| --- | --- | --- |
| POST | `/api/vulnerabilities/batch` | Einlieferung durch den Sammler (Header `X-Api-Key`) |
| GET | `/api/vulnerabilities?severity=&product=&search=&watchlistOnly=&page=` | Gefilterte, priorisierte Liste |
| GET | `/api/vulnerabilities/{cveId}` | Details |
| GET | `/api/stats` | Kennzahlen für das Lagebild |
| GET/POST/DELETE | `/api/watchlist` | Beobachtungsliste pflegen |

## Sicherheit

- Einlieferung nur mit gemeinsamem Schlüssel; Lesezugriff ohne personenbezogene Daten.
- Eingangsdaten werden geprüft (CVE-Format, CVSS-Bereich, Paketgröße).
- Container laufen mit eigenem Benutzer, Zugangsdaten kommen aus Umgebungsvariablen.

## Mögliche Erweiterungen

- Weitere Quellen: CISA Known Exploited Vulnerabilities, Herstellerhinweise, CERT-Bund
- Benachrichtigung bei neuen kritischen Treffern auf der Beobachtungsliste
- Anmeldung und Rollen für mehrere Teams

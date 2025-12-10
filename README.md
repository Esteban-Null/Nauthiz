# Nauthiz – Threat Intelligence Enrichment API

Small IOC enrichment API built with FastAPI and SQLite.

Given an IP or domain, the API:

- Enriches the IOC via VT/RDAP with **VirusTotal**, **SecurityTrails** and **WHOIS**.
- Computes a **risk score (0–100)** and normalizes it into `low` / `medium` / `high` / `critical`.
- Stores the full **query history in SQLite**, with strong constraints on score and risk level.
- Exposes endpoints for **summary**, **history** and temporal **timeline** for each IOC.

---

## Main features

- **Stack**: FastAPI, Python 3.11 and SQLite.
- **Security**:
  - Authentication via `X-API-Key`.
  - Sensitive variables stored in `.env` (not versioned).
  - Constraints in DB (`CHECK` on score and risk_level).
  - Hardened file permissions (`0o700` directory, `0o600` DB file).
- **Integrations**:
  - VirusTotal (domains/IPs).
  - SecurityTrails (domain/IP) – basic lookup.
  - Hunter (WHOIS / email OSINT stub).

These integrations can be customised or extended for other providers.

---

## API endpoints

- `POST /api/query`
- `GET /api/summary/{ioc}`
- `GET /api/history/{ioc}`
- `GET /api/timeline/{ioc}`

---

## Request example

```http
POST /api/query
X-API-Key: <insert_your_api_key>

{
  "ioc": "example.com",
  "ioc_type": "domain"
}
Works best with domains at the moment.
Short response example:
{
  "ioc": "example.com",
  "ioc_type": "domain",
  "score": 50,
  "risk_level": "medium",
  "sources": ["virustotal", "securitytrails", "whois"],
  "vt": { "...": "..." }
}

#Real request and full responses are available in the project screenshots (examples from the live API against VirusTotal and SecurityTrails).

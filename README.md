# ADFIR Platform

**Automated Digital Forensics & Incident Response Platform**

A humanized, rule-based cybersecurity platform that automatically detects threats, investigates incidents, classifies severity, executes safe response actions, and generates forensic reports — with complete audit trail integrity.

> **Lab environment only.** All data is synthetic. No real infrastructure is touched.

---

## Technology Stack

| Layer | Technology | License |
|-------|-----------|---------|
| Backend | Python 3.11+ / Flask | BSD-3 |
| Database | PostgreSQL 15+ | PostgreSQL |
| ORM | SQLAlchemy 2.x | MIT |
| Auth | Flask-JWT-Extended | MIT |
| Encryption | cryptography (AES-256-GCM + SHA-256) | Apache-2.0 |
| Scheduling | APScheduler | MIT |
| Migrations | Alembic | MIT |
| Frontend | HTML5 / Vanilla CSS / Vanilla JS | — |
| PDF Reports | WeasyPrint | BSD-3 |

**No GPL dependencies.** See `requirements.txt` for full license list.

---

## Quick Start

### 1. Prerequisites

- Python 3.11+
- PostgreSQL 15+
- (Optional, for PDF reports) Cairo + Pango system libraries

**Ubuntu/Debian PDF dependencies:**
```bash
sudo apt-get install libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

**Windows PDF dependencies:** Install via [GTK for Windows](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer).

### 2. Clone & Install

```bash
git clone <your-repo>
cd adfir-platform

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.example .env
# Edit .env — fill in SECRET_KEY, JWT_SECRET_KEY, AES_MASTER_KEY, DATABASE_URL
```

Generate secure keys:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

### 4. Set Up PostgreSQL

```sql
CREATE USER adfir_user WITH PASSWORD 'adfir_pass';
CREATE DATABASE adfir_db OWNER adfir_user;
GRANT ALL PRIVILEGES ON DATABASE adfir_db TO adfir_user;
```

### 5. Run Database Migrations

```bash
alembic upgrade head
```

### 6. Start the Platform

```bash
python run.py
```

Open your browser at **http://localhost:5000**

---

## Project Structure

```
adfir-platform/
├── backend/
│   ├── app.py              # Flask application factory
│   ├── config.py           # Dev / Test / Prod configuration
│   ├── extensions.py       # SQLAlchemy, JWT, CORS, APScheduler
│   ├── api/                # REST API blueprints (9 modules)
│   ├── models/             # SQLAlchemy ORM models (12 entities)
│   ├── ingestion/          # Event normalisation & deduplication
│   ├── detection/          # Rule-based detection engine + YAML rules
│   ├── orchestrator/       # Incident lifecycle state machine
│   ├── investigation/      # Evidence collection & timeline builder
│   ├── classifier/         # Severity scoring (P1–P4)
│   ├── response/           # Automated response engine + playbooks
│   ├── vault/              # AES-256-GCM evidence storage + SHA-256
│   ├── audit/              # Chained SHA-256 audit trail
│   ├── reporting/          # HTML / JSON / PDF report generation
│   ├── scheduler/          # APScheduler background jobs
│   └── utils/              # Shared utilities
├── frontend/               # Vanilla HTML/CSS/JS dashboard
│   ├── index.html
│   ├── css/
│   └── js/
├── tools/
│   └── data_generator/     # Synthetic attack scenario generator
├── migrations/             # Alembic migration scripts
├── tests/                  # Unit / Integration / API test suites
├── docs/                   # Technical documentation
├── data/                   # Runtime data (gitignored)
│   ├── evidence/           # Encrypted evidence artifacts
│   ├── reports/            # Generated forensic reports
│   └── lab/                # Synthetic lab state
├── requirements.txt
├── .env.example
└── run.py
```

---

## Detection Rules

Five built-in rules (YAML, in `backend/detection/rules/`):

| Rule ID | Name | Type | Severity |
|---------|------|------|----------|
| `BRUTE_FORCE_001` | SSH/RDP Brute Force | threshold | 7/10 |
| `PORT_SCAN_001` | Horizontal Port Scan | threshold | 5/10 |
| `DATA_EXFIL_001` | Large Outbound Transfer | threshold | 9/10 |
| `PRIV_ESC_001` | Privilege Escalation | sequence | 8/10 |
| `LATERAL_MOVE_001` | Multi-Asset Auth Sweep | threshold | 8/10 |

---

## Incident Lifecycle

```
NEW → INVESTIGATING → CLASSIFIED → RESPONDING → CONTAINED → CLOSED
```

Every state transition is recorded in the immutable audit log with a chained SHA-256 checksum.

---

## Evidence Integrity

- **SHA-256** computed on every artifact before encryption
- **AES-256-GCM** authenticated encryption (per-artifact nonce)
- Hash re-verified on every read — mismatch raises `EvidenceTamperedException`
- Audit chain uses SHA-256(prev_checksum + row_content) — blockchain-inspired

---

## API

All endpoints live under `/api/v1/`. JWT bearer token required (except `/auth/login`).

Key endpoints:
- `POST /api/v1/auth/login` — Authenticate
- `GET  /api/v1/incidents` — List incidents
- `GET  /api/v1/dashboard/summary` — Live KPI data
- `POST /api/v1/events/ingest` — Submit synthetic event
- `GET  /api/v1/audit/verify` — Verify audit chain integrity

See `docs/api_reference.md` for the full reference.

---

## Running Tests

```bash
pytest tests/ -v --tb=short
pytest tests/unit/ -v            # Unit tests only
pytest tests/integration/ -v     # Integration tests only
pytest tests/ --cov=backend      # With coverage report
```

---

## Generating Synthetic Attack Data

```bash
# Brute force scenario — 10 events/second for 30 seconds
python -m tools.data_generator.generator --scenario brute_force --rate 10 --duration 30

# Port scan scenario
python -m tools.data_generator.generator --scenario port_scan
```

---

## Security Notes

- Secrets are **never** hardcoded — all from environment variables
- Application DB user has **no DELETE/UPDATE rights** on `audit_log`
- Evidence blobs are **never served raw** — only via authenticated vault API
- All SQL uses **parameterised queries** via SQLAlchemy ORM
- Input validated with **Marshmallow schemas** on every endpoint

---

## Development Phases

| Phase | Status | Description |
|-------|--------|-------------|
| 1 | 🔲 Next | Foundation: DB, auth, vault, audit chain |
| 2 | 🔲 | Ingestion & detection engine |
| 3 | 🔲 | Orchestrator, investigation, classifier |
| 4 | 🔲 | Response engine & playbooks |
| 5 | 🔲 | Report generation |
| 6 | 🔲 | Frontend & synthetic data generator |
| 7 | 🔲 | Hardening, tests, documentation |

---

## License Strategy

All production dependencies are MIT / BSD / Apache-2.0.
`psycopg2-binary` is LGPL-2.1 (dynamic linking — compliant for non-GPL use).
No GPL dependencies.

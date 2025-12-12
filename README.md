# TTI Automation – CVE and Threat Intelligence Pipeline

## Overview

TTI Automation is a backend system that automates the discovery, analysis, and notification of security vulnerabilities for multiple clients.
It collects CVE information and vendor advisories, enriches them with threat-intelligence data, matches them against each client's technology inventory, and sends tailored HTML advisory emails.

The goal is to replace manual CVE tracking in Excel and email with a repeatable, auditable workflow.

## Main Features

- **CVE and Zero-Day Ingestion**
  - Pull CVEs from public sources such as NVD.
  - Ingest vendor advisories and security bulletins.
  - Store raw data for traceability and future re-processing.

- **Data Normalization and Tracking**
  - Normalize vulnerabilities into a consistent schema (CVE ID, CVSS, CWE, affected products and versions).
  - Maintain history for each vulnerability and source document.

- **Client-Specific Impact Mapping**
  - Store client technology inventories (assets, software, versions).
  - Match vulnerabilities to client software with version-aware logic.
  - Create per-client vulnerability records with impact level and status.

- **Threat Intelligence Enrichment**
  - Attach CVSS v3 scores, CWE details, references, and patch / mitigation links.
  - Optionally add Indicators of Compromise (IOCs) from external feeds.

- **LLM-Assisted Analysis**
  - Use an LLM to generate structured summaries for each vulnerability:
    - Short executive summary
    - Technical description
    - Business impact
    - Recommended mitigation steps

- **Automated Email Advisories**
  - Generate HTML advisory emails per client.
  - Include affected assets, impact, and mitigation guidance.
  - Route notifications to the right recipients (To / CC) using client contact data.
  - Log sent emails and notification status.

- **Scheduling and Automation**
  - Periodic ingestion of new CVEs and advisories.
  - Automatic client impact mapping and email sending.
  - Logging and basic error handling.

## High-Level Architecture

- **Ingestion Layer**
  - Fetches CVE and advisory data from NVD and selected vendors.
  - Stores raw JSON and HTML in a `source_documents` table.

- **Normalization and Storage**
  - Parses raw data into structured `vulnerabilities` and `vulnerability_affects` tables.
  - Uses PostgreSQL as the main data store.

- **Client Inventory Module**
  - Manages clients, assets, and installed software.
  - Imports inventory from CSV or API.

- **Matching Engine**
  - Compares affected products / versions against client software.
  - Creates `client_vulnerabilities` and tracks their lifecycle.

- **Enrichment and LLM Service**
  - Adds CVSS, CWE, references and IOCs.
  - Calls an LLM to create structured summaries used for reporting and email content.

- **Notification Service**
  - Builds HTML advisory emails based on templates.
  - Sends via SMTP and records results in `email_logs`.

- **Scheduler**
  - Runs ingestion, matching, enrichment, and notification jobs on a periodic schedule.

## Tech Stack

- **Language:** Python
- **Framework:** FastAPI (backend APIs)
- **Database:** PostgreSQL
- **Task Scheduling:** Cron or Celery
- **LLM:** OpenAI API or local model (configurable)
- **OS:** Kali Linux VPS

## Roadmap

- [X] Phase 0 – Project definition and Git repository
- [X] Phase 1 – Environment setup on VPS
- [X] Phase 2 – Database design and PostgreSQL setup
- [X] Phase 3 – Backend skeleton (FastAPI)
- [X] Phase 4 – NVD CVE ingestion and storage
- [X] Phase 5 – Vendor advisory scraping
- [X] Phase 6 – Client inventory module
- [X] Phase 7 – Matching engine
- [X] Phase 8 – Enrichment and LLM summaries
- [X] Phase 9 – Email advisory generation and routing
- [X] Phase 10 – Scheduling and automation
- [X] Phase 11 – Dashboard, documentation, and polishing

## Status

Work in progress. This repository is part of a personal project to build an end-to-end vulnerability intelligence workflow suitable for real-world consulting work and portfolio demonstration.



# TTI Automation – Threat Intelligence Workflow

Automated backend that:

- Ingests CVEs from NVD
- Enriches them with vendor references and LLM summaries
- Matches vulnerabilities to each client’s technology inventory
- Generates client-specific advisory emails (HTML + text)
- Exposes a JSON dashboard with key counts
- Runs the full pipeline daily via cron

This repo contains only the backend and batch jobs. Any SMTP sending or fancy UI can be integrated later on top of the existing APIs.

---

## 1. Architecture

**Stack**

- Python + FastAPI (`backend/app`)
- PostgreSQL (`tti_db`)
- SQLAlchemy ORM models
- Jinja2 for HTML email templates
- Stand-alone scripts for ingestion/enrichment (`scripts/`)
- Cron for daily automation

**Main components**

- `backend/app/main.py` – FastAPI application entrypoint
- `backend/app/models.py` – SQLAlchemy models
- `backend/app/schemas.py` – Pydantic schemas (API I/O)
- `backend/app/db.py` – DB session + engine
- `backend/app/routers/clients.py` – clients, assets, software, matching, advisory email
- `backend/app/routers/dashboard.py` – high-level dashboard summary
- `scripts/nvd_ingest.py` – pull CVEs from NVD and store in `vulnerabilities`
- `scripts/vendor_reference_enrich.py` – add vendor/extra references to vulns
- `scripts/llm_enrich.py` – add LLM summaries / structured metadata
- `scripts/refresh_all_clients.py` – run matching for all clients and log stats

---

## 2. Setup

### 2.1. Clone and install

git clone <this-repo-url> tti-automation
cd tti-automation

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt


### 2.2. PostgreSQL

## Create DB and user (only needed on a fresh install):

CREATE DATABASE tti_db;
CREATE USER tti_user WITH PASSWORD 'strongpassword';
GRANT ALL PRIVILEGES ON DATABASE tti_db TO tti_user;

## Check that backend/app/db.py points to the same database, for example:

DATABASE_URL = "postgresql+psycopg2://tti_user:strongpassword@localhost/tti_db"
Run migrations if you use Alembic, or create tables via SQLAlchemy as already configured in the project.

## 3. Running the API

From the repo root with the virtualenv activated:
uvicorn backend.app.main:app --reload --host 0.0.0.0 --port 8100

Open:
- Swagger / OpenAPI UI: http://<server-ip>:8100/docs
- Health check: GET /health → {"status": "ok"}

## 4. Data flow (end-to-end)

## This is the logical flow from CVE ingestion to advisory email.

### 4.1. Ingest CVEs from NVD

python -m scripts.nvd_ingest

Effect:
Populates vulnerabilities table with CVEs, severity, CVSS, descriptions, etc.

### 4.2. Vendor reference enrichment

python -m scripts.vendor_reference_enrich

Effect:
- Enriches existing vulnerabilities with extra references (patch links, vendor advisories, etc.).
- Stores those references inside JSON metadata (llm_summary / similar field).

### 4.3. LLM enrichment

python -m scripts.llm_enrich

Effect:
- Adds machine-readable + human-readable summaries to each vulnerability:
  - summary_text
  - structured references list
  - any additional metadata needed by the email template

### 4.4. Client inventory

Use the /clients routes (via Swagger UI or curl) to create:
1. Client
   POST /clients
{
  "name": "Demo Bank",
  "code": "DEMO"
}

2. Asset for that client
   POST /clients/{client_id}/assets
{
  "hostname": "web01.demobank.local",
  "ip_address": "10.0.0.10",
  "asset_type": "server",
  "criticality": "HIGH",
  "owner": "IT Operations"
}

3. Software installed on the asset
   POST /assets/{asset_id}/software
{
  "vendor": "apache",
  "product": "http_server",
  "version": "2.4.58",
  "cpe_uri": null
}

4. Client contacts (for routing)
   POST /clients/{client_id}/contacts
{
  "name": "John Doe",
  "email": "john.doe@example.com",
  "role": "CISO",
  "is_primary": true
}
You can add extra contacts with is_primary = false for CC.

### 4.5. Matching engine

Match all vuln records against this client’s software inventory:
POST /clients/{client_id}/match_vulnerabilities

Example output:

{
  "client_id": 1,
  "assets_seen": 1,
  "software_seen": 1,
  "matches_created": 1,
  "matches_skipped_existing": 0
}
This populates client_vulnerabilities with status open.

### 4.6. Advisory email generation

Generate a full advisory for the client:
POST /clients/{client_id}/generate_advisory_email

Returns:
  - Subject line
  - HTML body
  - Plain-text body
  - Stats (total, critical, high, medium, low)
  - To / CC recipients derived from the client’s contacts
  - An email_log_id row in email_logs for auditability

This is the object you would send via SMTP or any mail provider.

### 4.7. Dashboard summary

High-level JSON overview:
GET /dashboard/summary

Example response:
{
  "totals": {
    "clients": 1,
    "assets": 1,
    "software": 1,
    "vulnerabilities": 108,
    "matches": 1
  },
  "open_matches_by_severity": {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0,
    "UNKNOWN": 1
  }
}
This endpoint backs any future UI/dashboard without changing the backend.

## 5. Automation (cron)
On the VPS, the full nightly pipeline is wired into crontab:

### 1) NVD CVE ingest — every night at 01:00
0 1 * * * cd /home/kali/tti-automation && /home/kali/tti-automation/venv/bin/python -m scripts.nvd_ingest >> /home/kali/tti-automation/logs/nvd_ingest.log 2>&1
### 2) Vendor advisory / reference enrichment — 01:15
15 1 * * * cd /home/kali/tti-automation && /home/kali/tti-automation/venv/bin/python -m scripts.vendor_reference_enrich >> /home/kali/tti-automation/logs/vendor_reference_enrich.log 2>&1
### 3) LLM enrichment — 01:30
30 1 * * * cd /home/kali/tti-automation && /home/kali/tti-automation/venv/bin/python -m scripts.llm_enrich >> /home/kali/tti-automation/logs/llm_enrich.log 2>&1
### 4) Refresh all clients (re-run matching) — 06:00
0 6 * * * cd /home/kali/tti-automation && /home/kali/tti-automation/venv/bin/python -m scripts.refresh_all_clients >> /home/kali/tti-automation/logs/refresh_all_clients.log 2>&1

Effect:
  - Every night, new CVEs are imported.
  - References and LLM summaries are updated.
  - Every morning, all clients are re-matched so the dashboard and advisory outputs are always current.

Logs for debugging:
tail -n 50 logs/nvd_ingest.log
tail -n 50 logs/vendor_reference_enrich.log
tail -n 50 logs/llm_enrich.log
tail -n 50 logs/refresh_all_clients.log

## 6. How to demo in 5 minutes

  1. Show GET /health and GET /dashboard/summary.
  2. In Swagger, create a new client, asset, software, and primary contact.
  3. Run POST /clients/{id}/match_vulnerabilities.
  4. Run POST /clients/{id}/generate_advisory_email and display the HTML body.
  5. Show SELECT * FROM email_logs in psql to prove logging.
  6. Optionally, show the cron config and logs/*.log to demonstrate full automation.

This covers the full story: ingestion → enrichment → matching → advisory → basic dashboard → scheduled monitoring.



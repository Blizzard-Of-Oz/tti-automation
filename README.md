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
- [ ] Phase 5 – Vendor advisory scraping
- [ ] Phase 6 – Client inventory module
- [ ] Phase 7 – Matching engine
- [ ] Phase 8 – Enrichment and LLM summaries
- [ ] Phase 9 – Email advisory generation and routing
- [ ] Phase 10 – Scheduling and automation
- [ ] Phase 11 – Dashboard, documentation, and polishing

## Status

Work in progress. This repository is part of a personal project to build an end-to-end vulnerability intelligence workflow suitable for real-world consulting work and portfolio demonstration.

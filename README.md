# SentinelForge

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Security: Hardened](https://img.shields.io/badge/Security-Hardened-emerald.svg)](SECURITY.md)
[![Architecture: Decoupled](https://img.shields.io/badge/Architecture-SOC%20SIEM-orange.svg)](docs/architecture/system-architecture.md)

> [!NOTE]
> **Disclaimer**: SentinelForge is an educational portfolio project. It is not intended to replace a production enterprise SIEM platform.

SentinelForge is a production-style, lightweight Security Information and Event Management (SIEM) platform engineered to demonstrate core cybersecurity principles, event ingestion pipelines, log normalization, deterministic detection engineering, alert lifecycle management, incident response workflows, strict role-based access control (RBAC), immutable audit logging, and modern DevSecOps practices.

---

## Architecture Overview

SentinelForge adheres to a decoupled unidirectional pipeline ensuring clean separation of ingestion, normalization, detection evaluation, alerting, and human-in-the-loop investigation.

```text
                    Log Sources
                         │
                         ▼
                Event Ingestion API  (POST /api/v1/events)
                         │
                         ▼
                Event Validation     (Pydantic Schema Enforcement)
                         │
                         ▼
                 Normalization       (UTC, IP normalization, sanitization)
                         │
                         ▼
                 Enrichment Layer    (UUID generation, context binding)
                         │
                         ▼
                 Detection Engine    (Deterministic rule evaluations)
                    ┌────┴────┐
                    ▼         ▼
               PostgreSQL   Alert Engine (State machine: OPEN -> RESOLVED)
                                  │
                                  ▼
                            Alert Evidence (alert_events linkage)
                                  │
                                  ▼
                           Incident Management (Grouped alerts, triage)
                                  │
                                  ▼
                            Analyst SOC Dashboard (Next.js 15 Dark UI)
```

---

## Features

- **High-Throughput Ingestion**: Single and batch event ingestion API with input validation, payload size bounding, and rate limiting.
- **Strict Log Normalization**: UTC timestamp standardization, IP representation canonicalization, event taxonomy enforcement, and field sanitization.
- **Deterministic Detection Engine**: Rule-based detection sliding windows without unpredictable black-box heuristics or hallucinations.
- **Alert & Evidence Management**: Alerts strictly linked to triggering events (`alert_events`) maintaining an immutable evidence chain.
- **Incident Response Workflow**: Alert aggregation into incidents, analyst assignment, severity assessment, containment tracking, and resolution notes.
- **Role-Based Access Control (RBAC)**: Server-side enforced authorization (`ADMIN`, `ANALYST`, `VIEWER`) across all API endpoints.
- **Immutable Audit Logging**: Security-relevant mutations recorded with actor ID, action, resource, diff, source IP, user agent, and timestamp.
- **Real Metrics SOC Dashboard**: Dark-mode SOC dashboard powered strictly by live database metrics without mock or randomized values.

---

## Technology Stack

### Backend (`apps/api`)
- **Framework**: FastAPI (Python 3.13+)
- **Validation**: Pydantic v2 & Pydantic Settings
- **ORM & Migrations**: SQLAlchemy 2.0 (Async) & Alembic
- **Database**: PostgreSQL 16
- **Password Hashing**: Argon2id via `argon2-cffi`
- **Security & Tokens**: PyJWT (HMAC-SHA256), slowapi (rate limiting)
- **Testing & Quality**: Pytest, Ruff, Mypy, Bandit

### Frontend (`apps/web`)
- **Framework**: Next.js 15 (App Router, React 19, TypeScript)
- **Styling**: Tailwind CSS & shadcn/ui
- **State Management**: TanStack Query v5
- **Charts & Telemetry**: Recharts
- **Icons**: Lucide React

---

## Detection Rules Baseline

SentinelForge includes deterministic detection rules out of the box:

| Rule ID | Rule Name | Condition & Window | Severity |
| :--- | :--- | :--- | :--- |
| **RULE-001** | Brute Force Login | 5 failed authentications from same source IP in 5 min | `HIGH` |
| **RULE-002** | Account Attack | 10 failed authentications against same username in 10 min | `HIGH` |
| **RULE-003** | Suspicious Successful Login | Multiple failed logins followed by success from same IP in window | `HIGH` |
| **RULE-004** | HTTP Authentication Abuse | Repeated HTTP 401 responses from same source IP in window | `MEDIUM` |
| **RULE-005** | Port Scan Pattern | Connection attempts from same IP across multiple ports in window | `HIGH` |

For full specification and logic definitions, see [DETECTION-RULES.md](DETECTION-RULES.md).

---

## Security Controls

- **Zero Hardcoded Secrets**: Strict environment variable configuration via `.env`.
- **Argon2id Password Storage**: Industry-standard salted, memory-hard password hashing.
- **Strict Server-Side RBAC**: Route guards enforced at the controller layer; no client-only trust.
- **Parameterized Queries**: 100% ORM-driven SQL generation preventing SQL injection.
- **Safe Output Serialization**: Internal database identifiers and sensitive fields protected from exposure.
- **Immutable Audit Records**: Append-only security audit log table.
- **Structured JSON Logging**: Standardized application logs without sensitive token or password leakage.

For threat modeling details, review [THREAT-MODEL.md](THREAT-MODEL.md) and [SECURITY.md](SECURITY.md).

---

## Project Structure

```text
sentinelforge/
├── apps/
│   ├── web/                     # Next.js 15 SOC dashboard application
│   └── api/                     # FastAPI backend application & migrations
├── detection-rules/             # Declarative detection rules (YAML/JSON)
├── docs/
│   ├── architecture/            # Architectural design specifications
│   ├── security/                # Threat modeling & security controls
│   ├── api/                     # OpenAPI specs and API design
│   └── operations/              # Deployment and operational procedures
├── infrastructure/
│   └── docker/                  # Hardened Docker configurations
├── scripts/                     # Seed scripts, security validation harnesses
├── tests/                       # E2E integration and security test suites
├── .github/workflows/           # Security scanning (Semgrep, Gitleaks, Trivy)
├── docker-compose.yml           # Local multi-container development environment
└── .env.example                 # Environment configuration template
```

---

## Local Setup & Development

### Prerequisites
- Python 3.11+ (Python 3.13 recommended)
- Node.js v20+ & `pnpm` (or `npm`)
- PostgreSQL 16 (or Docker Desktop)

### 1. Backend Setup
```bash
cd apps/api
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp ../../.env.example .env
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup
```bash
cd apps/web
pnpm install
pnpm dev
```

Visit `http://localhost:3000` to access the analyst console.

---

## Docker Compose Setup

Run the full platform locally:
```bash
docker compose up --build
```
This deploys:
- `api` on `http://localhost:8000`
- `web` on `http://localhost:3000`
- `postgres` (internal network only)

---

## Project Limitations & Non-Goals

1. **Portfolio Scope**: Built as a demonstration of defensive engineering, detection logic, and secure API design.
2. **Deterministic Rules**: Uses deterministic rule processing rather than deep learning or probabilistic AI models.
3. **Standalone Architecture**: Designed for single-instance or containerized compose deployments without distributed event brokers (Kafka/Flink) in Phase 1.

---

## Future Roadmap

- [ ] Distributed event streaming integration (Kafka / Redpanda)
- [ ] AWS CloudFront / ECS / RDS Terraform deployment module
- [ ] SIGMA rule translation engine
- [ ] Automated incident containment webhooks (IP block automation)

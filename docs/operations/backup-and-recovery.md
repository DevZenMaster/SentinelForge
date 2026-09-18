# SentinelForge Backup & Disaster Recovery Guide

## 1. Scope & Authoritative Data Stores

SentinelForge stores authoritative, forensic-grade security evidence in PostgreSQL 16. All evidentiary records must be protected with deterministic, tamper-evident backup and recovery procedures.

### Critical Evidence Artifacts to Backup
- **Raw & Normalized Events** (`events`): Forensic event telemetry and normalized attributes.
- **Alerts & Evidence Associations** (`alerts`, `alert_events`, `alert_notes`): Security detection records, linked events, and append-only analyst triage notes.
- **Incident Cases & Timelines** (`incidents`, `incident_alerts`, `incident_notes`): Incident dossiers, correlated alerts, and case notes.
- **Threat Intelligence** (`indicators`, `threat_intel`): IOC repository, confidence scores, and observable sightings.
- **Detection Engineering Rules** (`detection_rules`): Immutable published rule versions and detection condition criteria.
- **Immutable Security Audit Trail** (`audit_logs`): Append-only security mutation logs with actor attribution and request correlation IDs.
- **Notification Records & Policies** (`integrations`, `notification_policies`, `notification_events`, `notification_deliveries`): Integration registry, delivery records, and audit dispatches.

---

## 2. Backup Strategy & Scheduling

| Tier | Type | Frequency | Retention | Target Destination |
| :--- | :--- | :--- | :--- | :--- |
| **Point-in-Time** | WAL Archiving | Continuous (archived every 60s) | 14 Days | Encrypted S3 / Cloud Storage |
| **Full Logical Dump** | `pg_dump` (Custom Format) | Daily at 01:00 UTC | 90 Days | Air-Gapped Object Storage |
| **Long-Term Archive** | Encrypted Snapshot | Monthly | 365+ Days | Immutable Object Lock Vault |

---

## 3. Backup Execution Procedures

### 3.1 Logical Backup Command (`pg_dump`)
Execute daily full logical backups using PostgreSQL's compressed custom format (`-Fc`), enabling parallel restores and selective table restoration:

```bash
#!/usr/bin/env bash
set -euo pipefail

BACKUP_DATE=$(date -u +"%Y%m%d_%H%M%SZ")
BACKUP_DIR="/var/backups/sentinelforge"
BACKUP_FILE="${BACKUP_DIR}/sentinelforge_backup_${BACKUP_DATE}.dump"

mkdir -p "${BACKUP_DIR}"

echo "Starting SentinelForge backup: ${BACKUP_FILE}"
PGPASSWORD="${POSTGRES_PASSWORD}" pg_dump \
    -h "${POSTGRES_SERVER:-localhost}" \
    -p "${POSTGRES_PORT:-5432}" \
    -U "${POSTGRES_USER:-sentinelforge}" \
    -d "${POSTGRES_DB:-sentinelforge_db}" \
    -Fc \
    -Z 9 \
    --no-owner \
    --no-privileges \
    -f "${BACKUP_FILE}"

echo "Encrypting backup archive with GPG/AES-256..."
gpg --symmetric --cipher-algo AES256 --batch --passphrase-file /etc/sentinelforge/backup_key.bin "${BACKUP_FILE}"
rm -f "${BACKUP_FILE}"

echo "Backup complete: ${BACKUP_FILE}.gpg"
```

---

## 4. Restoration & Recovery Procedures

### 4.1 Disaster Recovery Steps
1. **Provision Destination PostgreSQL 16 Instance**: Ensure identical major version and disk sizing.
2. **Decrypt Backup Archive**:
   ```bash
   gpg --decrypt --batch --passphrase-file /etc/sentinelforge/backup_key.bin \
       sentinelforge_backup_YYYYMMDD_HHMMSSZ.dump.gpg > restored.dump
   ```
3. **Restore Database Structure & Data**:
   ```bash
   PGPASSWORD="${RESTORE_DB_PASSWORD}" pg_restore \
       -h "${RESTORE_DB_HOST}" \
       -p 5432 \
       -U sentinelforge \
       -d sentinelforge_db \
       --clean \
       --if-exists \
       --no-owner \
       --no-privileges \
       restored.dump
   ```
4. **Apply Pending Migrations** (if restoring an earlier revision):
   ```bash
   cd apps/api
   ./.venv/bin/alembic upgrade head
   ```

---

## 5. Recovery Integrity Verification

Following any database restoration, run the automated, non-destructive verification tool to confirm evidentiary integrity:

```bash
python scripts/verify_backup_integrity.py \
    --db-url "postgresql+asyncpg://sentinelforge:secret@localhost:5432/sentinelforge_db" \
    --json
```

The script verifies:
1. **Catalog Completeness**: All 21 required tables exist across all phases.
2. **Record Count Non-Zero State**: Populated tables retain evidentiary records.
3. **Referential Integrity**: Zero orphaned records in `alert_events` or `incident_alerts`.

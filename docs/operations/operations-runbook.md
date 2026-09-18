# SentinelForge Operations Runbook

## 1. Application Unavailable / Crash Loop

### Symptoms
- Load balancer reports 502/504 Bad Gateway.
- API liveness probe (`GET /live`) fails or times out.
- Process exits immediately on startup.

### Diagnosis
1. Inspect container/system logs for startup validation errors:
   ```bash
   journalctl -u sentinelforge-api -n 100 --no-pager
   # Or docker logs sentinelforge-api --tail 100
   ```
2. Common causes:
   - **Configuration Validation Error**: In `ENVIRONMENT=production`, the application refuses to boot if `DEBUG=True`, default `SECRET_KEY` is detected, or `SESSION_COOKIE_SECURE` is False.
   - **Database Connectivity**: PostgreSQL is unreachable or authentication failed.
   - **Port Collision**: Another process is bound to port 8000.

### Remediation
1. Correct environment variables in `.env` or systemd environment file.
2. Verify PostgreSQL listener: `pg_isready -h localhost -p 5432`.
3. Restart service:
   ```bash
   systemctl restart sentinelforge-api
   ```

---

## 2. Database Connection Pool Exhaustion

### Symptoms
- API responses return HTTP 500 with `DATABASE_ERROR` code.
- Operational metrics show `checkedout == size + max_overflow`.
- Database logs indicate `FATAL: remaining connection slots are reserved for non-superuser connections`.

### Diagnosis
1. Query active PostgreSQL connections:
   ```sql
   SELECT count(*), state, client_addr FROM pg_stat_activity GROUP BY state, client_addr;
   ```
2. Check for long-running transactions:
   ```sql
   SELECT pid, now() - query_start AS duration, query
   FROM pg_stat_activity
   WHERE state != 'idle'
   ORDER BY duration DESC
   LIMIT 10;
   ```

### Remediation
1. Terminate hung backend sessions:
   ```sql
   SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state != 'idle' AND query_start < now() - interval '5 minutes';
   ```
2. Adjust pool limits in `apps/api/.env`:
   - Increase `DB_POOL_SIZE` (default: 20) and `DB_MAX_OVERFLOW` (default: 10).
   - Verify PostgreSQL `max_connections` in `postgresql.conf` is >= `workers * (DB_POOL_SIZE + DB_MAX_OVERFLOW) + 20`.
3. Restart API workers gracefully.

---

## 3. Notification Delivery Backlog & Stale Job Reconciliation

### Symptoms
- Delivery table (`/notifications`) shows deliveries stuck in `DELIVERING` or `PENDING`.
- High retry volume.

### Diagnosis
1. Check delivery metrics via API:
   ```bash
   curl -s -H "Cookie: sentinelforge_session=..." https://soc.corp.internal/api/v1/notifications/metrics
   ```
2. Query delivery statuses in DB:
   ```sql
   SELECT status, count(*) FROM notification_deliveries GROUP BY status;
   ```

### Remediation
1. **Trigger Automatic Startup Reconciliation**:
   On restart, SentinelForge automatically resets stuck `DELIVERING` jobs to `RETRYING` or marks them `EXHAUSTED` if max attempts have elapsed.
2. **Manual Reconciliation via API**:
   Authorized analysts can retry exhausted dispatches directly from the UI (`/notifications`) or via `POST /api/v1/notifications/{id}/retry`.
3. **Verify Destination Reachability**:
   Test the destination webhook or SMTP server via `POST /api/v1/integrations/{id}/test`.

---

## 4. Migration Failure & Safe Rollback

### Symptoms
- `alembic upgrade head` fails with a SQL error or lock timeout.
- Schema state out of synchronization.

### Rules
- **NEVER downgrade production migrations automatically** without reviewing data loss implications.
- Back up the database before executing any manual rollback.

### Remediation
1. Identify the current database revision:
   ```bash
   cd apps/api
   ./.venv/bin/alembic current
   ```
2. Inspect the failed migration script in `apps/api/migrations/versions/`.
3. If safe to roll back to the prior stable revision:
   ```bash
   ./.venv/bin/alembic downgrade <previous_revision_id>
   ```
4. Resolve the conflicting index or constraint, then retry:
   ```bash
   ./.venv/bin/alembic upgrade head
   ```

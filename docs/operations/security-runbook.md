# SentinelForge Security Runbook

## 1. Suspected Secret or Credential Leakage

### Symptoms
- An API key, database password, master `SECRET_KEY`, or integration secret was accidentally committed to source control or exposed in external logs.

### Immediate Containment
1. **Rotate the Master `SECRET_KEY`**:
   - Generate a new 64-character high-entropy secret:
     ```bash
     openssl rand -hex 32
     ```
   - Update `SECRET_KEY` in production `.env`.
   - Restart the API. Note: Rotating `SECRET_KEY` immediately invalidates all active session tokens, requiring all analysts to re-authenticate.
2. **Rotate Database Password**:
   - Update the password in PostgreSQL:
     ```sql
     ALTER USER sentinelforge WITH PASSWORD 'new_high_entropy_password';
     ```
   - Update `POSTGRES_PASSWORD` in `.env` and restart the backend.
3. **Rotate Integration Secret Tokens**:
   - Update destination secrets via the UI (`/integrations`) or `PATCH /api/v1/integrations/{id}` with `secret_token: "..."`.
   - Update consumer endpoint validation keys.

---

## 2. Compromised External Webhook Destination

### Symptoms
- External webhook consumer endpoint is breached or controlled by an adversary.
- Risk of sensitive alert metadata exfiltration.

### Containment
1. **Disable Destination Immediately**:
   Navigate to `/integrations` and toggle the destination status to `Disabled`, or issue:
   ```bash
   POST /api/v1/integrations/{destination_id}/disable
   ```
2. **Disable Associated Policies**:
   Disable any notification policies directing traffic to the compromised destination.
3. **Cancel In-Flight / Pending Deliveries**:
   Query all `PENDING` or `RETRYING` deliveries targeting the destination and cancel them:
   ```bash
   POST /api/v1/notifications/{delivery_id}/cancel
   ```
4. **Audit Historical Dispatches**:
   Query `notification_deliveries` for all records sent to that destination within the breach window to determine exact data exposure scope.

---

## 3. Suspicious Administrative Activity Investigation

### Symptoms
- Unauthorized policy changes, rule modifications, or alert suppression reported.

### Investigation
1. **Inspect Append-Only Audit Trail**:
   Query the audit log table or use the UI at `/audit` (requires `audit.read` permission):
   ```sql
   SELECT created_at, actor_user_id, action, resource_type, resource_id, request_id, old_value, new_value
   FROM audit_logs
   WHERE action IN ('USER_ROLE_UPDATED', 'DETECTION_RULE_ACTIVATED', 'ALERT_SUPPRESSED', 'INTEGRATION_UPDATED')
   ORDER BY created_at DESC
   LIMIT 50;
   ```
2. **Correlate Request ID**:
   Take the `request_id` from the audit record and cross-reference structured application access logs to identify client IP, user agent, and timestamp.
3. **Revoke Actor Sessions**:
   Terminate all active sessions for the compromised user account:
   ```sql
   UPDATE sessions SET is_active = FALSE WHERE user_id = 'compromised-uuid';
   ```

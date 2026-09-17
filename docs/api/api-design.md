# SentinelForge API Design Specification

## Overview

SentinelForge adheres to RESTful API principles with standardized JSON response envelopes, strict status codes, comprehensive OpenAPI documentation, and server-side RBAC validation on all endpoints.

Base API Prefix: `/api/v1`

---

## Response Envelope Standard

### Success Response
All successful responses return HTTP status `200 OK` (or `201 Created` for resource creation) with the following structure:

```json
{
  "data": {
    "id": "e3b0c442-98fc-1c14-9afb-4c8996fb9242",
    "status": "OPEN",
    "severity": "HIGH"
  },
  "meta": {
    "timestamp": "2026-09-17T08:15:00Z",
    "request_id": "req-98f7e2a1-0001",
    "page": 1,
    "limit": 20,
    "total": 1
  },
  "error": null
}
```

### Error Response
Errors return appropriate HTTP status codes (`400`, `401`, `403`, `404`, `422`, `429`, `500`) with no internal stack traces leaked:

```json
{
  "data": null,
  "meta": {
    "timestamp": "2026-09-17T08:15:00Z",
    "request_id": "req-98f7e2a1-0002"
  },
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to perform this action.",
    "details": null
  }
}
```

---

## Endpoint Catalog

### Authentication (`/api/v1/auth`)
- `POST /api/v1/auth/login` - Authenticate user credentials, create session, return token.
- `POST /api/v1/auth/logout` - Invalidate current session and revoke token.
- `GET /api/v1/auth/me` - Retrieve authenticated user profile, roles, and permissions.

### Events (`/api/v1/events`)
- `POST /api/v1/events` - Ingest a single security event into the pipeline.
  - **Auth**: Required (`events.create` permission; granted to `ADMIN` and `ANALYST`, blocked for `VIEWER` with `403 Forbidden`).
  - **Headers**:
    - `Idempotency-Key` *(optional)*: Client deduplication key (reconciles with `external_event_id`).
    - `X-Request-ID` *(optional)*: Client correlation ID (sanitized against log injection regex `^[a-zA-Z0-9_\-:.]{1,64}$`).
  - **Payload Limits**: Max 1MB (`MAX_EVENT_PAYLOAD_BYTES=1048576`); returns `413 Payload Too Large`.
  - **Rate Limiting**: Evaluated per client IP and user (`EVENTS_RATE_LIMIT_PER_MINUTE=1000`); returns `429 Too Many Requests` with `Retry-After` header.
  - **Validation**: Strict Pydantic v2 validation:
    - `timestamp`: Timezone-aware UTC ISO 8601 (max 5 min in future, max 365 days in past).
    - `source_ip` / `destination_ip`: Validated IPv4 / IPv6 via standard library `ipaddress` without DNS lookups.
    - `destination_port`: Integer `0` to `65535`.
    - `severity`: Controlled enum (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
    - `source_type`: Controlled enum (`generic`, `syslog`, `application`, `web`, `linux`, `windows`, `firewall`, `authentication`, `network`, `cloud`, `custom`).
    - `raw_payload`: Verbatim raw JSON object preserved without mutation.
  - **Response Semantics**:
    - Initial ingestion: `201 Created` with `data.status = "ingested"`.
    - Idempotent replay: `200 OK` with `data.status = "duplicate"` and original `event_id` and `ingested_at`.
- `GET /api/v1/events/{id}` - Retrieve a normalized security event by UUID.
  - **Auth**: Required (`events.read` permission; accessible to `ADMIN` and `ANALYST`. `VIEWER` receives `403 Forbidden`).
  - **Responses**: `200 OK` with canonical `EventResponse` (including `outcome`, `normalization_status`, `parser_name`, `attributes`, etc.), `404 Not Found` if nonexistent.
- `POST /api/v1/events/{id}/normalize` - Reprocess normalization for a single security event.
  - **Auth**: Required (`events.normalize` permission; accessible to `ADMIN` and `ANALYST`, `403 Forbidden` for `VIEWER`).
  - **Behavior**: Re-evaluates the preserved `raw_payload` against registered parsers, updates canonical fields, and emits audit event `EVENT_NORMALIZATION_REPROCESSED`.
  - **Responses**: `200 OK` with re-normalized `EventResponse`, `404 Not Found` if nonexistent.
- `POST /api/v1/events/{id}/detect` - Manually evaluate detection rules on an event.
  - **Auth**: Required (`detections.evaluate` permission; accessible to `ADMIN` and `ANALYST`, `403 Forbidden` for `VIEWER`).
  - **Behavior**: Evaluates all applicable rules in the active rule registry, creates/deduplicates alerts, links evidence, and emits audit event `EVENT_DETECTION_EVALUATED`.
  - **Responses**: `200 OK` with `DetectionEvaluationResponse`, `404 Not Found` if nonexistent.
- `GET /api/v1/events` - Query normalized security events (paginated, multi-filter).

### Alerts (`/api/v1/alerts`)
- `GET /api/v1/alerts` - List alerts (filtered by severity, status, rule, source IP, username).
  - **Auth**: Required (`alerts.read` permission; accessible to `ADMIN`, `ANALYST`, and `VIEWER`).
  - **Query Params**: `page` (default 1), `limit` (default 50, max 100), `rule_id`, `severity`, `status`, `source_ip`, `username`.
  - **Responses**: `200 OK` with paginated `AlertListResponse`.
- `GET /api/v1/alerts/{id}` - Retrieve alert details and linked triggering evidence events.
  - **Auth**: Required (`alerts.read` permission; accessible to `ADMIN`, `ANALYST`, and `VIEWER`).
  - **Responses**: `200 OK` with `AlertDetailResponse` enclosing constituent `evidence_events` and `evidence_event_ids`, `404 Not Found` if nonexistent.
- `PATCH /api/v1/alerts/{id}/status` - Update alert status (`OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).

### Incidents (`/api/v1/incidents`)
- `POST /api/v1/incidents` - Create a new incident case file.
  - **Auth**: Required (`incidents.create` permission; granted to `ADMIN` and `ANALYST`, `403 Forbidden` for `VIEWER`).
  - **Payload**: `IncidentCreateRequest` (`title` [3-255 chars], `description`, `severity` [`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`], `priority` [`LOW`, `MEDIUM`, `HIGH`, `URGENT`], `assigned_to_user_id` [optional UUID], `alert_ids` [optional UUID list], `event_ids` [optional UUID list]).
  - **Behavior**: Atomically allocates unique ticket identifier `incident_id` (`INC-YYYY-NNNNNN`), associates initial alerts and events, attributes creator to authenticated user, records `INCIDENT_CREATE` audit log.
  - **Responses**: `201 Created` with `IncidentDetailResponse`.
- `GET /api/v1/incidents` - Search and filter incident cases.
  - **Auth**: Required (`incidents.read` permission; accessible to `ADMIN`, `ANALYST`, and `VIEWER`).
  - **Query Parameters**: `status`, `severity`, `priority`, `assigned_to_user_id`, `created_by_user_id`, `search` (case-insensitive substring on title, description, or incident_id), `page` (default 1), `limit` (default 50, max 100).
  - **Responses**: `200 OK` with `IncidentListResponse` (items summarized with counts of linked alerts, events, and notes).
- `GET /api/v1/incidents/{incident_id}` - Retrieve complete incident details.
  - **Auth**: Required (`incidents.read` permission; accessible to `ADMIN`, `ANALYST`, and `VIEWER`).
  - **Path Parameter**: `incident_id` accepts either human-readable `incident_id` (`INC-2026-000001`) or internal database `UUID`.
  - **Responses**: `200 OK` with `IncidentDetailResponse` (enclosing linked alerts with evidence counts, linked direct events with timestamps and source types, and investigation notes), `404 Not Found` if nonexistent.
- `PATCH /api/v1/incidents/{incident_id}` - Update incident metadata.
  - **Auth**: Required (`incidents.update` permission; granted to `ADMIN` and `ANALYST`, `403 Forbidden` for `VIEWER`).
  - **Payload**: `IncidentUpdateRequest` (optional `title`, `description`, `severity`, `priority`).
  - **Responses**: `200 OK` with updated `IncidentDetailResponse`, `404 Not Found` if nonexistent.
- `POST /api/v1/incidents/{incident_id}/status` - Transition incident lifecycle status.
  - **Auth**: Required (`incidents.update` for `IN_PROGRESS`/`RESOLVED`/`REOPENED`; `incidents.close` for `CLOSED`).
  - **Payload**: `IncidentStatusTransitionRequest` (`status` [`IN_PROGRESS`, `RESOLVED`, `CLOSED`, `REOPENED`], optional `resolution_category` [`TRUE_POSITIVE_BENIGN`, `TRUE_POSITIVE_MALICIOUS`, `FALSE_POSITIVE`, `DUPLICATE`, `OTHER`], optional `resolution_notes`, optional `reopen_reason`).
  - **Validation & Rules**:
    - Valid state transitions enforced: `OPEN -> IN_PROGRESS`, `IN_PROGRESS -> RESOLVED`, `IN_PROGRESS -> OPEN`, `RESOLVED -> CLOSED`, `RESOLVED -> REOPENED`, `CLOSED -> REOPENED`, `REOPENED -> IN_PROGRESS`, `REOPENED -> RESOLVED`.
    - `RESOLVED` requires both `resolution_category` and non-empty `resolution_notes` (422 if missing).
    - `CLOSED` requires `incidents.close` permission (403 if unauthorized) and sets `closed_at` and `closed_by_user_id`.
    - `REOPENED` requires non-empty `reopen_reason` (422 if missing).
  - **Responses**: `200 OK` with `IncidentDetailResponse`, `400 Bad Request` on invalid state transition.
- `POST /api/v1/incidents/{incident_id}/assign` - Assign or reassign incident owner.
  - **Auth**: Required (`incidents.update` permission; granted to `ADMIN` and `ANALYST`).
  - **Payload**: `IncidentAssignRequest` (`assigned_to_user_id` [UUID or null]).
  - **Behavior**: Validates assignee is an active user (404 if invalid/inactive). Automatically advances `OPEN` incidents to `IN_PROGRESS`. Sets `assigned_to_user_id = null` when unassigned.
  - **Responses**: `200 OK` with `IncidentDetailResponse`.
- `POST /api/v1/incidents/{incident_id}/alerts` - Correlate security alert with incident.
  - **Auth**: Required (`incidents.update` permission).
  - **Payload**: `IncidentAlertAttachRequest` (`alert_id` [UUID]).
  - **Responses**: `201 Created` with `IncidentAlertSummaryResponse`, `404 Not Found` if incident or alert missing, `409 Conflict` if alert already linked.
- `DELETE /api/v1/incidents/{incident_id}/alerts/{alert_id}` - Detach alert from incident.
  - **Auth**: Required (`incidents.update` permission).
  - **Responses**: `200 OK`, `404 Not Found` if correlation does not exist.
- `POST /api/v1/incidents/{incident_id}/events` - Link raw event directly to incident as evidence.
  - **Auth**: Required (`incidents.update` permission).
  - **Payload**: `IncidentEventAttachRequest` (`event_id` [UUID]).
  - **Behavior**: Creates immutable evidence linkage (`ForeignKey("events.id", ondelete="RESTRICT")`).
  - **Responses**: `201 Created` with `IncidentEventSummaryResponse`, `404 Not Found` if incident or event missing, `409 Conflict` if event already linked.
- `DELETE /api/v1/incidents/{incident_id}/events/{event_id}` - Detach direct event evidence from incident.
  - **Auth**: Required (`incidents.update` permission).
  - **Responses**: `200 OK`, `404 Not Found` if link does not exist.
- `POST /api/v1/incidents/{incident_id}/notes` - Add analyst investigation note.
  - **Auth**: Required (`incidents.update` permission).
  - **Payload**: `IncidentNoteCreateRequest` (`content` string between 1 and 10,000 characters).
  - **Behavior**: Note author is strictly derived from authenticated session (`current_user.id`). Emits `INCIDENT_NOTE_CREATE` audit log with note body redacted for privacy.
  - **Responses**: `201 Created` with `IncidentNoteResponse`.
- `GET /api/v1/incidents/{incident_id}/timeline` - Unified investigation timeline.
  - **Auth**: Required (`incidents.read` permission).
  - **Behavior**: Aggregates alerts, direct evidence events, notes, assignments, and status transitions in chronological order. Explicitly distinguishes `occurred_at` (telemetry occurrence timestamp) from `action_at` (SOC investigation timestamp).
  - **Responses**: `200 OK` with `IncidentTimelineResponse`.

### Detection Rules (`/api/v1/rules`)
- `GET /api/v1/rules` - List all detection rules.
- `GET /api/v1/rules/{id}` - Retrieve detection rule configuration.
- `POST /api/v1/rules` - Create a new custom detection rule (`ADMIN` only).
- `PATCH /api/v1/rules/{id}` - Update rule status (enable/disable), threshold, or window.

### User Management (`/api/v1/users`)
- `GET /api/v1/users` - List users (`ADMIN` only).
- `POST /api/v1/users` - Create user and assign roles (`ADMIN` only).
- `GET /api/v1/users/{id}` - Retrieve user details (`ADMIN` only).
- `PATCH /api/v1/users/{id}` - Update user status or roles (`ADMIN` only).

### Audit Logs (`/api/v1/audit`)
- `GET /api/v1/audit` - Inspect append-only audit trail records (`ADMIN` or `ANALYST` with `audit.read`).

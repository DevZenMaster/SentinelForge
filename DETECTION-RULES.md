# SentinelForge Detection Rules Specification

## Overview

Detection engineering in SentinelForge relies on **deterministic, rule-based state evaluation** operating on normalized event streams and indexed sliding time windows. Detection logic is completely separated from user interface layers and decoupled from probabilistic models.

---

## Initial Core Rule Catalog

### RULE-001: Brute Force Login
- **Rule ID**: `RULE-001`
- **Name**: Brute Force Login
- **Description**: Detects repeated authentication failures originating from a single source IP address within a compressed time window, indicating an automated password guessing or credential brute-force attack.
- **Severity**: `HIGH`
- **Target Event Type**: `authentication`
- **Target Action**: `login_failed`
- **Condition**:
  - `COUNT(events) >= 5`
  - `GROUP BY source_ip`
  - `TIME_WINDOW = 300 seconds (5 minutes)`
- **Alert Title**: "Brute Force Authentication Attempt from {source_ip}"
- **Alert Status on Creation**: `OPEN`

---

### RULE-002: Account Attack
- **Rule ID**: `RULE-002`
- **Name**: Targeted Account Password Spray
- **Description**: Detects a high volume of failed authentication attempts against a specific username regardless of source IP variation, indicating targeted credential stuffing or account lock attack.
- **Severity**: `HIGH`
- **Target Event Type**: `authentication`
- **Target Action**: `login_failed`
- **Condition**:
  - `COUNT(events) >= 10`
  - `GROUP BY username`
  - `TIME_WINDOW = 600 seconds (10 minutes)`
- **Alert Title**: "Targeted Account Attack Against User {username}"
- **Alert Status on Creation**: `OPEN`

---

### RULE-003: Suspicious Successful Login
- **Rule ID**: `RULE-003`
- **Name**: Suspicious Login Following Failures
- **Description**: Detects an authentication success preceded by multiple authentication failures from the same source IP within a short sliding window, signaling a potentially successful brute-force or credential compromise.
- **Severity**: `HIGH`
- **Target Event Type**: `authentication`
- **Target Action**: `login_success`
- **Condition**:
  - Triggering event: `action == 'login_success'`
  - Window check: `COUNT(login_failed events) >= 3` from identical `source_ip` within the preceding 600 seconds (10 minutes)
- **Alert Title**: "Successful Authentication from {source_ip} Following Failures"
- **Alert Status on Creation**: `OPEN`

---

### RULE-004: HTTP Authentication Abuse
- **Rule ID**: `RULE-004`
- **Name**: HTTP Authentication Abuse
- **Description**: Detects repeated HTTP 401 Unauthorized responses emitted by web application logs from a single client IP, indicating API token brute-force or unauthorized web endpoint enumeration.
- **Severity**: `MEDIUM`
- **Target Event Type**: `web`
- **Target Action**: `http_401`
- **Condition**:
  - `COUNT(events) >= 15`
  - `GROUP BY source_ip`
  - `TIME_WINDOW = 300 seconds (5 minutes)`
- **Alert Title**: "Excessive HTTP 401 Unauthorized from {source_ip}"
- **Alert Status on Creation**: `OPEN`

---

### RULE-005: Port Scan Pattern
- **Rule ID**: `RULE-005`
- **Name**: Network Port Scan Pattern
- **Description**: Detects connection attempts from a single source IP targeting multiple distinct destination ports within a short period, characteristic of reconnaissance and port scanning tools (e.g. Nmap, Masscan).
- **Severity**: `HIGH`
- **Target Event Type**: `network`
- **Target Action**: `connection_attempt`
- **Condition**:
  - `COUNT(DISTINCT destination_port) >= 10`
  - `GROUP BY source_ip`
  - `TIME_WINDOW = 120 seconds (2 minutes)`
- **Alert Title**: "Reconnaissance Port Scan Detected from {source_ip}"
- **Alert Status on Creation**: `OPEN`

---

## Detection Rule Data Model Specification

Rules are persisted and managed via the `detection_rules` table supporting versioning and lifecycle tracking:

```sql
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(32) NOT NULL,           -- Stable identifier e.g. RULE-001
    version INTEGER NOT NULL DEFAULT 1,     -- Monotonically incrementing version number
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,          -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    category VARCHAR(32) NOT NULL DEFAULT 'security',
    status VARCHAR(16) NOT NULL DEFAULT 'DRAFT',  -- DRAFT, ACTIVE, DISABLED, DEPRECATED
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    event_type VARCHAR(32) NOT NULL,        -- authentication, web, network, system, etc.
    threshold INTEGER NOT NULL,
    time_window_seconds INTEGER NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}', -- declarative criteria (actions, filters, distinct fields)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    activated_at TIMESTAMPTZ,
    activated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT uq_detection_rules_rule_id_version UNIQUE (rule_id, version)
);

-- Partial unique index guaranteeing at most ONE active version per rule_id
CREATE UNIQUE INDEX uq_detection_rules_rule_id_active ON detection_rules (rule_id) WHERE status = 'ACTIVE';
```

---

## Rule Lifecycle & State Machine (Phase 9)

Detection rules transition through a deterministic server-side state machine:

```text
       ┌────────┐
       │ DRAFT  │
       └───┬─┬──┘
           │ └─────────────────────────┐
           ▼                           │
      ┌─────────┐                      │
 ┌───►│ ACTIVE  │                      │
 │    └───┬─┬───┘                      │
 │        │ │                          │
 │        ▼ ▼                          ▼
 │   ┌──────────┐               ┌────────────┐
 └───┤ DISABLED │──────────────►│ DEPRECATED │ (Terminal)
     └──────────┘               └────────────┘
```

- **DRAFT**: Newly authored rule definitions or revision drafts. Not evaluated by detection engine. Editable.
- **ACTIVE**: Authoritative production version. Evaluated by engine. Strictly immutable. Max 1 active version per `rule_id`.
- **DISABLED**: Temporarily deactivated rule version. Not evaluated by detection engine. Strictly immutable.
- **DEPRECATED**: Permanently retired rule version. Terminal state — cannot be reactivated. Strictly immutable.

---

## Strict Rule Immutability & Versioning

- **Immutable Published Versions**: Once a rule reaches `ACTIVE`, `DISABLED`, or `DEPRECATED` status, its conditions, thresholds, and detection logic cannot be modified in place.
- **Version Branching**: To modify an existing rule, analysts create a new version (`vN+1`) via `POST /api/v1/detection-rules/{rule_id}/versions`, which starts as `DRAFT`.
- **Historical Alert Traceability**: Historical alerts retain immutable references to the exact `rule_id` and `rule_version` that triggered them. Activating a newer version never rewrites historical records.

---

## Structured Declarative Condition Schema & Validation

Arbitrary code, eval, exec, and raw SQL execution are strictly prohibited. Rule logic is represented as structured JSON data:

- **Supported Operators**: `equals`, `not_equals`, `greater_than`, `greater_than_or_equal`, `less_than`, `less_than_or_equal`, `contains`, `starts_with`, `ends_with`, `in`, `distinct_count`.
- **Supported Fields**: `action`, `source_ip`, `destination_ip`, `username`, `destination_port`, `source_port`, `source`, `source_type`, `outcome`, `attributes.*`.
- **Supported Group By Keys**: `source_ip`, `destination_ip`, `username`.
- **Aggregations**: `count` (default) or `distinct_count` (requires `distinct_field`).
- **Resource Bounds**:
  - `1 <= threshold <= 10000`
  - `10 <= time_window_seconds <= 86400`
  - Maximum 10 filters per rule
  - Max string value length: 255 characters
  - Max `in` list items: 100 items

---

## Detection Engineering REST APIs (`/api/v1/detection-rules`)

| Method | Path | Permission | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/detection-rules` | `detection_rules.read` | List detection rules (paginated, filterable) |
| `POST` | `/api/v1/detection-rules` | `detection_rules.create` | Author a new detection rule (starts as DRAFT v1) |
| `POST` | `/api/v1/detection-rules/validate` | `detection_rules.read` | Dry-run validation of rule definition |
| `GET` | `/api/v1/detection-rules/{rule_id}` | `detection_rules.read` | Get active or latest version of rule |
| `GET` | `/api/v1/detection-rules/{rule_id}/versions` | `detection_rules.read` | Get version history for rule |
| `POST` | `/api/v1/detection-rules/{rule_id}/versions` | `detection_rules.create` | Author new version draft (vN+1) |
| `GET` | `/api/v1/detection-rules/{rule_id}/versions/{v}` | `detection_rules.read` | Get exact version definition |
| `PUT` | `/api/v1/detection-rules/{rule_id}/versions/{v}` | `detection_rules.update` | Modify DRAFT version definition |
| `POST` | `/api/v1/detection-rules/{rule_id}/versions/{v}/activate` | `detection_rules.activate` | Promote version to ACTIVE |
| `POST` | `/api/v1/detection-rules/{rule_id}/versions/{v}/disable` | `detection_rules.disable` | Deactivate ACTIVE version to DISABLED |
| `POST` | `/api/v1/detection-rules/{rule_id}/versions/{v}/deprecate` | `detection_rules.deprecate` | Retire version to DEPRECATED |

---

## Alert Evidence Preservation (`alert_events`)

To ensure analyst transparency and forensic auditability, no alert is created without preserving its supporting evidence. Every event that satisfied the rule conditions during the trigger window is linked via the `alert_events` join table:

```text
Alert [ID: e7a1-...] (RULE-001: Brute Force Login)
  ├── Evidence Event 1 (10:00:01 - 192.168.1.50 - login_failed - admin)
  ├── Evidence Event 2 (10:00:15 - 192.168.1.50 - login_failed - admin)
  ├── Evidence Event 3 (10:00:32 - 192.168.1.50 - login_failed - admin)
  ├── Evidence Event 4 (10:00:48 - 192.168.1.50 - login_failed - admin)
  └── Evidence Event 5 (10:01:02 - 192.168.1.50 - login_failed - admin)
```

---

## Alert Deduplication & Coalescing Semantics

To prevent alert fatigue and storm cascades during ongoing attacks, SentinelForge enforces deterministic alert deduplication backed by a unique database constraint (`uq_alerts_dedup_key`):

```text
dedup_key = f"{rule_id}:{correlation_key}:{bucket}"
where bucket = int(event_timestamp.timestamp() // window_seconds)
```

- When an attack pattern persists within an active sliding time bucket, subsequent matching events update the existing alert (`observed_count`, `last_seen`, `evidence`) and append new constituent records to `alert_events`.
- No duplicate alert records are generated within the same time bucket.
- Concurrency races across worker threads are resolved via database unique constraint exception handling and savepoint fallbacks.

---

## Detection Execution Engine & RBAC

- **Pipeline Trigger**: Evaluated synchronously upon event normalization during ingestion (`POST /api/v1/events`) and reprocessing (`POST /api/v1/events/{id}/normalize`).
- **Manual Evaluation**: Analysts and Administrators can trigger on-demand evaluation via `POST /api/v1/events/{id}/detect` (requires `detections.evaluate`).
- **Alert Retrieval**: Analysts and Viewers inspect alerts via `GET /api/v1/alerts` and `GET /api/v1/alerts/{id}` (requires `alerts.read`).
- **Fault Isolation**: Each rule executes in an isolated try-except block. Runtime failures in any individual rule are logged with full structured context and never prevent other rules or event persistence from completing.


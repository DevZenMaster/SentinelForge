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

Rules are persisted and managed via the `detection_rules` table:

```sql
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(32) UNIQUE NOT NULL,
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL,          -- CRITICAL, HIGH, MEDIUM, LOW, INFO
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    event_type VARCHAR(32) NOT NULL,        -- authentication, web, network, system, etc.
    threshold INTEGER NOT NULL,
    time_window_seconds INTEGER NOT NULL,
    conditions JSONB NOT NULL DEFAULT '{}', -- declarative criteria (actions, filters, distinct fields)
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

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

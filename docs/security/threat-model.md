# SentinelForge Threat Model Documentation

See root [THREAT-MODEL.md](../../THREAT-MODEL.md) for the complete project-wide STRIDE Threat Matrix, mitigations, and residual risks.

---

## Phase 2: Authentication & RBAC Security Architecture

### 1. Server-Managed Session Security
* **No Client-Stored Tokens / JWTs**: SentinelForge deliberately rejects browser-accessible JWTs and `localStorage` persistence to mitigate token exfiltration via XSS.
* **Opaque Session Tokens**: Generated using cryptographically secure entropy (`secrets.token_urlsafe(32)` providing 256 bits of entropy).
* **Database Token Hashing**: The database **never** stores raw session tokens. Tokens are hashed using SHA-256 (`session_token_hash`) prior to storage. If database backups or replicas are compromised, attackers cannot reconstruct active user session cookies.
* **Cookie Defenses**:
  - `HttpOnly`: Prevents client-side scripts from reading the session cookie.
  - `SameSite=Lax`: Prevents ambient transmission in standard cross-site requests.
  - `Secure`: Transmitted strictly over HTTPS in production environments.
  - `Path=/`: Restricts cookie scope to the SentinelForge origin.

### 2. Password Storage & Anti-Enumeration Controls
* **Argon2id Password Hashing (RFC 9106)**:
  - `time_cost = 3`
  - `memory_cost = 65536 KiB` (64 MiB)
  - `parallelism = 4`
  - Memory-hard algorithm resistant to GPU-accelerated cracking and ASIC attacks.
* **Constant-Time Verification on Unknown Accounts**:
  - To defeat account enumeration via response-timing discrepancies, authentication attempts targeting non-existent or inactive usernames execute an Argon2id verification cycle against a deterministic precomputed dummy hash (`_DUMMY_HASH`).
  - Responses return generic `401 Unauthorized` (`"Invalid username or password."`) regardless of whether the identifier exists.

### 3. Role-Based Access Control (RBAC) Matrix
* **Normalized Database-Backed RBAC**: Permissions are assigned to Roles, and Roles are assigned to Users via associative tables (`role_permissions`, `user_roles`).
* **Zero Trust in Client Claims**: Authorization decisions are computed entirely server-side from PostgreSQL via `resolve_user_capabilities()`.
* **Persona Boundaries**:
  - `ADMIN`: Full access to user management, detection rule lifecycle, alert handling, incident management, and audit inspection.
  - `ANALYST`: Triage alerts, author/tune detection rules, create/update incidents, search events, inspect audit logs. No access to user creation/deletion or rule deletion.
  - `VIEWER`: Read-only access to events, alerts, incidents, and audit trails. No mutate or create actions permitted.
* **FastAPI Dependency Guards**: `require_permission(perm)` and `require_role(role)` evaluate server-side context; unauthenticated requests receive `401`, while authenticated requests lacking permissions receive `403 Forbidden`.

### 4. Defense-in-Depth CSRF Defense
* **SameSite Cookie Isolation**: Mitigates automated ambient credential inclusion.
* **State-Changing Custom Header & Origin Verification**: `CSRFProtectionMiddleware` intercepts unsafe methods (`POST`, `PUT`, `PATCH`, `DELETE`) with an active session cookie:
  - Validates the presence of an anti-CSRF custom header (`X-Requested-With`, `X-CSRF-Token`) or `application/json` payload structure.
  - Validates `Origin` and `Referer` headers against configured `BACKEND_CORS_ORIGINS`. Untrusted origins receive `403 CSRF_ERROR`.

### 5. In-Memory Sliding-Window Rate Limiting
* `/api/v1/auth/login` is protected by a thread-safe sliding window limiter.
* Tracks both source IP (`auth:ip:<ip>`) and targeted identifier (`auth:user:<username>`).
* Exceeded requests return `429 Too Many Requests` with `Retry-After` headers.

### 6. Append-Only Security Audit Trail
* Authentication and authorization events write immutable audit records to `audit_logs`.
* Actions captured: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`.
* Audit records capture `actor_user_id`, `action`, `resource_type`, `resource_id`, `source_ip`, `user_agent`, `request_id`, and `timestamp`.
* **No Credential Storage**: Audit trails strictly redact and exclude passwords, session tokens, and token hashes.

### 7. Detection Engine Security Controls (Phase 5)
* **Fault-Isolated Execution**: Each detection rule executes inside a dedicated exception handling boundary. Runtime errors, divide-by-zero, or data irregularities in a single rule cannot crash the detection engine, corrupt sibling rule evaluation, or roll back ingested events.
* **Bounded Query Resource Protection**: Historical sliding-window queries enforce a hard limit (`max_window_events = 1000`) and use composite temporal database indexes (`(source_ip, timestamp)`, `(username, timestamp)`, `(event_type, action, timestamp)`) to prevent algorithmic complexity attacks or memory exhaustion from event flooding.
* **SQL Injection Immunity**: All temporal and entity filters in the detection context use SQLAlchemy parameterized bind expressions.
* **Deduplication Storm Defense**: Deterministic hashing (`rule_id:correlation_key:bucket`) backed by a PostgreSQL unique constraint (`uq_alerts_dedup_key`) stops alert storming by coalescing repeated triggering events into an existing alert.
* **Forensic Evidence Immutability**: All evidence associations (`alert_events`) use strict foreign key constraints (`ForeignKey("events.id", ondelete="RESTRICT")`), ensuring evidence logs cannot be deleted while referenced by active alerts. Ingested `raw_payload` data remains strictly read-only.
* **Granular RBAC**: Alert search and inspection require `alerts.read` (accessible to `ADMIN`, `ANALYST`, and `VIEWER`); manual evaluation requires `detections.evaluate` (`ADMIN` and `ANALYST` only, `VIEWER` receives `403 Forbidden`).

### 8. Incident Management Security Controls (Phase 6)
* **Dedicated Case Closure Privilege Separation**: Closing an incident (`RESOLVED -> CLOSED`) is decoupled from general triage updates and restricted to `incidents.close` (`ADMIN` only by default). Analysts cannot unilaterally close cases without requisite privilege.
* **Strict State Machine Validation**: State changes are enforced server-side. Arbitrary or cyclical jumps (e.g., `OPEN -> CLOSED` or `RESOLVED -> IN_PROGRESS` without reopening) are rejected with `400 Bad Request`.
* **Mandatory Resolution & Reopen Rationale**: Transitioning to `RESOLVED` requires a verified `resolution_category` and non-empty `resolution_notes`. Transitioning to `REOPENED` requires a non-empty `reopen_reason`. This mitigates unverified ticket closure and undocumented reopening.
* **Referential Integrity & Evidence Deletion Protection**: Direct event linkages in `incident_events` are enforced with `ForeignKey("events.id", ondelete="RESTRICT")`. Attempting to delete an ingested security event that is referenced as evidence in an incident is strictly prevented at the database level.
* **Analyst Identity Attribution & Note Privacy**: Notes attached to incidents derive the author identity strictly from the verified server session (`current_user.id`), preventing impersonation of senior analysts. While note creation actions are logged to `audit_logs` (`INCIDENT_NOTE_CREATE`), note content is omitted from audit log payloads to prevent accidental leakage of sensitive investigative details or analyst commentary.
* **Dual-Timestamp Timeline Integrity**: The timeline engine strictly separates telemetric occurrence timestamps (`occurred_at`) from operational triage and analyst action timestamps (`action_at`), preventing spoofing of incident chronology.
* **Granular RBAC Enforcements**:
  - `incidents.read`: Granted to `ADMIN`, `ANALYST`, and `VIEWER`.
  - `incidents.create`: Granted to `ADMIN` and `ANALYST`. `VIEWER` receives `403 Forbidden`.
  - `incidents.update`: Granted to `ADMIN` and `ANALYST`. `VIEWER` receives `403 Forbidden`.
  - `incidents.close`: Granted to `ADMIN`. `ANALYST` and `VIEWER` receive `403 Forbidden`.

### 9. Acknowledged Residual Risks
* **Single-Process Memory Limiting**: In-memory rate limiting is process-bound. Distributed clusters in subsequent phases will integrate Redis for multi-node sliding window state.
* **Database Admin Access**: A compromised PostgreSQL superuser could directly mutate database records, bypassing API-level immutability. Addressed via database-level privilege separation in production.
* **Subjective Analyst Triage**: Resolution categorizations depend on analyst judgment; mitigated by mandatory resolution notes and peer audit trails.


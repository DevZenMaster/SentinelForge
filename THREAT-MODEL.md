# SentinelForge Threat Model

## 1. Threat Modeling Methodology

SentinelForge employs the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) along with qualitative risk assessment:
- **Likelihood**: Low, Medium, High
- **Impact**: Low, Medium, High, Critical
- **Risk Level**: Qualitative composite (Critical, High, Medium, Low)

> [!IMPORTANT]
> Defensive engineering operates under realistic security assumptions. Zero risk does not exist. All mitigations are paired with acknowledged residual risks.

---

## 2. Threat Matrix

| # | Threat | Attack Surface | Impact | Likelihood | Risk | Mitigation | Residual Risk |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T-01** | **Credential Stuffing / Password Brute-Force** | `/api/v1/auth/login` | High | High | **High** | Argon2id password hashing, IP and username rate limiting, account lockout thresholds. | Distributed botnets rotating IPs could slowly test common passwords below rate thresholds. |
| **T-02** | **Session Hijacking / Replay** | Session Bearer Tokens / Cookies | High | Medium | **High** | Short token TTL, cryptographic signature (HS256/RS256), DB-tracked session revocation, Secure/HttpOnly/SameSite cookies. | Compromise of client endpoint or memory dump of browser could expose active token before expiration. |
| **T-03** | **Privilege Escalation** | Admin/Analyst Endpoints | Critical | Medium | **High** | Strict server-side RBAC dependencies (`require_permission`), role hierarchy, rejection of client role claims. | Logic bugs in newly added route decorators if not covered by regression tests. |
| **T-04** | **Insecure Direct Object Reference (IDOR)** | `/api/v1/alerts/{id}`, `/api/v1/incidents/{id}` | Medium | Medium | **Medium** | UUID primary keys instead of sequential integers, ownership & tenant/RBAC validation on fetch. | Knowing a UUID allows read access if the user holds generic `alerts.read` permission. |
| **T-05** | **SQL Injection** | Dynamic queries & event search filters | Critical | Low | **Medium** | 100% SQLAlchemy 2.0 ORM parameterized statements; strict typing; no raw string query concatenation. | Developer error if custom raw SQL queries are introduced in future extensions. |
| **T-06** | **Stored / Reflected XSS** | Analyst Dashboard (Event viewer, notes) | High | Medium | **Medium** | React default string escaping, Content Security Policy (CSP), HTML sanitization on analyst markdown notes. | DOM-based injection if third-party chart libraries improperly parse unsanitized SVG strings. |
| **T-07** | **Cross-Site Request Forgery (CSRF)** | State-changing API endpoints | Medium | Low | **Low** | Strict `SameSite=Lax/Strict` cookies and `Authorization: Bearer` token pattern immune to standard ambient browser CSRF. | Cross-origin vulnerabilities if CORS is misconfigured with `Access-Control-Allow-Origin: *`. |
| **T-08** | **Rate Limit Abuse / API DoS** | `/api/v1/events`, `/api/v1/auth/*` | High | High | **High** | Ingestion payload size limit (`MAX_EVENT_PAYLOAD_BYTES=1048576`, returns 413), sliding-window rate limiters (`EVENTS_RATE_LIMIT_PER_MINUTE=1000` with `Retry-After`), request timeouts. | Coordinated volumetric DDoS saturating the network link before reaching the application layer. |
| **T-09** | **Log Injection (CRLF / Log Tampering)** | Ingestion payloads, correlation headers | Medium | Medium | **Medium** | Incoming `X-Request-ID` sanitized against `^[a-zA-Z0-9_\-:.]{1,64}$`; structured JSON logging with raw payloads excluded from operational and audit logs. | Downstream log collector parsing errors if raw logs are inspected outside structured formats. |
| **T-10** | **Malicious / Corrupt Event Payloads** | Ingestion endpoint (`/api/v1/events`) | Medium | High | **Medium** | Strict Pydantic v2 validation (`extra='forbid'`, IP validation via `ipaddress` without DNS lookups, timezone-aware UTC timestamps with past/future bounds, port range 0-65535, controlled severity enum). | Syntactically valid events containing deceptive semantic indicators. |
| **T-11** | **Unauthorized Event Ingestion** | Ingestion endpoint (`/api/v1/events`) | High | High | **High** | Requires authenticated session/Bearer token possessing `events.create` permission (`ADMIN` or `ANALYST`); `VIEWER` strictly denied with `403 Forbidden`; anonymous access denied with `401 Unauthorized`. | Compromise of an active analyst session allows an attacker to inject fraudulent events. |
| **T-12** | **Audit Log Tampering** | Audit log database table | High | Low | **Medium** | Append-only database table; absence of `UPDATE` or `DELETE` API endpoints for audit records; RBAC restrictions. | A compromised PostgreSQL superuser could directly mutate database records bypassing the API layer. |
| **T-13** | **Sensitive Data Disclosure** | API responses, stack traces | High | Low | **Medium** | Global exception handlers returning standardized error envelopes without stack traces; Pydantic response models excluding password hashes. | Verbose debug logging accidentally left enabled in production environment. |
| **T-14** | **Container / Host Compromise** | Docker container runtimes | Critical | Low | **Medium** | Non-root container execution (`USER nonroot`), minimal base images (Alpine/Distroless), read-only root filesystems where practical. | Zero-day kernel container escape vulnerabilities. |
| **T-15** | **Supply Chain Vulnerabilities** | Python/Node dependencies | High | Medium | **High** | Automated dependency scanning (`pip-audit`, Trivy, Dependabot), pinning exact versions, minimal dependency footprints. | Zero-day vulnerabilities in transitive dependencies prior to CVE disclosure. |
| **T-16** | **Secret Exposure** | Source control & Git history | Critical | Low | **Medium** | Strict `.gitignore`, pre-commit hooks, automated Gitleaks scanning in CI pipeline, zero hardcoded secrets. | Accidental commit of an active API key or `.env` file if developers bypass pre-commit hooks. |
| **T-17** | **Event Duplication / Replay Attacks** | Ingestion endpoint (`/api/v1/events`) | Medium | High | **Medium** | Idempotency enforced via `external_event_id` and `Idempotency-Key` header; database unique index; in-process lock preventing race conditions; duplicate returns 200 OK duplicate without re-inserting. | High-frequency client retries without idempotency keys create separate event entries. |

---

## 3. Threat Modeling Review & Maintenance

This document must be re-evaluated:
1. When introducing new ingestion protocols (e.g., Syslog UDP/TCP, Kafka).
2. Prior to any major version release.
3. Following any reported security incident or vulnerability disclosure.

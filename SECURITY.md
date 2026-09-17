# Security Policy

## Reporting a Vulnerability

SentinelForge is an educational security portfolio project. However, security reports and vulnerability disclosures are treated with the highest priority and evaluated under standard Coordinated Vulnerability Disclosure (CVD) principles.

If you discover a potential vulnerability in this repository:
1. **Do not** create a public GitHub issue.
2. Please submit your finding directly to the project maintainers via email or private security advisory.
3. Include:
   - Vulnerability class (e.g. Broken Object Level Authorization, SQL Injection, Authentication Bypass)
   - Step-by-step reproduction instructions or a Proof of Concept (PoC)
   - Affected versions and endpoints
   - Potential impact and recommended remediation

---

## Security Architecture & Guiding Principles

### 1. Zero Trust Input Handling
All incoming network inputs—whether on event ingestion endpoints (`POST /api/v1/events`), authentication endpoints, or administrative routes—are validated through strict Pydantic schemas. Unrecognized fields are stripped or rejected.

### 2. Cryptographic Rigor
- **Password Hashing**: Uses Argon2id (`argon2-cffi`), the winner of the Password Hashing Competition (PHC), parameterized with memory hardness to mitigate GPU/ASIC-based brute-force attacks. Plaintext passwords are never logged, stored, or echoed.
- **Session Tokens**: JWTs signed with HMAC-SHA256 (or asymmetric algorithms in distributed environments), accompanied by database session tracking to enable immediate server-side revocation on logout or account compromise.

### 3. Server-Side Role-Based Access Control (RBAC)
Client-side role checks are strictly cosmetic. Every sensitive route in the API validates the requesting user's identity, active session status, and specific required permission (`users.read`, `alerts.update`, `rules.create`, etc.) via FastAPI dependency injection guards before executing business logic.

### 4. Injection Defenses
- **SQL Injection**: Prevented by using SQLAlchemy 2.0 ORM with 100% parameterized query construction. Direct string concatenation in queries is forbidden.
- **Cross-Site Scripting (XSS)**: Handled by React/Next.js default context-aware encoding and strict Content Security Policy (CSP) headers.
- **Command Injection**: SentinelForge executes no shell commands or external subprocesses based on user-provided data.

### 5. Append-Only Audit Trail
Security-sensitive mutations (authentication events, rule edits, alert status transitions, incident notes, role changes) trigger an immutable record in the `audit_logs` table. Audit records cannot be altered or purged through standard application endpoints.

### 6. Rate Limiting & Denial of Service Protection
- Authentication routes (`/api/v1/auth/login`) are protected by strict rate limits to defeat credential stuffing and brute-force attacks.
- Ingestion endpoints enforce request body size limits and rate bounds to prevent denial-of-service or database exhaustion.

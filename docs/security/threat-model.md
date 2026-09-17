# SentinelForge Threat Model Documentation

See root [THREAT-MODEL.md](../../THREAT-MODEL.md) for the complete STRIDE Threat Matrix, mitigations, and residual risks.

### Summary of Key Controls
1. **Zero Trust Authentication**: Argon2id password hashing, database-backed session invalidation, strict rate limiting.
2. **Deterministic Detection**: Unambiguous rule triggers without black-box ML inference.
3. **Immutable Auditing**: Append-only audit records tracking user actions, IP addresses, and state changes.
4. **Least Privilege RBAC**: Server-side permission enforcement on all API routes.

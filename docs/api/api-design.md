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
- `POST /api/v1/events` - Ingest a single security event or a batch of events (Max 100 events / 1MB).
- `GET /api/v1/events` - Query normalized security events (paginated, multi-filter).
- `GET /api/v1/events/{id}` - Retrieve details of a specific normalized event.

### Alerts (`/api/v1/alerts`)
- `GET /api/v1/alerts` - List alerts (filtered by severity, status, rule, date range).
- `GET /api/v1/alerts/{id}` - Retrieve alert details and linked triggering evidence events.
- `PATCH /api/v1/alerts/{id}/status` - Update alert status (`OPEN`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`).

### Incidents (`/api/v1/incidents`)
- `POST /api/v1/incidents` - Create a new incident ticket.
- `GET /api/v1/incidents` - List incidents (paginated, filtered by status, assignee, severity).
- `GET /api/v1/incidents/{id}` - Retrieve incident details, grouped alerts, and timeline notes.
- `PATCH /api/v1/incidents/{id}` - Update incident status, assignee, severity, or resolution notes.
- `POST /api/v1/incidents/{id}/alerts` - Associate alerts with an existing incident.

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

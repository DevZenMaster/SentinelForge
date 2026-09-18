# SentinelForge Production Deployment Guide

## 1. Architectural Topology

In a production environment, SentinelForge is deployed behind a dedicated TLS termination reverse proxy:

```text
                  Internet / SOC Network
                             │
                             ▼  (HTTPS Port 443)
                 ┌───────────────────────────┐
                 │  TLS Reverse Proxy / ALB  │
                 │  (Nginx, Caddy, AWS ALB)  │
                 └─────────────┬─────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            │ (HTTP / Host Header)                │ (HTTP /api/* Proxy)
            ▼                                     ▼
  ┌───────────────────┐                 ┌───────────────────┐
  │  Next.js Frontend │                 │   FastAPI Backend │
  │    (Port 3000)    │                 │    (Port 8000)    │
  └───────────────────┘                 └─────────┬─────────┘
                                                  │
                                                  ▼ (TLS Port 5432)
                                        ┌───────────────────┐
                                        │   PostgreSQL 16   │
                                        │ (Encrypted Volume)│
                                        └───────────────────┘
```

---

## 2. Infrastructure Sizing & Prerequisites

| Resource | Minimum | Recommended | Notes |
| :--- | :--- | :--- | :--- |
| **CPU** | 4 Cores | 8+ Cores | Fast JSON parsing & sliding-window rule evaluations |
| **RAM** | 8 GB | 16+ GB | Database shared buffers & in-memory sliding-window caches |
| **Storage** | 100 GB SSD | 500+ GB NVMe | Append-only raw event logs and audit trail storage |
| **OS** | Ubuntu 22.04 LTS / Debian 12 / RHEL 9 | Hardened Linux kernel, non-root container runtimes |
| **Database** | PostgreSQL 16.x | PostgreSQL 16.x with SSL enabled |

---

## 3. Production Configuration Invariants

Before booting the backend in production (`ENVIRONMENT=production`), the application enforces **fail-closed validation**. The process will terminate immediately on startup if any of the following are violated:

1. **`ENVIRONMENT`**: Must be set to `production`.
2. **`DEBUG`**: Must be explicitly set to `False`.
3. **`SECRET_KEY`**: Must be a cryptographically random string of at least 32 characters (e.g., generated via `openssl rand -hex 32`). Default development keys are rejected.
4. **`POSTGRES_PASSWORD`**: Default development passwords (`sentinel_dev_password_change_me`, `postgres`, `password`) are rejected.
5. **`BACKEND_CORS_ORIGINS`**: Wildcard (`*`) is strictly forbidden. Must list explicit internal or corporate origins (e.g. `https://soc.corp.internal`).
6. **`SESSION_COOKIE_SECURE`**: Must be `True` (enforces HTTPS cookie transmission).
7. **`SESSION_COOKIE_HTTPONLY`**: Must be `True` (blocks JavaScript access).
8. **`WEBHOOK_ALLOW_INSECURE_HTTP`**: Must be `False` (blocks plaintext HTTP webhooks).

---

## 4. Reverse Proxy & Edge Hardening (Nginx Reference)

Configure Nginx as the front-facing TLS termination proxy:

```nginx
# /etc/nginx/conf.d/sentinelforge.conf

upstream sentinelforge_web {
    server 127.0.0.1:3000;
    keepalive 32;
}

upstream sentinelforge_api {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name soc.corp.internal;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name soc.corp.internal;

    ssl_certificate /etc/ssl/certs/sentinelforge.crt;
    ssl_certificate_key /etc/ssl/private/sentinelforge.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Edge Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Payload & Buffer Limits
    client_max_body_size 10M;
    client_body_timeout 10s;
    client_header_timeout 10s;

    # Forward API routes
    location /api/ {
        proxy_pass http://sentinelforge_api;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Request-ID $request_id;
    }

    # Forward Web UI routes
    location / {
        proxy_pass http://sentinelforge_web;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 5. Deployment Procedure

### Step 1: Database Migration
Always execute migrations from an authorized maintenance workstation or CI pipeline:
```bash
cd apps/api
export $(cat .env.production | xargs)
./.venv/bin/alembic upgrade head
```

### Step 2: Start API Service
```bash
cd apps/api
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

### Step 3: Start Web Frontend
```bash
cd apps/web
node server.js
```

---

## 6. Pre-Deployment Verification Checklist

- [ ] Production `.env` configured with high-entropy `SECRET_KEY` (>= 32 chars).
- [ ] Database credentials rotated and not using development defaults.
- [ ] `alembic upgrade head` executed cleanly with single current head.
- [ ] Liveness probe `/live` returns HTTP 200.
- [ ] Readiness probe `/ready` returns HTTP 200 with database connected.
- [ ] Health summary `/health` reports `healthy`.
- [ ] HTTPS termination validated with valid TLS certificates.
- [ ] Anti-CSRF and secure cookie attributes (`Secure`, `HttpOnly`, `SameSite=Lax`) verified.
- [ ] Backup verification script (`scripts/verify_backup_integrity.py`) executed against replica.

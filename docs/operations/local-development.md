# Local Development & Operations Guide

## 1. Prerequisites

- **macOS** or **Linux** workstation
- **Git** 2.40+
- **Python 3.11+** (Recommended: Python 3.13 via `/opt/homebrew/bin/python3.13`)
- **Node.js v20+** with `pnpm` (or `npm`)
- **PostgreSQL 16** (local service or Docker container)

---

## 2. Setting Up Backend (`apps/api`)

1. Navigate to the API application directory:
   ```bash
   cd apps/api
   ```

2. Create and activate a Python virtual environment:
   ```bash
   /opt/homebrew/bin/python3.13 -m venv .venv
   source .venv/bin/activate
   ```

3. Upgrade pip and install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp ../../.env.example .env
   # Edit .env to set your PostgreSQL connection details and secret keys
   ```

5. Run database migrations:
   ```bash
   alembic upgrade head
   ```

6. Seed default roles, permissions, and admin user:
   ```bash
   python -m app.scripts.seed
   ```

7. Start the API development server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

The OpenAPI documentation is accessible at `http://127.0.0.1:8000/docs`.

---

## 3. Setting Up Frontend (`apps/web`)

1. Navigate to the web application directory:
   ```bash
   cd apps/web
   ```

2. Install dependencies via `pnpm`:
   ```bash
   pnpm install
   ```

3. Start the Next.js development server:
   ```bash
   pnpm dev
   ```

Access the SOC dashboard at `http://localhost:3000`.

---

## 4. Running Automated Tests

### Backend Tests
```bash
cd apps/api
source .venv/bin/activate
pytest -v
```

### Security Scans
```bash
# Static Application Security Testing (SAST)
bandit -r app/

# Dependency Vulnerability Audit
pip-audit
```

### Frontend Tests
```bash
cd apps/web
pnpm test
pnpm lint
```

---

## 5. Docker Compose Local Deployment

To launch all services with isolated networking and persistent database volume:

```bash
docker compose up -d --build
```

Verify service health:
```bash
docker compose ps
```

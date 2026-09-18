# syntax=docker/dockerfile:1
# Production Dockerfile for SentinelForge API Service
# Hardened multi-stage build, unprivileged non-root execution, minimal attack surface

# Build stage
FROM python:3.13-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY apps/api/pyproject.toml /build/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# Runtime stage
FROM python:3.13-slim AS runner

WORKDIR /app

# Install runtime libpq and curl for container healthcheck probes
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /install /usr/local

# Create dedicated non-root unprivileged service user and group
RUN groupadd -g 10001 sentinelforge && \
    useradd -u 10001 -g sentinelforge -s /sbin/nologin -d /app sentinelforge && \
    mkdir -p /app && \
    chown -R sentinelforge:sentinelforge /app

# Copy application source code, migrations, and entrypoint
COPY --chown=sentinelforge:sentinelforge apps/api/app /app/app
COPY --chown=sentinelforge:sentinelforge apps/api/migrations /app/migrations
COPY --chown=sentinelforge:sentinelforge apps/api/alembic.ini /app/alembic.ini
COPY --chown=sentinelforge:sentinelforge infrastructure/docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

USER sentinelforge:sentinelforge

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    ENVIRONMENT=production

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/live || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

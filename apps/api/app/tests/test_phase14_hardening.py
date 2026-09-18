"""Automated test suite for SentinelForge Phase 14: Hardening & Observability.

Validates:
1. Production configuration fail-closed invariants.
2. Structured logging secret redaction.
3. Request correlation and client IP trusted proxy validation.
4. Database error shielding and error taxonomy envelopes.
5. Root and API health/readiness/liveness probes.
6. Operational metrics collection and RBAC access gating.
7. Stale background delivery reconciliation.
"""

import logging
import uuid
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import Settings, settings, validate_startup_configuration
from app.core.logging import JSONLogFormatter
from app.core.metrics import system_metrics
from app.core.middleware import get_client_ip
from app.core.rbac import ROLE_ADMIN, ROLE_VIEWER
from app.core.security import get_password_hash
from app.db.base import utc_now
from app.main import create_app
from app.models.auth import Role, User, UserRole
from app.models.notification import (
    Integration,
    NotificationDelivery,
    NotificationEvent,
    NotificationPolicy,
)
from app.schemas.notification import DeliveryStatus
from app.services.auth import create_session
from app.services.notifications.delivery import reconcile_stale_deliveries
from app.services.seed import seed_rbac_and_admin

# ============================================================================
# 1. Production Configuration Fail-Closed Tests
# ============================================================================


def test_production_rejects_debug_mode() -> None:
    """Production configuration must fail fast if DEBUG=True."""
    with pytest.raises(ValidationError, match="DEBUG mode must be disabled"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=True,
            SECRET_KEY="super-secret-production-key-32-chars-long!",
            POSTGRES_PASSWORD="secure_prod_password_12345!",
            POSTGRES_USER="sentinelforge",
            POSTGRES_DB="sentinelforge_db",
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            WEBHOOK_ALLOW_INSECURE_HTTP=False,
            BACKEND_CORS_ORIGINS=["https://soc.corp.internal"],
        )


def test_production_rejects_short_secret_key() -> None:
    """Production configuration must fail fast if SECRET_KEY is too short."""
    with pytest.raises(ValidationError, match="SECRET_KEY must be a cryptographically secure"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY="short-secret-key",
            POSTGRES_PASSWORD="secure_prod_password_12345!",
            POSTGRES_USER="sentinelforge",
            POSTGRES_DB="sentinelforge_db",
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            WEBHOOK_ALLOW_INSECURE_HTTP=False,
            BACKEND_CORS_ORIGINS=["https://soc.corp.internal"],
        )


def test_production_rejects_default_database_password() -> None:
    """Production configuration must fail fast if default DB password is used."""
    with pytest.raises(ValidationError, match="Default database password detected"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY="super-secret-production-key-32-chars-long!",
            POSTGRES_PASSWORD="sentinel_dev_password_change_me",
            POSTGRES_USER="sentinelforge",
            POSTGRES_DB="sentinelforge_db",
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            WEBHOOK_ALLOW_INSECURE_HTTP=False,
            BACKEND_CORS_ORIGINS=["https://soc.corp.internal"],
        )


def test_production_rejects_wildcard_cors() -> None:
    """Production configuration must fail fast if CORS origins contain '*'."""
    with pytest.raises(ValidationError, match="Wildcard CORS origin"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY="super-secret-production-key-32-chars-long!",
            POSTGRES_PASSWORD="secure_prod_password_12345!",
            POSTGRES_USER="sentinelforge",
            POSTGRES_DB="sentinelforge_db",
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            WEBHOOK_ALLOW_INSECURE_HTTP=False,
            BACKEND_CORS_ORIGINS=["*"],
        )


def test_production_rejects_insecure_cookie() -> None:
    """Production configuration must fail fast if cookies are not Secure and HttpOnly."""
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE must be True"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY="super-secret-production-key-32-chars-long!",
            POSTGRES_PASSWORD="secure_prod_password_12345!",
            POSTGRES_USER="sentinelforge",
            POSTGRES_DB="sentinelforge_db",
            SESSION_COOKIE_SECURE=False,
            SESSION_COOKIE_HTTPONLY=True,
            WEBHOOK_ALLOW_INSECURE_HTTP=False,
            BACKEND_CORS_ORIGINS=["https://soc.corp.internal"],
        )


def test_production_rejects_insecure_webhook_override() -> None:
    """Production configuration must fail fast if HTTP webhooks are allowed."""
    with pytest.raises(ValidationError, match="WEBHOOK_ALLOW_INSECURE_HTTP must be False"):
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY="super-secret-production-key-32-chars-long!",
            POSTGRES_PASSWORD="secure_prod_password_12345!",
            POSTGRES_USER="sentinelforge",
            POSTGRES_DB="sentinelforge_db",
            SESSION_COOKIE_SECURE=True,
            SESSION_COOKIE_HTTPONLY=True,
            WEBHOOK_ALLOW_INSECURE_HTTP=True,
            BACKEND_CORS_ORIGINS=["https://soc.corp.internal"],
        )


def test_validate_startup_configuration_development() -> None:
    """Startup configuration validator passes without errors in development settings."""
    validate_startup_configuration(settings)


# ============================================================================
# 2. Structured Logging Secret Redaction Tests
# ============================================================================


def test_logging_redacts_credentials_and_secrets() -> None:
    """JSONLogFormatter must redact all secret tokens and passwords."""
    formatter = JSONLogFormatter()
    record = logging.LogRecord(
        name="sentinelforge.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=100,
        msg="User authentication attempt",
        args=(),
        exc_info=None,
    )
    record.extra_fields = {
        "username": "admin",
        "password": "ClearTextPassword123!",
        "secret_token": "whsec_supersecrettoken9876543210",
        "nested": {
            "smtp_password": "mail-password",
            "safe_field": "public_data",
        },
    }

    formatted = formatter.format(record)
    assert "ClearTextPassword123!" not in formatted
    assert "whsec_supersecrettoken9876543210" not in formatted
    assert "mail-password" not in formatted
    assert "[REDACTED]" in formatted
    assert "public_data" in formatted


# ============================================================================
# 3. Request Correlation & Client IP Trusted Proxy Tests
# ============================================================================


@pytest.mark.asyncio
async def test_request_id_propagation_and_sanitization() -> None:
    """Valid request ID must be propagated; malformed ID must be sanitized."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Valid request ID preserved
        res1 = await client.get("/live", headers={"X-Request-ID": "valid-trace-id-12345"})
        assert res1.status_code == 200
        assert res1.headers.get("X-Request-ID") == "valid-trace-id-12345"

        # 2. Malformed request ID sanitized (contains CRLF or illegal chars)
        res2 = await client.get("/live", headers={"X-Request-ID": "bad\r\nid<script>"})
        assert res2.status_code == 200
        assigned_id = res2.headers.get("X-Request-ID")
        assert assigned_id is not None
        assert assigned_id.startswith("req-")
        assert "bad" not in assigned_id


def test_get_client_ip_trusted_vs_untrusted() -> None:
    """X-Forwarded-For should only be honored when remote client host is in TRUSTED_PROXIES."""
    # Request from untrusted remote IP
    req_untrusted = MagicMock()
    req_untrusted.client.host = "198.51.100.25"
    req_untrusted.headers = {"X-Forwarded-For": "203.0.113.195"}
    assert get_client_ip(req_untrusted) == "198.51.100.25"

    # Request from trusted proxy (e.g. 127.0.0.1)
    req_trusted = MagicMock()
    req_trusted.client.host = "127.0.0.1"
    req_trusted.headers = {"X-Forwarded-For": "203.0.113.195, 10.0.0.1"}
    assert get_client_ip(req_trusted) == "203.0.113.195"


@pytest.mark.asyncio
async def test_db_error_shielding_handler() -> None:
    """Database errors must be shielded from leaking internal SQL or credentials."""
    app = create_app()

    @app.get("/test-db-error")
    async def trigger_db_error() -> None:
        raise DBAPIError("SELECT secret_col FROM users", {}, Exception("psycopg2 internal error"))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/test-db-error")
        assert res.status_code == 500
        body = res.json()
        assert body["error"]["code"] == "DATABASE_ERROR"
        assert "psycopg2" not in body["error"]["message"]
        assert "SELECT secret_col" not in body["error"]["message"]


# ============================================================================
# 4. Root Probes Tests (/live, /ready, /health)
# ============================================================================


@pytest.mark.asyncio
async def test_root_probes_behavior(async_client: AsyncClient) -> None:
    """Verify /live, /ready, and /health endpoints return expected operational data."""
    # Liveness probe (process vitality)
    res_live = await async_client.get("/live")
    assert res_live.status_code == 200
    assert res_live.json() == {"status": "live"}

    # Readiness probe (DB connected)
    with patch("app.main.check_database_readiness", return_value=True):
        res_ready = await async_client.get("/ready")
        assert res_ready.status_code == 200
        assert res_ready.json() == {"status": "ready", "database": "connected"}

    # Readiness probe (DB disconnected / unready)
    with patch("app.main.check_database_readiness", return_value=False):
        res_unready = await async_client.get("/ready")
        assert res_unready.status_code == 503
        assert res_unready.json() == {"status": "not_ready", "database": "unreachable"}

    # Health summary
    with patch("app.main.check_database_readiness", return_value=True):
        res_health = await async_client.get("/health")
        assert res_health.status_code == 200
        data = res_health.json()
        assert data["status"] == "healthy"
        assert data["version"] == settings.APP_VERSION
        assert data["database"] == "connected"


# ============================================================================
# 5. Operational Metrics Endpoint & RBAC Gating
# ============================================================================


async def _create_user_with_role(
    db: AsyncSession, username: str, role_name: str
) -> tuple[User, str]:
    await seed_rbac_and_admin(db)
    user = User(
        id=uuid.uuid4(),
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash("ValidPassword123!"),
        is_active=True,
    )
    db.add(user)
    await db.flush()

    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.commit()

    _, token = await create_session(db, user)
    return user, token


@pytest.mark.asyncio
async def test_metrics_endpoint_rbac(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """GET /api/v1/metrics must be restricted to users with audit.read permission."""
    # 1. Unauthenticated request rejected
    res_anon = await async_client.get("/api/v1/metrics")
    assert res_anon.status_code in (401, 403)

    # 2. Unauthorized role (VIEWER lacking audit.read) rejected
    _viewer, viewer_token = await _create_user_with_role(
        test_db_session, "metrics_viewer", ROLE_VIEWER
    )
    headers_viewer = {
        "Cookie": f"sentinelforge_session={viewer_token}",
        "X-Requested-With": "XMLHttpRequest",
    }
    res_viewer = await async_client.get("/api/v1/metrics", headers=headers_viewer)
    assert res_viewer.status_code == 403

    # 3. Authorized role (ADMIN possessing audit.read) permitted
    _admin, admin_token = await _create_user_with_role(test_db_session, "metrics_admin", ROLE_ADMIN)
    headers_admin = {
        "Cookie": f"sentinelforge_session={admin_token}",
        "X-Requested-With": "XMLHttpRequest",
    }
    res_admin = await async_client.get("/api/v1/metrics", headers=headers_admin)
    assert res_admin.status_code == 200
    body = res_admin.json()
    assert body["data"]["version"] == settings.APP_VERSION
    assert "api" in body["data"]
    assert "security_operations" in body["data"]

    # 4. Record simulated API and security metrics
    system_metrics.record_request("GET", 200, 15.5)
    system_metrics.record_alert_event("created")

    snapshot = system_metrics.get_snapshot()
    assert snapshot["api"]["total_requests"] >= 1
    assert snapshot["security_operations"]["alerts"]["created"] >= 1


# ============================================================================
# 6. Background Task Crash Recovery & Reconciliation Tests
# ============================================================================


@pytest.mark.asyncio
async def test_stale_deliveries_reconciliation(test_db_session: AsyncSession) -> None:
    """Deliveries stuck in DELIVERING state must be safely reconciled on server recovery."""
    integration = Integration(
        id=uuid.uuid4(),
        name="Crash Recovery Webhook",
        type="WEBHOOK",
        endpoint_url="https://recovery.example.com/alerts",
        enabled=True,
        version=1,
    )
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Recovery Policy",
        enabled=True,
        event_types=["ALERT_CREATED"],
        destination_ids=[str(integration.id)],
    )
    event = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id=str(uuid.uuid4()),
        payload_version=1,
        payload={"title": "Interrupted Job"},
        created_at=utc_now(),
    )
    test_db_session.add_all([integration, policy, event])
    await test_db_session.flush()

    # Create job 1: Stuck in DELIVERING, attempts < max_attempts -> Should reset to RETRYING
    delivery_retrying = NotificationDelivery(
        id=uuid.uuid4(),
        event_id=event.id,
        policy_id=policy.id,
        destination_id=integration.id,
        idempotency_key=f"{event.id}:pol1:dest1",
        status=DeliveryStatus.DELIVERING.value,
        attempt_count=1,
        max_attempts=3,
        created_at=utc_now(),
        updated_at=utc_now(),
    )

    # Create job 2: Stuck in DELIVERING, attempts >= max_attempts -> Should transition to EXHAUSTED
    delivery_exhausted = NotificationDelivery(
        id=uuid.uuid4(),
        event_id=event.id,
        policy_id=policy.id,
        destination_id=integration.id,
        idempotency_key=f"{event.id}:pol2:dest2",
        status=DeliveryStatus.DELIVERING.value,
        attempt_count=3,
        max_attempts=3,
        created_at=utc_now(),
        updated_at=utc_now(),
    )

    test_db_session.add_all([delivery_retrying, delivery_exhausted])
    await test_db_session.commit()

    # Run reconciliation
    reconciled_count = await reconcile_stale_deliveries(test_db_session)
    assert reconciled_count == 2

    # Verify states after reconciliation
    await test_db_session.refresh(delivery_retrying)
    await test_db_session.refresh(delivery_exhausted)

    assert delivery_retrying.status == DeliveryStatus.RETRYING.value
    assert delivery_retrying.next_retry_at is not None
    assert "Reconciled after server restart" in (delivery_retrying.failure_reason or "")

    assert delivery_exhausted.status == DeliveryStatus.EXHAUSTED.value
    assert "Exceeded maximum delivery attempts" in (delivery_exhausted.failure_reason or "")

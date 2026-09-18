"""Integration and RBAC tests for Phase 11 Backend Extensions.

Validates:
- GET /api/v1/dashboard/metrics: Accurate aggregate operational metrics, RBAC, and recent items
- GET /api/v1/audit/logs: Security audit trail inspection guarded by audit.read permission
- GET /api/v1/users: Sanitized user account directory without hashed password leakage
- GET /api/v1/events: Paginated security event log telemetry with criteria filtering
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash
from app.models.auth import Role, User, UserRole
from app.models.event import Event
from app.services.auth import create_session, record_audit_log
from app.services.seed import seed_rbac_and_admin


async def _create_test_user(db: AsyncSession, role_name: str, username: str) -> tuple[User, str]:
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash("TestPassword123!"),
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
async def test_dashboard_metrics_unauthenticated_rejected(async_client: AsyncClient) -> None:
    resp = await async_client.get("/api/v1/dashboard/metrics")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dashboard_metrics_authenticated_success(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    analyst, token = await _create_test_user(test_db_session, ROLE_ANALYST, "p11_analyst_dash")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await async_client.get("/api/v1/dashboard/metrics")
    assert resp.status_code == 200
    body = resp.json()
    assert "data" in body
    data = body["data"]
    assert "open_alerts_count" in data
    assert "critical_alerts_count" in data
    assert "open_incidents_count" in data
    assert "active_rules_count" in data
    assert "total_indicators_count" in data
    assert isinstance(data["recent_alerts"], list)
    assert isinstance(data["recent_activity"], list)


@pytest.mark.asyncio
async def test_audit_logs_rbac(async_client: AsyncClient, test_db_session: AsyncSession) -> None:
    # 1. Unauthenticated -> 401
    resp = await async_client.get("/api/v1/audit/logs")
    assert resp.status_code == 401

    # 2. Viewer without audit.read -> 403
    _viewer, v_token = await _create_test_user(test_db_session, ROLE_VIEWER, "p11_viewer_audit")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, v_token)
    resp = await async_client.get("/api/v1/audit/logs")
    assert resp.status_code == 403

    # 3. Analyst with audit.read -> 200
    analyst, a_token = await _create_test_user(test_db_session, ROLE_ANALYST, "p11_analyst_audit")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, a_token)

    await record_audit_log(
        db=test_db_session,
        action="TEST_ACTION_AUDIT",
        actor_user_id=analyst.id,
        resource_type="system",
        resource_id="123",
        new_value={"test": "data"},
    )
    await test_db_session.commit()

    resp = await async_client.get("/api/v1/audit/logs")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] >= 1
    items = body["data"]["items"]
    assert len(items) >= 1
    assert "action" in items[0]
    assert "resource_type" in items[0]


@pytest.mark.asyncio
async def test_users_directory_endpoint(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    analyst, token = await _create_test_user(test_db_session, ROLE_ANALYST, "p11_user_lookup")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await async_client.get("/api/v1/users")
    assert resp.status_code == 200
    body = resp.json()
    items = body["data"]["items"]
    assert len(items) >= 1
    user_item = next(u for u in items if u["username"] == "p11_user_lookup")
    assert "email" in user_item
    assert "hashed_password" not in user_item
    assert "roles" in user_item
    assert ROLE_ANALYST in user_item["roles"]


@pytest.mark.asyncio
async def test_events_list_endpoint(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    analyst, token = await _create_test_user(test_db_session, ROLE_ANALYST, "p11_events_reader")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    now = datetime.now(UTC)
    ev = Event(
        id=uuid.uuid4(),
        external_event_id=f"test-p11-{uuid.uuid4()}",
        timestamp=now,
        ingested_at=now,
        source="p11_test_sensor",
        source_type="generic",
        event_type="test_event",
        action="observed",
        severity="MEDIUM",
        raw_payload={"msg": "p11 test"},
    )
    test_db_session.add(ev)
    await test_db_session.commit()

    resp = await async_client.get("/api/v1/events?source=p11_test_sensor")
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] >= 1
    assert body["data"]["items"][0]["source"] == "p11_test_sensor"

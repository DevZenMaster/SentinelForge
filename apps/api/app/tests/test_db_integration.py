"""Database integration tests executing async queries, constraints, and relationship cascades."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Alert,
    AlertEvent,
    AuditLog,
    DetectionRule,
    Event,
    Incident,
    IncidentAlert,
    Permission,
    Role,
    RolePermission,
    Session,
    User,
    UserRole,
)


@pytest.mark.asyncio
async def test_rbac_creation_and_relationships(test_db_session: AsyncSession) -> None:
    """Verify creation of User, Role, Permission and their associations."""
    # 1. Create User
    user = User(
        username="sec_admin",
        email="admin@sentinelforge.local",
        hashed_password="$argon2id$v=19$m=65536,t=3,p=4$dummyhashforphase1test",
        full_name="Security Administrator",
    )
    test_db_session.add(user)
    await test_db_session.flush()

    # 2. Create Role
    admin_role = Role(name="ADMIN", description="Full administrative access")
    test_db_session.add(admin_role)
    await test_db_session.flush()

    # 3. Create Permission
    perm = Permission(name="alerts.update", description="Update alert status")
    test_db_session.add(perm)
    await test_db_session.flush()

    # 4. Associate User -> Role and Role -> Permission
    user_role = UserRole(user_id=user.id, role_id=admin_role.id)
    role_perm = RolePermission(role_id=admin_role.id, permission_id=perm.id)
    test_db_session.add_all([user_role, role_perm])
    await test_db_session.commit()

    # 5. Query back and verify
    stmt = select(User).where(User.username == "sec_admin")
    result = await test_db_session.execute(stmt)
    retrieved_user = result.scalar_one()
    assert retrieved_user.email == "admin@sentinelforge.local"


@pytest.mark.asyncio
async def test_user_unique_constraint_violation(test_db_session: AsyncSession) -> None:
    """Verify that inserting duplicate username triggers IntegrityError."""
    u1 = User(
        username="analyst_1",
        email="analyst1@sentinelforge.local",
        hashed_password="hash1",
    )
    test_db_session.add(u1)
    await test_db_session.commit()

    u2 = User(
        username="analyst_1",  # Duplicate username
        email="analyst2@sentinelforge.local",
        hashed_password="hash2",
    )
    test_db_session.add(u2)

    with pytest.raises(IntegrityError):
        await test_db_session.commit()
    await test_db_session.rollback()


@pytest.mark.asyncio
async def test_session_lifecycle_and_user_cascade(test_db_session: AsyncSession) -> None:
    """Verify Session creation with opaque token and CASCADE on user deletion."""
    user = User(
        username="session_user",
        email="session@sentinelforge.local",
        hashed_password="hash",
    )
    test_db_session.add(user)
    await test_db_session.flush()

    now = datetime.now(UTC)
    token = uuid.uuid4().hex + uuid.uuid4().hex
    session = Session(
        session_token=token,
        user_id=user.id,
        expires_at=now + timedelta(hours=8),
        ip_address="127.0.0.1",
        user_agent="pytest-client/1.0",
    )
    test_db_session.add(session)
    await test_db_session.commit()

    # Verify session is retrievable
    stmt = select(Session).where(Session.session_token == token)
    res = await test_db_session.execute(stmt)
    assert res.scalar_one_or_none() is not None

    # Delete user and verify session is cascaded
    await test_db_session.delete(user)
    await test_db_session.commit()

    res_after = await test_db_session.execute(stmt)
    assert res_after.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_event_alert_evidence_chain(test_db_session: AsyncSession) -> None:
    """Verify Event ingestion structure, Alert creation, and AlertEvent multi-evidence linking."""
    now = datetime.now(UTC)

    # 1. Create 3 events representing brute force attempts
    events: list[Event] = []
    for i in range(3):
        e = Event(
            timestamp=now - timedelta(seconds=i * 30),
            source="linux-auth-node-01",
            source_type="linux",
            source_ip="10.0.0.15",
            event_type="authentication",
            action="login_failed",
            username="root",
            severity="MEDIUM",
            raw_payload={"msg": "Failed password for root", "attempt": i + 1},
            metadata_={"geo": "internal"},
        )
        events.append(e)
        test_db_session.add(e)
    await test_db_session.flush()

    # 2. Create DetectionRule
    rule = DetectionRule(
        rule_id="RULE-001",
        version=1,
        name="Brute Force Login",
        description="5 failed auths in 5m",
        severity="HIGH",
        event_type="authentication",
        threshold=5,
        time_window_seconds=300,
        conditions={"action": "login_failed", "group_by": "source_ip"},
    )
    test_db_session.add(rule)
    await test_db_session.flush()

    # 3. Create Alert
    alert = Alert(
        rule_id="RULE-001",
        rule_version=1,
        title="Brute Force Attempt from 10.0.0.15",
        description="Repeated failed authentications detected.",
        severity="HIGH",
        status="OPEN",
        source_ip="10.0.0.15",
        username="root",
        first_seen=now - timedelta(seconds=90),
        last_seen=now,
    )
    test_db_session.add(alert)
    await test_db_session.flush()

    # 4. Link evidence events to alert (AlertEvent)
    for e in events:
        ae = AlertEvent(alert_id=alert.id, event_id=e.id)
        test_db_session.add(ae)
    await test_db_session.commit()

    # 5. Query alert_events
    stmt = select(AlertEvent).where(AlertEvent.alert_id == alert.id)
    linked = (await test_db_session.execute(stmt)).scalars().all()
    assert len(linked) == 3


@pytest.mark.asyncio
async def test_incident_grouping_and_audit_log(test_db_session: AsyncSession) -> None:
    """Verify Incident creation with grouped alerts and append-only AuditLog."""
    now = datetime.now(UTC)

    # 1. Create Alert
    alert = Alert(
        rule_id="RULE-002",
        rule_version=1,
        title="Account Spray against admin",
        description="10 failed logins on admin",
        severity="HIGH",
        status="OPEN",
        first_seen=now,
        last_seen=now,
    )
    test_db_session.add(alert)
    await test_db_session.flush()

    # 2. Create Incident
    incident = Incident(
        title="Incident 2026-001: Distributed Password Spray",
        description="Multiple external hosts spraying corporate admin account.",
        severity="HIGH",
        status="INVESTIGATING",
        notes=[{"author": "system", "text": "Incident auto-created"}],
    )
    test_db_session.add(incident)
    await test_db_session.flush()

    # 3. Link alert to incident
    inc_alert = IncidentAlert(incident_id=incident.id, alert_id=alert.id)
    test_db_session.add(inc_alert)

    # 4. Create Audit Log entry
    audit = AuditLog(
        action="INCIDENT_CREATED",
        resource_type="incident",
        resource_id=str(incident.id),
        new_value={"status": "INVESTIGATING", "severity": "HIGH"},
        source_ip="127.0.0.1",
        request_id="req-audit-test-01",
    )
    test_db_session.add(audit)
    await test_db_session.commit()

    # Query audit record
    stmt = select(AuditLog).where(AuditLog.resource_id == str(incident.id))
    log_entry = (await test_db_session.execute(stmt)).scalar_one()
    assert log_entry.action == "INCIDENT_CREATED"
    assert log_entry.new_value["status"] == "INVESTIGATING"  # type: ignore[index]

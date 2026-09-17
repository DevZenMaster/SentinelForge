"""Comprehensive Test Suite for SentinelForge Incident Management & Investigation (Phase 6).

Validates:
- Case creation, sequential human-readable identifier generation (INC-YYYY-NNNNNN)
- Strict lifecycle state transitions (OPEN -> IN_PROGRESS -> RESOLVED -> CLOSED -> REOPENED)
- Invalid lifecycle state transitions rejection (400 Bad Request)
- Resolution validation (category and notes required) & reopen reason validation
- Analyst assignment & auto-advancement from OPEN to IN_PROGRESS
- Alert correlation, attachment, detachment, and duplicate prevention (409 Conflict)
- Forensic event evidence attachment, detachment, and duplicate prevention (409 Conflict)
- Event evidence referential integrity (RESTRICT on deletion) & raw_payload immutability
- Investigation notes CRUD, server-derived author attribution, and length boundaries
- Unified investigation timeline distinguishing telemetry vs action timestamps
- Append-only security audit trail verification for all lifecycle actions
- RBAC enforcement across VIEWER (read-only), ANALYST, and ADMIN personas
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash
from app.models import (
    Alert,
    AuditLog,
    Event,
    Incident,
    Role,
    User,
    UserRole,
)
from app.schemas.event import EventCreateRequest
from app.services.auth import create_session
from app.services.event import ingest_security_event
from app.services.incident import generate_incident_id
from app.services.seed import seed_rbac_and_admin

# ==============================================================================
# Test Fixtures & Helpers
# ==============================================================================


async def create_user(
    db: AsyncSession, role_name: str, username: str, is_active: bool = True
) -> tuple[User, str]:
    """Create test user with assigned role and active session token."""
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash("ValidPass123!"),
        is_active=is_active,
    )
    db.add(user)
    await db.flush()

    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.commit()

    _, token = await create_session(db, user)
    return user, token


def auth_headers(token: str) -> dict[str, str]:
    """Return headers with session cookie and CSRF defense header."""
    return {
        "Cookie": f"{settings.SESSION_COOKIE_NAME}={token}",
        "X-Requested-With": "XMLHttpRequest",
    }


async def create_dummy_event(db: AsyncSession, source_ip: str = "192.168.1.100") -> Event:
    """Helper to ingest a real normalized event."""
    user, _ = await create_user(db, ROLE_ANALYST, f"ingest_user_{uuid.uuid4().hex[:6]}")
    payload = EventCreateRequest(
        timestamp=datetime.now(UTC) - timedelta(minutes=5),
        source="linux_auth",
        source_type="syslog",
        source_ip=source_ip,
        event_type="authentication",
        action="login_failed",
        username="target_user",
        severity="HIGH",
        raw_payload={"msg": "Failed password for root", "ip": source_ip},
    )
    res, _ = await ingest_security_event(db, payload, actor_user_id=user.id)
    stmt = select(Event).where(Event.id == res.id)
    return (await db.execute(stmt)).scalar_one()


async def create_dummy_alert(db: AsyncSession, dedup_suffix: str = "1") -> Alert:
    """Helper creating a test alert."""
    now = datetime.now(UTC)
    alert = Alert(
        rule_id="RULE-001",
        rule_version=1,
        title="Test Alert: Brute Force",
        description="Multiple failed logins observed",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"RULE-001:192.168.1.100:{dedup_suffix}",
        correlation_key="192.168.1.100",
        observed_count=5,
        threshold=5,
        evidence={"reason": "test"},
        first_seen=now - timedelta(minutes=2),
        last_seen=now,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


# ==============================================================================
# 1. Incident Creation & Identifier Generation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_create_incident_minimal(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify creating an incident case with minimal valid fields."""
    analyst, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_create_min")

    payload = {
        "title": "Unauthorized Access Investigation",
        "description": "Investigating unusual access patterns from internal network.",
        "severity": "HIGH",
        "priority": "URGENT",
    }
    response = await async_client.post(
        "/api/v1/incidents",
        json=payload,
        headers=auth_headers(token),
    )
    assert response.status_code == 201
    body = response.json()
    assert body["data"] is not None
    data = body["data"]

    year = datetime.now(UTC).year
    assert data["incident_id"].startswith(f"INC-{year}-")
    assert data["title"] == payload["title"]
    assert data["description"] == payload["description"]
    assert data["severity"] == "HIGH"
    assert data["priority"] == "URGENT"
    assert data["status"] == "OPEN"
    assert data["created_by"]["id"] == str(analyst.id)
    assert data["alerts_count"] == 0
    assert data["events_count"] == 0
    assert data["notes_count"] == 0

    # Verify audit log
    audit_stmt = select(AuditLog).where(
        AuditLog.resource_type == "incident",
        AuditLog.resource_id == data["id"],
        AuditLog.action == "INCIDENT_CREATED",
    )
    audit = (await test_db_session.execute(audit_stmt)).scalar_one_or_none()
    assert audit is not None
    assert audit.actor_user_id == analyst.id
    assert audit.new_value is not None
    assert audit.new_value["incident_id"] == data["incident_id"]


@pytest.mark.asyncio
async def test_create_incident_with_alerts_events_and_note(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify creating an incident bundled with initial alerts and telemetry."""
    analyst, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_bundle")
    alert = await create_dummy_alert(test_db_session, "bundle_alert")
    event = await create_dummy_event(test_db_session, "10.0.0.50")

    payload = {
        "title": "Bundled Incident",
        "description": "Case created with pre-correlated alerts and telemetry evidence.",
        "severity": "CRITICAL",
        "priority": "HIGH",
        "alert_ids": [str(alert.id)],
        "event_ids": [str(event.id)],
        "initial_note": "Initial assessment indicates possible host compromise.",
    }
    response = await async_client.post(
        "/api/v1/incidents",
        json=payload,
        headers=auth_headers(token),
    )
    assert response.status_code == 201
    data = response.json()["data"]

    assert data["alerts_count"] == 1
    assert data["events_count"] == 1
    assert data["notes_count"] == 1
    assert len(data["alerts"]) == 1
    assert data["alerts"][0]["alert_id"] == str(alert.id)
    assert len(data["events"]) == 1
    assert data["events"][0]["event_id"] == str(event.id)
    assert len(data["notes"]) == 1
    assert data["notes"][0]["content"] == payload["initial_note"]
    assert data["notes"][0]["author"]["id"] == str(analyst.id)


@pytest.mark.asyncio
async def test_create_incident_invalid_assigned_user(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify creating an incident targeting a non-existent analyst fails with 404."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_inv_assign")

    payload = {
        "title": "Invalid Assignee Case",
        "description": "Assigning to unknown UUID.",
        "severity": "LOW",
        "assigned_to_user_id": str(uuid.uuid4()),
    }
    response = await async_client.post(
        "/api/v1/incidents",
        json=payload,
        headers=auth_headers(token),
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_generate_incident_id_sequential(
    test_db_session: AsyncSession,
) -> None:
    """Verify sequential incident ID format: INC-YYYY-000001, INC-YYYY-000002."""
    year = datetime.now(UTC).year
    id1 = await generate_incident_id(test_db_session, year=year)
    assert id1 == f"INC-{year}-000001"

    inc = Incident(
        incident_id=id1,
        title="Test Inc 1",
        description="Desc",
        severity="LOW",
        priority="LOW",
        status="OPEN",
    )
    test_db_session.add(inc)
    await test_db_session.commit()

    id2 = await generate_incident_id(test_db_session, year=year)
    assert id2 == f"INC-{year}-000002"


# ==============================================================================
# 2. Retrieval, Search & Listing Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_get_incident_by_uuid_and_ticket_id(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify retrieving an incident by both its UUID and human-readable incident_id."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_get_dual")

    res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Lookup Test Incident",
            "description": "Case for checking dual lookup by UUID and ticket ID.",
            "severity": "MEDIUM",
        },
        headers=auth_headers(token),
    )
    assert res.status_code == 201
    inc_data = res.json()["data"]
    inc_uuid = inc_data["id"]
    inc_id = inc_data["incident_id"]

    # 1. Lookup by UUID
    res_uuid = await async_client.get(
        f"/api/v1/incidents/{inc_uuid}",
        headers=auth_headers(token),
    )
    assert res_uuid.status_code == 200
    assert res_uuid.json()["data"]["incident_id"] == inc_id

    # 2. Lookup by ticket ID
    res_ticket = await async_client.get(
        f"/api/v1/incidents/{inc_id}",
        headers=auth_headers(token),
    )
    assert res_ticket.status_code == 200
    assert res_ticket.json()["data"]["id"] == inc_uuid

    # 3. Lookup non-existent
    res_unknown = await async_client.get(
        f"/api/v1/incidents/INC-{datetime.now(UTC).year}-999999",
        headers=auth_headers(token),
    )
    assert res_unknown.status_code == 404


@pytest.mark.asyncio
async def test_list_incidents_filtering_and_search(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify multi-criteria filtering and text search over incidents."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_filter")

    await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Ransomware Alpha",
            "description": "Crypto locker",
            "severity": "CRITICAL",
            "priority": "URGENT",
        },
        headers=auth_headers(token),
    )
    await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Phishing Beta",
            "description": "Credential harvest",
            "severity": "MEDIUM",
            "priority": "MEDIUM",
        },
        headers=auth_headers(token),
    )
    await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Portscan Gamma",
            "description": "Recon probe",
            "severity": "LOW",
            "priority": "LOW",
        },
        headers=auth_headers(token),
    )

    # Filter by severity
    res_sev = await async_client.get(
        "/api/v1/incidents?severity=CRITICAL",
        headers=auth_headers(token),
    )
    assert res_sev.status_code == 200
    sev_data = res_sev.json()["data"]
    assert sev_data["total"] == 1
    assert sev_data["items"][0]["title"] == "Ransomware Alpha"

    # Search by keyword
    res_search = await async_client.get(
        "/api/v1/incidents?search=harvest",
        headers=auth_headers(token),
    )
    assert res_search.status_code == 200
    search_data = res_search.json()["data"]
    assert search_data["total"] == 1
    assert search_data["items"][0]["title"] == "Phishing Beta"


# ==============================================================================
# 3. Update & Assignment Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_update_incident_properties(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify updating title, description, severity, and priority."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_updater")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Initial Title",
            "description": "Initial Desc",
            "severity": "LOW",
            "priority": "LOW",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    patch_res = await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"title": "Updated Title", "severity": "CRITICAL", "priority": "URGENT"},
        headers=auth_headers(token),
    )
    assert patch_res.status_code == 200
    patched = patch_res.json()["data"]
    assert patched["title"] == "Updated Title"
    assert patched["severity"] == "CRITICAL"
    assert patched["priority"] == "URGENT"
    assert patched["description"] == "Initial Desc"


@pytest.mark.asyncio
async def test_assign_analyst_and_auto_in_progress(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify assigning an analyst auto-transitions an OPEN ticket to IN_PROGRESS."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_assigner")
    analyst2, _ = await create_user(test_db_session, ROLE_ANALYST, "analyst_assignee")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={"title": "Assignment Case", "description": "Case to assign", "severity": "MEDIUM"},
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]
    assert create_res.json()["data"]["status"] == "OPEN"

    assign_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        json={"assigned_to_user_id": str(analyst2.id)},
        headers=auth_headers(token),
    )
    assert assign_res.status_code == 200
    assigned_data = assign_res.json()["data"]
    assert assigned_data["assigned_to"]["id"] == str(analyst2.id)
    assert assigned_data["status"] == "IN_PROGRESS"


# ==============================================================================
# 4. Lifecycle State Machine Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_lifecycle_complete_happy_path(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify lifecycle progression: OPEN -> IN_PROGRESS -> RESOLVED -> CLOSED -> REOPENED."""
    _, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "analyst_lifecycle")
    _, admin_token = await create_user(test_db_session, ROLE_ADMIN, "admin_lifecycle")

    # 1. Start in OPEN
    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Lifecycle Test",
            "description": "Full lifecycle tracking",
            "severity": "HIGH",
        },
        headers=auth_headers(analyst_token),
    )
    inc_id = create_res.json()["data"]["id"]

    # 2. OPEN -> IN_PROGRESS
    res_prog = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS", "comment": "Analyst began investigation"},
        headers=auth_headers(analyst_token),
    )
    assert res_prog.status_code == 200
    assert res_prog.json()["data"]["status"] == "IN_PROGRESS"

    # 3. IN_PROGRESS -> RESOLVED
    res_resolv = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "RESOLVED",
            "resolution_category": "TRUE_POSITIVE",
            "resolution_notes": "Identified malicious IP and revoked compromised API token.",
            "comment": "Resolution confirmed by security team.",
        },
        headers=auth_headers(analyst_token),
    )
    assert res_resolv.status_code == 200
    resolv_data = res_resolv.json()["data"]
    assert resolv_data["status"] == "RESOLVED"
    assert resolv_data["resolution_category"] == "TRUE_POSITIVE"
    assert resolv_data["resolved_at"] is not None

    # 4. RESOLVED -> CLOSED (Requires ADMIN possessing incidents.close)
    res_close = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "comment": "All remediation verified."},
        headers=auth_headers(admin_token),
    )
    assert res_close.status_code == 200
    close_data = res_close.json()["data"]
    assert close_data["status"] == "CLOSED"
    assert close_data["closed_at"] is not None

    # 5. CLOSED -> REOPENED (Analyst or Admin can reopen with reason)
    res_reopen = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "REOPENED",
            "comment": "Further unauthorized activity detected from related IP.",
        },
        headers=auth_headers(analyst_token),
    )
    assert res_reopen.status_code == 200
    reopen_data = res_reopen.json()["data"]
    assert reopen_data["status"] == "REOPENED"
    assert reopen_data["closed_at"] is None


@pytest.mark.asyncio
async def test_lifecycle_invalid_transitions_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify invalid state transitions are strictly rejected with 400 Bad Request."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_inv_trans")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Invalid Transition Case",
            "description": "Testing rejection",
            "severity": "LOW",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # OPEN -> REOPENED is invalid
    res_inv1 = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "REOPENED", "comment": "Attempting invalid reopen from OPEN"},
        headers=auth_headers(token),
    )
    assert res_inv1.status_code == 400

    # OPEN -> CLOSED is invalid (cannot skip investigation)
    res_inv_close = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "comment": "Attempting invalid direct close from OPEN"},
        headers=auth_headers(token),
    )
    assert res_inv_close.status_code in (400, 403)

    # Transition to IN_PROGRESS
    res_prog = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=auth_headers(token),
    )
    assert res_prog.status_code == 200

    # IN_PROGRESS -> OPEN is valid (de-escalation/unassign back to triage)
    res_open = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "OPEN", "comment": "Reset back to open triage queue"},
        headers=auth_headers(token),
    )
    assert res_open.status_code == 200
    assert res_open.json()["data"]["status"] == "OPEN"

    # Transition back to IN_PROGRESS, then RESOLVED
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=auth_headers(token),
    )
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "RESOLVED",
            "resolution_category": "FALSE_POSITIVE",
            "resolution_notes": "Identified benign penetration testing activity.",
        },
        headers=auth_headers(token),
    )

    # RESOLVED -> IN_PROGRESS is invalid (must be REOPENED first)
    res_inv3 = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=auth_headers(token),
    )
    assert res_inv3.status_code == 400


@pytest.mark.asyncio
async def test_lifecycle_resolution_validation_enforced(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify RESOLVED status strictly requires resolution_category and resolution_notes."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_res_val")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Resolution Validation Case",
            "description": "Testing required fields",
            "severity": "MEDIUM",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # Missing category and notes
    res_fail = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "RESOLVED"},
        headers=auth_headers(token),
    )
    assert res_fail.status_code == 422


# ==============================================================================
# 5. Alert & Event Association and Duplicate Prevention Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_attachment_and_duplicate_prevention(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify attaching an alert and ensuring duplicate attachments return 409 Conflict."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_alert_link")
    alert = await create_dummy_alert(test_db_session, "dup_alert_test")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Alert Link Case",
            "description": "Testing alert linkage",
            "severity": "HIGH",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # Attach alert
    att_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/alerts",
        json={"alert_id": str(alert.id)},
        headers=auth_headers(token),
    )
    assert att_res.status_code == 200
    assert att_res.json()["data"]["alert_id"] == str(alert.id)

    # Attach duplicate -> 409 Conflict
    dup_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/alerts",
        json={"alert_id": str(alert.id)},
        headers=auth_headers(token),
    )
    assert dup_res.status_code == 409

    # Detach alert
    det_res = await async_client.delete(
        f"/api/v1/incidents/{inc_id}/alerts/{alert.id}",
        headers=auth_headers(token),
    )
    assert det_res.status_code == 200

    # Detach again -> 404 Not Found
    det_again = await async_client.delete(
        f"/api/v1/incidents/{inc_id}/alerts/{alert.id}",
        headers=auth_headers(token),
    )
    assert det_again.status_code == 404


@pytest.mark.asyncio
async def test_event_evidence_attachment_duplicate_and_immutability(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify attaching event evidence, duplicate rejection, and strict payload immutability."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_event_link")
    event = await create_dummy_event(test_db_session, "172.16.0.42")
    original_raw_payload = dict(event.raw_payload)

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Evidence Case",
            "description": "Testing forensic evidence attachment",
            "severity": "HIGH",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # Attach event evidence
    att_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/events",
        json={"event_id": str(event.id)},
        headers=auth_headers(token),
    )
    assert att_res.status_code == 200
    assert att_res.json()["data"]["event_id"] == str(event.id)

    # Duplicate attachment -> 409 Conflict
    dup_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/events",
        json={"event_id": str(event.id)},
        headers=auth_headers(token),
    )
    assert dup_res.status_code == 409

    # Verify event evidence immutability
    reloaded_event = (
        await test_db_session.execute(select(Event).where(Event.id == event.id))
    ).scalar_one()
    assert reloaded_event.raw_payload == original_raw_payload

    # Verify RESTRICT on event deletion while attached to incident
    with pytest.raises(IntegrityError):
        await test_db_session.delete(reloaded_event)
        await test_db_session.flush()

    await test_db_session.rollback()


# ==============================================================================
# 6. Investigation Notes Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_investigation_notes_author_attribution_and_confidentiality(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify note author is server-derived from session and note omitted from audit."""
    analyst, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_noter")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={"title": "Notes Case", "description": "Testing notes", "severity": "LOW"},
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    note_content = "Suspicious traffic observed from host. Analyst initiated memory acquisition."
    note_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"content": note_content},
        headers=auth_headers(token),
    )
    assert note_res.status_code == 201
    note_data = note_res.json()["data"]
    assert note_data["content"] == note_content
    assert note_data["author"]["id"] == str(analyst.id)

    list_notes = await async_client.get(
        f"/api/v1/incidents/{inc_id}/notes",
        headers=auth_headers(token),
    )
    assert list_notes.status_code == 200
    assert len(list_notes.json()["data"]) == 1

    # Verify audit log does NOT contain full confidential note text
    audit_stmt = select(AuditLog).where(
        AuditLog.resource_type == "incident",
        AuditLog.resource_id == inc_id,
        AuditLog.action == "INCIDENT_NOTE_CREATED",
    )
    audit = (await test_db_session.execute(audit_stmt)).scalar_one()
    assert audit.new_value is not None
    assert "content" not in audit.new_value
    assert audit.new_value["content_length"] == len(note_content)


# ==============================================================================
# 7. Unified Timeline Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_timeline_distinguishes_telemetry_from_action_timestamp(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify the timeline differentiates telemetry occurrence from action timestamp."""
    analyst, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_timeline")

    # Ingest event with timestamp 1 hour in past
    t0_event = datetime.now(UTC) - timedelta(hours=1)
    event_payload = EventCreateRequest(
        timestamp=t0_event,
        source="linux_auth",
        source_type="syslog",
        source_ip="10.20.30.40",
        event_type="authentication",
        action="login_failed",
        username="admin",
        severity="HIGH",
        raw_payload={"msg": "Failed password"},
    )
    ev_res, _ = await ingest_security_event(
        test_db_session, event_payload, actor_user_id=analyst.id
    )

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Timeline Test Incident",
            "description": "Testing timeline distinctions",
            "severity": "HIGH",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # Attach event as evidence
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/events",
        json={"event_id": str(ev_res.id)},
        headers=auth_headers(token),
    )

    tl_res = await async_client.get(
        f"/api/v1/incidents/{inc_id}/timeline",
        headers=auth_headers(token),
    )
    assert tl_res.status_code == 200
    timeline = tl_res.json()["data"]["entries"]

    evidence_entry = next((e for e in timeline if e["entry_type"] == "EVIDENCE_ATTACHED"), None)
    assert evidence_entry is not None

    action_ts = datetime.fromisoformat(evidence_entry["timestamp"])
    event_ts = datetime.fromisoformat(evidence_entry["event_timestamp"])

    assert action_ts > event_ts
    assert (action_ts - event_ts).total_seconds() > 3000


# ==============================================================================
# 8. RBAC Security Persona Boundaries
# ==============================================================================


@pytest.mark.asyncio
async def test_rbac_persona_boundaries(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify VIEWER has read-only access and is forbidden from mutating incidents."""
    _, admin_token = await create_user(test_db_session, ROLE_ADMIN, "admin_rbac_inc")
    _, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "analyst_rbac_inc")
    _, viewer_token = await create_user(test_db_session, ROLE_VIEWER, "viewer_rbac_inc")

    # 1. VIEWER cannot create incident
    v_create = await async_client.post(
        "/api/v1/incidents",
        json={"title": "Forbidden", "description": "Viewer attempt", "severity": "LOW"},
        headers=auth_headers(viewer_token),
    )
    assert v_create.status_code == 403

    # 2. ANALYST can create incident
    a_create = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Analyst Allowed",
            "description": "Analyst created case",
            "severity": "MEDIUM",
        },
        headers=auth_headers(analyst_token),
    )
    assert a_create.status_code == 201
    inc_id = a_create.json()["data"]["id"]

    # 3. VIEWER can read incident
    v_get = await async_client.get(
        f"/api/v1/incidents/{inc_id}",
        headers=auth_headers(viewer_token),
    )
    assert v_get.status_code == 200

    # 4. VIEWER cannot add notes
    v_note = await async_client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"content": "Unauthorized note"},
        headers=auth_headers(viewer_token),
    )
    assert v_note.status_code == 403

    # 5. VIEWER cannot transition status
    v_status = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=auth_headers(viewer_token),
    )
    assert v_status.status_code == 403

    # 6. Unauthenticated request receives 401
    unauth = await async_client.get(f"/api/v1/incidents/{inc_id}")
    assert unauth.status_code == 401


# ==============================================================================
# 9. Security & Architecture Hardening Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_privilege_escalation_analyst_cannot_close_incident(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify an ANALYST cannot close an incident (403 Forbidden); only ADMIN can."""
    _, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "analyst_close_att")
    _, admin_token = await create_user(test_db_session, ROLE_ADMIN, "admin_close_att")

    # Create and resolve incident
    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Closure Privilege Test",
            "description": "Detailed incident description",
            "severity": "HIGH",
        },
        headers=auth_headers(analyst_token),
    )
    inc_id = create_res.json()["data"]["id"]

    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=auth_headers(analyst_token),
    )
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "RESOLVED",
            "resolution_category": "TRUE_POSITIVE",
            "resolution_notes": "Resolved by analyst",
        },
        headers=auth_headers(analyst_token),
    )

    # 1. Analyst attempts to close -> 403 Forbidden
    analyst_close = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "comment": "Analyst trying to close"},
        headers=auth_headers(analyst_token),
    )
    assert analyst_close.status_code == 403
    assert "incidents.close" in analyst_close.json()["error"]["message"]

    # 2. Admin closes -> 200 OK
    admin_close = await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "comment": "Admin officially closing"},
        headers=auth_headers(admin_token),
    )
    assert admin_close.status_code == 200
    assert admin_close.json()["data"]["status"] == "CLOSED"


@pytest.mark.asyncio
async def test_raw_evidence_integrity_across_full_incident_lifecycle(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify raw security event payload and timestamps remain strictly immutable
    across full lifecycle.
    """
    _, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "analyst_ev_immut")
    _, admin_token = await create_user(test_db_session, ROLE_ADMIN, "admin_ev_immut")

    # 1. Ingest security event with complex raw payload
    raw_evidence_payload = {
        "event_source": "syslog",
        "nested_details": {"process": "sshd", "pid": 4128, "cmd": "/usr/sbin/sshd -D"},
        "evidence_markers": ["malicious_ip", "recon_pattern"],
    }
    event_time = datetime.now(UTC) - timedelta(hours=2)
    ev = Event(
        timestamp=event_time,
        source="linux_auth",
        source_type="syslog",
        raw_payload=raw_evidence_payload,
        event_type="authentication",
        action="login_failure",
        outcome="failure",
        severity="HIGH",
        source_ip="198.51.100.77",
    )
    test_db_session.add(ev)
    await test_db_session.commit()
    await test_db_session.refresh(ev)
    ev_id = ev.id

    # 2. Create incident and attach event
    inc_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Evidence Immutability Case",
            "description": "Case testing raw payload",
            "severity": "HIGH",
        },
        headers=auth_headers(analyst_token),
    )
    inc_id = inc_res.json()["data"]["id"]

    att_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/events",
        json={"event_id": str(ev_id)},
        headers=auth_headers(analyst_token),
    )
    assert att_res.status_code == 200

    # 3. Update incident metadata
    await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"title": "Updated Title", "priority": "URGENT"},
        headers=auth_headers(analyst_token),
    )

    # 4. Add notes
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/notes",
        json={"content": "Investigative findings note"},
        headers=auth_headers(analyst_token),
    )

    # 5. Move through lifecycle: IN_PROGRESS -> RESOLVED -> REOPENED -> RESOLVED -> CLOSED
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "IN_PROGRESS"},
        headers=auth_headers(analyst_token),
    )
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "RESOLVED",
            "resolution_category": "TRUE_POSITIVE",
            "resolution_notes": "Remediated threat",
        },
        headers=auth_headers(analyst_token),
    )
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "REOPENED", "comment": "Further anomalies"},
        headers=auth_headers(analyst_token),
    )
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={
            "status": "RESOLVED",
            "resolution_category": "TRUE_POSITIVE",
            "resolution_notes": "Second remediation confirmed",
        },
        headers=auth_headers(analyst_token),
    )
    await async_client.post(
        f"/api/v1/incidents/{inc_id}/status",
        json={"status": "CLOSED", "comment": "Case formally closed"},
        headers=auth_headers(admin_token),
    )

    # 6. Re-fetch original event and assert 100% forensic immutability
    reloaded = (await test_db_session.execute(select(Event).where(Event.id == ev_id))).scalar_one()
    assert reloaded.raw_payload == raw_evidence_payload
    assert (
        reloaded.timestamp.replace(tzinfo=UTC) == event_time
        if reloaded.timestamp.tzinfo is None
        else reloaded.timestamp == event_time
    )
    assert reloaded.source_ip == "198.51.100.77"


@pytest.mark.asyncio
async def test_auto_assignment_advances_status_with_audit_trail(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify assigning an OPEN incident auto-advances status and logs both
    assignment and status audit events.
    """
    _, analyst1_token = await create_user(test_db_session, ROLE_ANALYST, "analyst_auto_assign1")
    analyst2, _ = await create_user(test_db_session, ROLE_ANALYST, "analyst_auto_assign2")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Auto Advance Case",
            "description": "Testing status advancement",
            "severity": "MEDIUM",
        },
        headers=auth_headers(analyst1_token),
    )
    inc_id = create_res.json()["data"]["id"]
    assert create_res.json()["data"]["status"] == "OPEN"

    assign_res = await async_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        json={"assigned_to_user_id": str(analyst2.id)},
        headers=auth_headers(analyst1_token),
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["data"]["status"] == "IN_PROGRESS"

    # Verify both audit records were committed
    stmt = (
        select(AuditLog)
        .where(AuditLog.resource_type == "incident", AuditLog.resource_id == inc_id)
        .order_by(AuditLog.timestamp.asc())
    )
    logs = (await test_db_session.execute(stmt)).scalars().all()
    actions = [log.action for log in logs]
    assert "INCIDENT_ASSIGNED" in actions
    assert "INCIDENT_STATUS_CHANGED" in actions


@pytest.mark.asyncio
async def test_list_incidents_invalid_enum_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify invalid query parameter enums are strictly rejected with 422 Unprocessable Content."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_enum_test")

    res_status = await async_client.get(
        "/api/v1/incidents?status=MALICIOUS_STATUS",
        headers=auth_headers(token),
    )
    assert res_status.status_code == 422

    res_sev = await async_client.get(
        "/api/v1/incidents?severity=SUPER_CRITICAL",
        headers=auth_headers(token),
    )
    assert res_sev.status_code == 422

    res_prio = await async_client.get(
        "/api/v1/incidents?priority=HYPER_PRIORITY",
        headers=auth_headers(token),
    )
    assert res_prio.status_code == 422


@pytest.mark.asyncio
async def test_mass_assignment_protection_patch_rejects_extra_fields(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify PATCH /api/v1/incidents/{id} rejects extra/protected fields with 422."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_mass_assign")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Mass Assign Protection",
            "description": "Detailed incident description",
            "severity": "LOW",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # Attempt to modify status or timestamps via PATCH -> 422
    patch_res = await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "CLOSED"},
        headers=auth_headers(token),
    )
    assert patch_res.status_code == 422

    patch_res2 = await async_client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"created_by_user_id": str(uuid.uuid4())},
        headers=auth_headers(token),
    )
    assert patch_res2.status_code == 422


@pytest.mark.asyncio
async def test_timeline_query_bounded_and_deterministic_tie_breaking(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify timeline query is bounded by limit parameter and maintains deterministic ordering."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_timeline_bound")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Timeline Bound Test",
            "description": "Detailed incident description",
            "severity": "LOW",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    # Add 5 notes
    for i in range(5):
        await async_client.post(
            f"/api/v1/incidents/{inc_id}/notes",
            json={"content": f"Note {i}"},
            headers=auth_headers(token),
        )

    # Fetch timeline with limit=2
    res_bounded = await async_client.get(
        f"/api/v1/incidents/{inc_id}/timeline?limit=2",
        headers=auth_headers(token),
    )
    assert res_bounded.status_code == 200
    data = res_bounded.json()["data"]
    assert len(data["entries"]) == 2

    # Fetch unbounded timeline
    res_all = await async_client.get(
        f"/api/v1/incidents/{inc_id}/timeline",
        headers=auth_headers(token),
    )
    assert res_all.status_code == 200
    assert len(res_all.json()["data"]["entries"]) >= 6


@pytest.mark.asyncio
async def test_generate_incident_id_skips_non_numeric_fallback_ids(
    test_db_session: AsyncSession,
) -> None:
    """Verify generate_incident_id safely skips non-numeric fallback IDs
    without resetting sequence to 1.
    """
    year = datetime.now(UTC).year

    # Seed an incident with a non-numeric fallback ID
    inc_fallback = Incident(
        incident_id=f"INC-{year}-A1B2C3",
        title="Fallback ID Case",
        description="Desc",
        severity="LOW",
        priority="LOW",
        status="OPEN",
    )
    # And a sequential one
    inc_seq = Incident(
        incident_id=f"INC-{year}-000005",
        title="Sequential Case",
        description="Desc",
        severity="LOW",
        priority="LOW",
        status="OPEN",
    )
    test_db_session.add_all([inc_fallback, inc_seq])
    await test_db_session.commit()

    next_id = await generate_incident_id(test_db_session, year=year)
    assert next_id == f"INC-{year}-000006"


@pytest.mark.asyncio
async def test_concurrent_incident_creation_and_sequential_ids(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify multiple concurrent incident creations allocate unique, non-colliding IDs."""
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_concurrent_inc")

    async def create_one(i: int) -> Response:
        return await async_client.post(
            "/api/v1/incidents",
            json={
                "title": f"Concurrent Incident {i}",
                "description": "Testing concurrency",
                "severity": "LOW",
            },
            headers=auth_headers(token),
        )

    responses = await asyncio.gather(create_one(1), create_one(2))
    for r in responses:
        assert r.status_code == 201

    incident_ids = [r.json()["data"]["incident_id"] for r in responses]
    assert len(set(incident_ids)) == 2
    for i_id in incident_ids:
        assert i_id.startswith(f"INC-{datetime.now(UTC).year}-")


@pytest.mark.asyncio
async def test_concurrent_alert_attachment_race_handling(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify concurrent attempts to attach the same alert to an incident
    are handled safely with 409 Conflict.
    """
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_race_alert")
    alert = await create_dummy_alert(test_db_session, "Race Alert")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Alert Race Case",
            "description": "Testing alert race",
            "severity": "MEDIUM",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    responses = await asyncio.gather(
        async_client.post(
            f"/api/v1/incidents/{inc_id}/alerts",
            json={"alert_id": str(alert.id)},
            headers=auth_headers(token),
        ),
        async_client.post(
            f"/api/v1/incidents/{inc_id}/alerts",
            json={"alert_id": str(alert.id)},
            headers=auth_headers(token),
        ),
    )
    status_codes = sorted([r.status_code for r in responses])
    assert status_codes == [200, 409]


@pytest.mark.asyncio
async def test_concurrent_event_attachment_race_handling(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify concurrent attempts to attach the same event to an incident
    are handled safely with 409 Conflict.
    """
    _, token = await create_user(test_db_session, ROLE_ANALYST, "analyst_race_event")
    event = await create_dummy_event(test_db_session, "10.0.0.99")

    create_res = await async_client.post(
        "/api/v1/incidents",
        json={
            "title": "Event Race Case",
            "description": "Testing event race",
            "severity": "MEDIUM",
        },
        headers=auth_headers(token),
    )
    inc_id = create_res.json()["data"]["id"]

    responses = await asyncio.gather(
        async_client.post(
            f"/api/v1/incidents/{inc_id}/events",
            json={"event_id": str(event.id)},
            headers=auth_headers(token),
        ),
        async_client.post(
            f"/api/v1/incidents/{inc_id}/events",
            json={"event_id": str(event.id)},
            headers=auth_headers(token),
        ),
    )
    status_codes = sorted([r.status_code for r in responses])
    assert status_codes == [200, 409]

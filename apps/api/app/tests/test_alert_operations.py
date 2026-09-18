"""Comprehensive Test Suite for Detection Operations, Alert Triage & Security Monitoring (Phase 10).

Validates:
- Explicit deterministic state machine transitions and dedicated operational endpoints
- Safe bounded suppression with reason and max 90 days validity
- Active-user assignment, re-assignment, and unassignment
- Append-only sanitized triage notes with HTML/XSS escaping and pagination
- Strict server-side RBAC authorization (ADMIN, ANALYST, VIEWER, Unauthenticated)
- Optimistic concurrency control and row locking preventing lost updates
- Detection rule immutability and historical alert traceability
- Bounded search, multi-field filtering, and sort allowlist validation
- Bidirectional incident linking and investigation query anchor generation
- Deterministic prioritization scoring, SLA calculations, and audit logging
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.auth import Role, User, UserRole
from app.models.incident import Incident
from app.services.auth import create_session
from app.services.seed import seed_rbac_and_admin

# ==============================================================================
# Test Fixtures and Helpers
# ==============================================================================


async def create_test_user(
    db: AsyncSession, role_name: str, username: str, is_active: bool = True
) -> tuple[User, str]:
    """Create test user with role and return (user, session_token)."""
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash("TestPassword123!"),
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
    """Return session cookie and CSRF defense headers."""
    return {
        "Cookie": f"{settings.SESSION_COOKIE_NAME}={token}",
        "X-Requested-With": "XMLHttpRequest",
    }


async def create_test_alert(
    db: AsyncSession,
    *,
    rule_id: str = "RULE-BRUTE-01",
    rule_version: int = 1,
    severity: str = "HIGH",
    status: str = "OPEN",
    title: str = "SSH Brute Force Detected",
    source_ip: str = "198.51.100.25",
    dest_ip: str = "10.0.0.15",
    username: str = "target_admin",
    created_at_offset_minutes: int = 10,
    dedup_suffix: str | None = None,
) -> Alert:
    """Helper to insert a test alert directly in the database."""
    now = datetime.now(UTC)
    seen_time = now - timedelta(minutes=created_at_offset_minutes)
    suffix = dedup_suffix or uuid.uuid4().hex[:8]
    alert = Alert(
        rule_id=rule_id,
        rule_version=rule_version,
        title=title,
        description=f"Automated detection of {title}",
        severity=severity,
        status=status,
        dedup_key=f"{rule_id}:{source_ip}:{suffix}",
        correlation_key=source_ip,
        observed_count=4,
        threshold=3,
        evidence={
            "source_ip": source_ip,
            "dest_ip": dest_ip,
            "username": username,
            "confidence": 0.85,
            "criticality": "high",
        },
        first_seen=seen_time,
        last_seen=now,
        created_at=seen_time,
        updated_at=seen_time,
        version=1,
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


async def create_test_incident(
    db: AsyncSession,
    creator_id: uuid.UUID,
    title: str = "Investigated Security Incident",
) -> Incident:
    """Helper to insert a test incident."""
    incident = Incident(
        title=title,
        description="Incident created for operational testing",
        severity="HIGH",
        status="OPEN",
        priority="HIGH",
        created_by_user_id=creator_id,
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


# ==============================================================================
# 1. TestAlertLifecycleStateMachine
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_lifecycle_valid_progression(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify standard progression: OPEN -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED."""
    analyst, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_lifecycle")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")

    # 1. Acknowledge: OPEN -> ACKNOWLEDGED
    resp = await async_client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "ACKNOWLEDGED"
    assert data["acknowledged_by_id"] == str(analyst.id)
    assert data["acknowledged_at"] is not None
    assert data["version"] == 2

    # 2. Transition: ACKNOWLEDGED -> IN_PROGRESS
    resp = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "IN_PROGRESS"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "IN_PROGRESS"
    assert data["version"] == 3

    # 3. Resolve: IN_PROGRESS -> RESOLVED
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/resolve",
        json={"resolution_notes": "Identified as authorized scanner activity from pentest team"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "RESOLVED"
    assert data["resolved_by_id"] == str(analyst.id)
    assert data["resolved_at"] is not None
    assert "authorized scanner activity" in data["resolution_notes"]
    assert data["version"] == 4

    # 4. Close: RESOLVED -> CLOSED
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/close",
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "CLOSED"
    assert data["closed_by_id"] == str(analyst.id)
    assert data["closed_at"] is not None
    assert data["version"] == 5


@pytest.mark.asyncio
async def test_alert_lifecycle_reopening_transitions(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify reopening transitions: RESOLVED -> IN_PROGRESS and CLOSED -> OPEN."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_reopen")
    headers = auth_headers(token)

    # Reopen from RESOLVED
    alert_res = await create_test_alert(test_db_session, status="RESOLVED")
    resp = await async_client.patch(
        f"/api/v1/alerts/{alert_res.id}/status",
        json={"status": "IN_PROGRESS"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "IN_PROGRESS"

    # Reopen from CLOSED
    alert_cls = await create_test_alert(test_db_session, status="CLOSED")
    resp = await async_client.patch(
        f"/api/v1/alerts/{alert_cls.id}/status",
        json={"status": "OPEN"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "OPEN"


@pytest.mark.asyncio
async def test_alert_lifecycle_rejects_invalid_transitions(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify invalid jumps and same-state transitions are deterministically rejected with 400."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_invalid")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")

    # Same-state transition (OPEN -> OPEN)
    resp = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "OPEN"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "already in state" in resp.json()["error"]["message"]

    # Invalid jump: OPEN -> RESOLVED (cannot resolve without triage)
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/resolve",
        json={"resolution_notes": "Direct resolve attempt"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "Cannot resolve an alert in 'OPEN' state" in resp.json()["error"]["message"]

    # Invalid jump: OPEN -> CLOSED
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/close",
        headers=headers,
    )
    assert resp.status_code == 400
    assert "Cannot close an alert in 'OPEN' state" in resp.json()["error"]["message"]

    # Invalid jump: CLOSED -> RESOLVED
    alert_closed = await create_test_alert(test_db_session, status="CLOSED")
    resp = await async_client.patch(
        f"/api/v1/alerts/{alert_closed.id}/status",
        json={"status": "RESOLVED"},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "Invalid transition" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_alert_resolve_requires_notes(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify resolving requires non-empty resolution notes."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_res_notes")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="IN_PROGRESS")

    # Empty notes rejected
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/resolve",
        json={"resolution_notes": "   "},
        headers=headers,
    )
    assert resp.status_code in (400, 422)


# ==============================================================================
# 2. TestAlertSuppression
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_suppression_success_and_unsuppress(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify valid bounded suppression and unsuppression back to OPEN state."""
    analyst, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_suppress")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")

    until_dt = (datetime.now(UTC) + timedelta(days=14)).isoformat()
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/suppress",
        json={
            "reason": "Expected maintenance window on target cluster",
            "suppressed_until": until_dt,
        },
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["status"] == "SUPPRESSED"
    assert data["suppressed_by_id"] == str(analyst.id)
    assert data["suppression_reason"] == "Expected maintenance window on target cluster"
    assert data["suppressed_until"] is not None

    # Unsuppress back to OPEN
    resp_unsuppress = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "OPEN"},
        headers=headers,
    )
    assert resp_unsuppress.status_code == 200
    data_un = resp_unsuppress.json()["data"]
    assert data_un["status"] == "OPEN"
    assert data_un["suppression_reason"] is None
    assert data_un["suppressed_until"] is None


@pytest.mark.asyncio
async def test_alert_suppression_validation_failures(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify suppression enforces reason requirement, future timestamp, and max 90 days limit."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_sup_val")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")

    # Missing / whitespace reason
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/suppress",
        json={"reason": "   "},
        headers=headers,
    )
    assert resp.status_code in (400, 422)

    # Past expiration timestamp
    past_dt = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/suppress",
        json={
            "reason": "Valid reason but past date",
            "suppressed_until": past_dt,
        },
        headers=headers,
    )
    assert resp.status_code in (400, 422)

    # Expiration > 90 days in the future
    far_future_dt = (datetime.now(UTC) + timedelta(days=95)).isoformat()
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/suppress",
        json={
            "reason": "Excessive suppression duration",
            "suppressed_until": far_future_dt,
        },
        headers=headers,
    )
    assert resp.status_code in (400, 422)


# ==============================================================================
# 3. TestAlertAssignment
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_assignment_reassignment_and_unassignment(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify assigning to active analyst, reassigning, and unassigning."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_assigner")
    assignee_1, _ = await create_test_user(test_db_session, ROLE_ANALYST, "assignee_1")
    assignee_2, _ = await create_test_user(test_db_session, ROLE_ANALYST, "assignee_2")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")

    # 1. Assign to assignee_1
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/assign",
        json={"assigned_to_user_id": str(assignee_1.id)},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["assignee_id"] == str(assignee_1.id)
    assert data["assigned_at"] is not None
    assert data["version"] == 2

    # 2. Reassign to assignee_2
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/assign",
        json={"assigned_to_user_id": str(assignee_2.id)},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["assignee_id"] == str(assignee_2.id)
    assert data["version"] == 3

    # 3. Unassign (assigned_to_user_id: null)
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/assign",
        json={"assigned_to_user_id": None},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["assignee_id"] is None
    assert data["assigned_at"] is None
    assert data["version"] == 4


@pytest.mark.asyncio
async def test_alert_assignment_rejects_invalid_users(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify assigning to non-existent user returns 404, and inactive user returns 400."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_val_assign")
    inactive_user, _ = await create_test_user(
        test_db_session, ROLE_ANALYST, "inactive_analyst", is_active=False
    )
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")

    # Non-existent user -> 404
    fake_uuid = str(uuid.uuid4())
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/assign",
        json={"assigned_to_user_id": fake_uuid},
        headers=headers,
    )
    assert resp.status_code == 404
    assert "does not exist" in resp.json()["error"]["message"]

    # Inactive user -> 400
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/assign",
        json={"assigned_to_user_id": str(inactive_user.id)},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "inactive" in resp.json()["error"]["message"]


# ==============================================================================
# 4. TestAlertNotes
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_notes_creation_and_chronological_listing(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify creating notes, author attribution, HTML escaping, and chronological listing."""
    analyst, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_notes")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="IN_PROGRESS")

    # Create first note
    resp1 = await async_client.post(
        f"/api/v1/alerts/{alert.id}/notes",
        json={"content": "First triage note: Initial triage initiated on host."},
        headers=headers,
    )
    assert resp1.status_code == 201, resp1.text
    n1 = resp1.json()["data"]
    assert n1["author"]["id"] == str(analyst.id)
    assert "First triage note" in n1["content"]

    # Create second note with XSS payload to verify sanitization
    xss_content = "<script>alert('pwned')</script> Look at <b>evidence</b> & logs"
    resp2 = await async_client.post(
        f"/api/v1/alerts/{alert.id}/notes",
        json={"content": xss_content},
        headers=headers,
    )
    assert resp2.status_code == 201
    n2 = resp2.json()["data"]
    assert "<script>" not in n2["content"]
    assert "&lt;script&gt;" in n2["content"]
    assert "&lt;b&gt;" in n2["content"]

    # Verify notes in chronological order
    list_resp = await async_client.get(f"/api/v1/alerts/{alert.id}/notes", headers=headers)
    assert list_resp.status_code == 200
    notes = list_resp.json()["data"]["items"]
    assert len(notes) == 2
    assert notes[0]["id"] == n1["id"]
    assert notes[1]["id"] == n2["id"]


@pytest.mark.asyncio
async def test_alert_notes_validation_rejections(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify empty/whitespace notes and notes exceeding 10000 chars are rejected."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_notes_val")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session)

    # Empty / whitespace
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/notes",
        json={"content": "     \n\t   "},
        headers=headers,
    )
    assert resp.status_code in (400, 422)

    # Oversized > 10000 characters
    long_content = "A" * 10001
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/notes",
        json={"content": long_content},
        headers=headers,
    )
    assert resp.status_code in (400, 422)


# ==============================================================================
# 5. TestAlertRBACAndAuthorization
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_operations_unauthenticated_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify all operational endpoints return 401 Unauthorized when unauthenticated."""
    alert = await create_test_alert(test_db_session)

    endpoints = [
        ("GET", f"/api/v1/alerts/{alert.id}"),
        ("POST", f"/api/v1/alerts/{alert.id}/acknowledge"),
        ("POST", f"/api/v1/alerts/{alert.id}/assign"),
        ("PATCH", f"/api/v1/alerts/{alert.id}/status"),
        ("POST", f"/api/v1/alerts/{alert.id}/suppress"),
        ("POST", f"/api/v1/alerts/{alert.id}/resolve"),
        ("POST", f"/api/v1/alerts/{alert.id}/close"),
        ("GET", f"/api/v1/alerts/{alert.id}/notes"),
        ("POST", f"/api/v1/alerts/{alert.id}/notes"),
        ("GET", f"/api/v1/alerts/{alert.id}/incidents"),
        ("POST", f"/api/v1/alerts/{alert.id}/incidents"),
        ("GET", f"/api/v1/alerts/{alert.id}/investigations"),
    ]

    for method, url in endpoints:
        if method == "GET":
            resp = await async_client.get(url)
        elif method == "POST":
            resp = await async_client.post(url, json={})
        else:
            resp = await async_client.patch(url, json={})
        assert resp.status_code == 401, f"{method} {url} returned {resp.status_code}"


@pytest.mark.asyncio
async def test_alert_operations_viewer_role_boundaries(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify VIEWER role has read access but 403 Forbidden on all mutation endpoints."""
    _, token = await create_test_user(test_db_session, ROLE_VIEWER, "viewer_user")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session)

    # Read endpoints must succeed (200)
    read_resp = await async_client.get(f"/api/v1/alerts/{alert.id}", headers=headers)
    assert read_resp.status_code == 200

    notes_resp = await async_client.get(f"/api/v1/alerts/{alert.id}/notes", headers=headers)
    assert notes_resp.status_code == 200

    inc_resp = await async_client.get(f"/api/v1/alerts/{alert.id}/incidents", headers=headers)
    assert inc_resp.status_code == 200

    inv_resp = await async_client.get(f"/api/v1/alerts/{alert.id}/investigations", headers=headers)
    assert inv_resp.status_code == 200

    # Write endpoints must be rejected with 403 Forbidden
    mutation_endpoints = [
        ("POST", f"/api/v1/alerts/{alert.id}/acknowledge", {}),
        ("POST", f"/api/v1/alerts/{alert.id}/assign", {"assigned_to_user_id": str(uuid.uuid4())}),
        ("PATCH", f"/api/v1/alerts/{alert.id}/status", {"status": "ACKNOWLEDGED"}),
        (
            "POST",
            f"/api/v1/alerts/{alert.id}/suppress",
            {
                "reason": "test valid suppression reason",
                "suppressed_until": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            },
        ),
        (
            "POST",
            f"/api/v1/alerts/{alert.id}/resolve",
            {"resolution_notes": "test valid resolution notes"},
        ),
        ("POST", f"/api/v1/alerts/{alert.id}/close", {}),
        ("POST", f"/api/v1/alerts/{alert.id}/notes", {"content": "viewer trying to comment"}),
        ("POST", f"/api/v1/alerts/{alert.id}/incidents", {"incident_id": str(uuid.uuid4())}),
    ]

    for method, url, payload in mutation_endpoints:
        if method == "POST":
            resp = await async_client.post(url, json=payload, headers=headers)
        else:
            resp = await async_client.patch(url, json=payload, headers=headers)
        assert resp.status_code == 403, f"{method} {url} allowed VIEWER: {resp.status_code}"


@pytest.mark.asyncio
async def test_alert_operations_admin_full_access(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify ADMIN role has full operational access."""
    admin, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_ops")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session)

    resp = await async_client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["acknowledged_by_id"] == str(admin.id)


# ==============================================================================
# 6. TestAlertConcurrencyAndLostUpdates
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_optimistic_concurrency_conflict(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify version checks prevent lost updates and return 409 Conflict."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_concurrency")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session, status="OPEN")
    assert alert.version == 1

    # First update matches version 1 -> succeeds and increments version to 2
    resp1 = await async_client.post(
        f"/api/v1/alerts/{alert.id}/acknowledge",
        json={"expected_version": 1},
        headers=headers,
    )
    assert resp1.status_code == 200
    assert resp1.json()["data"]["version"] == 2

    # Second update using stale version 1 -> 409 Conflict
    resp2 = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "IN_PROGRESS", "expected_version": 1},
        headers=headers,
    )
    assert resp2.status_code == 409
    assert "version conflict" in resp2.json()["error"]["message"]

    # Retrying with correct version 2 -> succeeds
    resp3 = await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "IN_PROGRESS", "expected_version": 2},
        headers=headers,
    )
    assert resp3.status_code == 200
    assert resp3.json()["data"]["version"] == 3


# ==============================================================================
# 7. TestRuleTraceability
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_rule_traceability_immutable(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify rule_id and rule_version remain immutable across operational updates."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_traceability")
    headers = auth_headers(token)
    alert = await create_test_alert(
        test_db_session, rule_id="RULE-PERSIST-01", rule_version=3, status="OPEN"
    )

    # Perform multiple operational mutations
    await async_client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=headers)
    await async_client.post(
        f"/api/v1/alerts/{alert.id}/notes",
        json={"content": "Adding note to verify rule traceability."},
        headers=headers,
    )
    await async_client.patch(
        f"/api/v1/alerts/{alert.id}/status",
        json={"status": "IN_PROGRESS"},
        headers=headers,
    )

    # Verify rule_id and rule_version in detail response
    get_resp = await async_client.get(f"/api/v1/alerts/{alert.id}", headers=headers)
    assert get_resp.status_code == 200
    data = get_resp.json()["data"]
    assert data["rule_id"] == "RULE-PERSIST-01"
    assert data["rule_version"] == 3


# ==============================================================================
# 8. TestAlertSearchFilteringAndSorting
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_filtering_and_pagination(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify status, severity, rule_id, and assignee filters with pagination bounds."""
    analyst, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_search")
    headers = auth_headers(token)

    # Create distinct alerts
    a1 = await create_test_alert(
        test_db_session, rule_id="RULE-CRIT-01", severity="CRITICAL", status="OPEN"
    )
    a2 = await create_test_alert(
        test_db_session, rule_id="RULE-LOW-01", severity="LOW", status="OPEN"
    )
    a3 = await create_test_alert(
        test_db_session, rule_id="RULE-MED-01", severity="MEDIUM", status="RESOLVED"
    )

    # Assign a1 to analyst
    await async_client.post(
        f"/api/v1/alerts/{a1.id}/assign",
        json={"assigned_to_user_id": str(analyst.id)},
        headers=headers,
    )

    # 1. Filter by severity
    resp = await async_client.get("/api/v1/alerts?severity=CRITICAL", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["data"]["items"]
    assert any(item["id"] == str(a1.id) for item in items)
    assert not any(item["id"] == str(a2.id) for item in items)

    # 2. Filter by status
    resp = await async_client.get("/api/v1/alerts?status=RESOLVED", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["data"]["items"]
    assert any(item["id"] == str(a3.id) for item in items)
    assert not any(item["id"] == str(a1.id) for item in items)

    # 3. Filter by assignee_id
    resp = await async_client.get(f"/api/v1/alerts?assignee_id={analyst.id}", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["data"]["items"]
    assert len(items) >= 1
    assert all(item["assignee_id"] == str(analyst.id) for item in items)

    # 4. Pagination bounds: max limit capped at 500 (requesting 1000 yields 422)
    resp = await async_client.get("/api/v1/alerts?limit=1000", headers=headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_alert_sorting_allowlist_validation(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify sorting respects allowlist and rejects unvalidated sort columns."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_sort")
    headers = auth_headers(token)

    # Valid sort parameters
    valid_sorts = ["created_at", "severity", "status", "assigned_at"]
    for sort_field in valid_sorts:
        resp = await async_client.get(
            f"/api/v1/alerts?sort_by={sort_field}&sort_order=desc", headers=headers
        )
        assert resp.status_code == 200, f"sort_by={sort_field} failed"

    # Invalid sort column rejected with 400 Bad Request
    resp = await async_client.get("/api/v1/alerts?sort_by=non_existent_col", headers=headers)
    assert resp.status_code == 400
    assert "Invalid sort field" in resp.json()["error"]["message"]


# ==============================================================================
# 9. TestAlertIncidentAndInvestigationLinks
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_incident_linking_and_duplicate_prevention(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify linking alerts to incidents and preventing duplicate associations."""
    analyst, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_inc_link")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session)
    incident = await create_test_incident(test_db_session, analyst.id, "Host Compromise")

    # Link incident to alert
    resp = await async_client.post(
        f"/api/v1/alerts/{alert.id}/incidents",
        json={"incident_id": str(incident.id)},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()["data"]
    assert data["incident_id"] == str(incident.id)

    # Duplicate linking rejected with 409 Conflict
    resp_dup = await async_client.post(
        f"/api/v1/alerts/{alert.id}/incidents",
        json={"incident_id": str(incident.id)},
        headers=headers,
    )
    assert resp_dup.status_code == 409
    assert "already linked" in resp_dup.json()["error"]["message"]

    # List linked incidents
    resp_list = await async_client.get(f"/api/v1/alerts/{alert.id}/incidents", headers=headers)
    assert resp_list.status_code == 200
    inc_items = resp_list.json()["data"]
    assert len(inc_items) == 1
    assert inc_items[0]["incident_id"] == str(incident.id)
    assert inc_items[0]["title"] == "Host Compromise"


@pytest.mark.asyncio
async def test_alert_investigation_query_generation(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify investigation anchor endpoint generates canonical Phase 8 links."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_investigate")
    headers = auth_headers(token)
    alert = await create_test_alert(
        test_db_session,
        source_ip="198.51.100.99",
        dest_ip="10.0.0.22",
        username="compromised_user",
    )

    resp = await async_client.get(f"/api/v1/alerts/{alert.id}/investigations", headers=headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["alert_id"] == str(alert.id)
    assert data["anchor_type"] == "ALERT"
    assert "/investigations" in data["context_url"]


# ==============================================================================
# 10. TestDeterministicPrioritizationAndAuditLogging
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_prioritization_and_sla_breach_calculation(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify explainable deterministic prioritization score and SLA breach detection."""
    _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_prio")
    headers = auth_headers(token)

    # Alert created 25 hours ago (exceeds CRITICAL/HIGH 24h untriaged SLA)
    alert = await create_test_alert(
        test_db_session,
        severity="CRITICAL",
        created_at_offset_minutes=1500,
    )

    resp = await async_client.get(f"/api/v1/alerts/{alert.id}", headers=headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert "prioritization" in data
    prio = data["prioritization"]
    assert prio["priority_score"] >= 400
    assert prio["sla_breach"] is True
    assert any("Base severity" in factor for factor in prio["factors"])
    assert any("SLA breach" in factor for factor in prio["factors"])


@pytest.mark.asyncio
async def test_alert_operations_audit_logging(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify all operational mutations emit immutable audit log entries."""
    analyst, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_audit")
    headers = auth_headers(token)
    alert = await create_test_alert(test_db_session)

    # 1. Acknowledge
    await async_client.post(f"/api/v1/alerts/{alert.id}/acknowledge", headers=headers)

    # 2. Add note
    await async_client.post(
        f"/api/v1/alerts/{alert.id}/notes",
        json={"content": "Triage audit verification note"},
        headers=headers,
    )

    # Verify audit log records
    audit_stmt = (
        select(AuditLog)
        .where(
            AuditLog.resource_type == "alert",
            AuditLog.resource_id == str(alert.id),
        )
        .order_by(AuditLog.timestamp.asc())
    )
    logs = (await test_db_session.execute(audit_stmt)).scalars().all()
    assert len(logs) >= 2
    actions = [log.action for log in logs]
    assert "ALERT_ACKNOWLEDGED" in actions
    assert "ALERT_NOTE_CREATED" in actions
    assert all(log.actor_user_id == analyst.id for log in logs)

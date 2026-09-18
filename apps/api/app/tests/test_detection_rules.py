"""Comprehensive Test Suite for Detection Engineering & Rule Management (Phase 9).

Validates:
- Structured rule creation and declarative schema validation
- Immutability of published rule versions (ACTIVE, DISABLED, DEPRECATED)
- Strict server-side lifecycle state machine (DRAFT -> ACTIVE -> DISABLED -> DEPRECATED)
- Single active version per stable rule_id invariant and atomic displacement
- Database-enforced partial unique index preventing dual active versions
- Authoritative detection engine evaluation of active rules only
- Historical alert traceability linking alerts to exact rule ID and version
- Granular RBAC authorization (ADMIN, ANALYST, VIEWER, Unauthenticated)
- Append-only audit logging on all rule mutations
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash
from app.detection.engine import DetectionEngine
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.auth import Role, User, UserRole
from app.models.detection import DetectionRule
from app.models.event import Event
from app.services.auth import create_session
from app.services.seed import seed_rbac_and_admin

# ==============================================================================
# Helpers and Fixtures
# ==============================================================================


async def create_test_user(db: AsyncSession, role_name: str, username: str) -> tuple[User, str]:
    """Create test user with specified role and return user object and session token."""
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


def auth_headers(token: str) -> dict[str, str]:
    """Headers for authenticated request with session cookie and CSRF token."""
    return {
        "Cookie": f"{settings.SESSION_COOKIE_NAME}={token}",
        "X-Requested-With": "XMLHttpRequest",
    }


async def insert_event(
    db: AsyncSession,
    *,
    timestamp: datetime,
    event_type: str,
    action: str,
    source_ip: str | None = None,
    username: str | None = None,
) -> Event:
    """Helper to insert security event directly."""
    event = Event(
        id=uuid.uuid4(),
        timestamp=timestamp,
        ingested_at=datetime.now(UTC),
        source="sensor_p9",
        source_type="generic",
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        action=action,
        outcome="failure" if "failed" in action else "success",
        severity="medium",
        normalization_status="normalized",
        raw_payload={"action": action, "source_ip": source_ip},
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


# ==============================================================================
# 1. Rule Creation & Validation Tests
# ==============================================================================


@pytest.mark.asyncio
class TestRuleCreationAndValidation:
    """Tests for rule authoring, validation, and rejection of malformed definitions."""

    async def test_create_valid_rule_as_draft(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        payload = {
            "rule_id": "RULE-TEST-001",
            "name": "Test Brute Force Detection",
            "description": "Detects repeated failed logins from single IP.",
            "severity": "HIGH",
            "category": "authentication",
            "event_type": "authentication",
            "threshold": 5,
            "time_window_seconds": 300,
            "conditions": {"action": "login_failed", "group_by": "source_ip"},
        }

        resp = await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )
        assert resp.status_code == 201
        data = resp.json()["data"]
        assert data["rule_id"] == "RULE-TEST-001"
        assert data["version"] == 1
        assert data["status"] == "DRAFT"
        assert data["enabled"] is False

    async def test_create_duplicate_rule_id_conflict(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        payload = {
            "rule_id": "RULE-DUP-001",
            "name": "Duplicate Detection Rule",
            "description": "Rule to test collision prevention.",
            "severity": "MEDIUM",
            "event_type": "authentication",
            "threshold": 3,
            "time_window_seconds": 60,
            "conditions": {"group_by": "source_ip"},
        }

        resp1 = await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )
        assert resp1.status_code == 201

        # Duplicate create must fail with 409 Conflict
        resp2 = await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )
        assert resp2.status_code == 409

    async def test_validation_rejects_invalid_bounds_and_operators(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        # Invalid threshold < 1
        resp = await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-INV-001",
                "name": "Invalid Threshold Rule",
                "description": "Threshold is zero",
                "severity": "HIGH",
                "event_type": "authentication",
                "threshold": 0,
                "time_window_seconds": 300,
                "conditions": {},
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 422

        # Invalid time window < 10
        resp = await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-INV-002",
                "name": "Invalid Window Rule",
                "description": "Window is too short",
                "severity": "HIGH",
                "event_type": "authentication",
                "threshold": 5,
                "time_window_seconds": 5,
                "conditions": {},
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 422

        # Unsupported operator in conditions
        resp = await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-INV-003",
                "name": "Invalid Operator Rule",
                "description": "Uses unsupported operator",
                "severity": "HIGH",
                "event_type": "authentication",
                "threshold": 5,
                "time_window_seconds": 300,
                "conditions": {
                    "filters": [{"field": "action", "operator": "eval_code", "value": "1"}]
                },
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 422

    async def test_dry_run_validation_endpoint(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        # Valid payload
        resp = await async_client.post(
            "/api/v1/detection-rules/validate",
            json={
                "rule_id": "RULE-DRY-001",
                "name": "Dry Run Rule",
                "description": "Dry run testing",
                "severity": "LOW",
                "event_type": "network",
                "threshold": 10,
                "time_window_seconds": 120,
                "conditions": {"group_by": "source_ip"},
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 200
        assert resp.json()["data"]["valid"] is True
        assert resp.json()["data"]["errors"] == []

        # Invalid payload
        resp_inv = await async_client.post(
            "/api/v1/detection-rules/validate",
            json={
                "rule_id": "bad id with spaces",
                "threshold": -5,
                "time_window_seconds": 999999,
            },
            headers=auth_headers(token),
        )
        assert resp_inv.status_code == 200
        assert resp_inv.json()["data"]["valid"] is False
        assert len(resp_inv.json()["data"]["errors"]) > 0


# ==============================================================================
# 2. Lifecycle State Machine Tests
# ==============================================================================


@pytest.mark.asyncio
class TestRuleLifecycleStateMachine:
    """Tests for deterministic state transitions (DRAFT -> ACTIVE -> DISABLED -> DEPRECATED)."""

    async def test_full_valid_lifecycle_transitions(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        # 1. Create DRAFT
        payload = {
            "rule_id": "RULE-LIFE-001",
            "name": "Lifecycle Test Rule",
            "description": "Tests all valid lifecycle transitions.",
            "severity": "HIGH",
            "event_type": "authentication",
            "threshold": 5,
            "time_window_seconds": 300,
            "conditions": {"action": "login_failed", "group_by": "source_ip"},
        }
        create_resp = await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )
        assert create_resp.status_code == 201
        assert create_resp.json()["data"]["status"] == "DRAFT"

        # 2. DRAFT -> ACTIVE
        act_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-LIFE-001/versions/1/activate",
            headers=auth_headers(token),
        )
        assert act_resp.status_code == 200
        assert act_resp.json()["data"]["status"] == "ACTIVE"
        assert act_resp.json()["data"]["enabled"] is True
        assert act_resp.json()["data"]["activated_at"] is not None

        # 3. ACTIVE -> DISABLED
        dis_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-LIFE-001/versions/1/disable",
            headers=auth_headers(token),
        )
        assert dis_resp.status_code == 200
        assert dis_resp.json()["data"]["status"] == "DISABLED"
        assert dis_resp.json()["data"]["enabled"] is False

        # 4. DISABLED -> ACTIVE
        react_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-LIFE-001/versions/1/activate",
            headers=auth_headers(token),
        )
        assert react_resp.status_code == 200
        assert react_resp.json()["data"]["status"] == "ACTIVE"

        # 5. ACTIVE -> DEPRECATED
        dep_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-LIFE-001/versions/1/deprecate",
            headers=auth_headers(token),
        )
        assert dep_resp.status_code == 200
        assert dep_resp.json()["data"]["status"] == "DEPRECATED"
        assert dep_resp.json()["data"]["enabled"] is False

    async def test_invalid_state_transitions_rejected(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        payload = {
            "rule_id": "RULE-INVALID-TRANS",
            "name": "Invalid Transition Test",
            "description": "Tests invalid transitions fail closed.",
            "severity": "LOW",
            "event_type": "network",
            "threshold": 5,
            "time_window_seconds": 60,
            "conditions": {"group_by": "source_ip"},
        }
        await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )

        # DRAFT -> DISABLED (invalid transition)
        dis_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-INVALID-TRANS/versions/1/disable",
            headers=auth_headers(token),
        )
        assert dis_resp.status_code == 400

        # Activate
        await async_client.post(
            "/api/v1/detection-rules/RULE-INVALID-TRANS/versions/1/activate",
            headers=auth_headers(token),
        )

        # Same state transition: ACTIVE -> ACTIVE rejected
        same_act = await async_client.post(
            "/api/v1/detection-rules/RULE-INVALID-TRANS/versions/1/activate",
            headers=auth_headers(token),
        )
        assert same_act.status_code == 400

        # Deprecate to terminal
        await async_client.post(
            "/api/v1/detection-rules/RULE-INVALID-TRANS/versions/1/deprecate",
            headers=auth_headers(token),
        )

        # DEPRECATED -> ACTIVE rejected (terminal state)
        react_dep = await async_client.post(
            "/api/v1/detection-rules/RULE-INVALID-TRANS/versions/1/activate",
            headers=auth_headers(token),
        )
        assert react_dep.status_code == 400


# ==============================================================================
# 3. Rule Versioning & Immutability Tests
# ==============================================================================


@pytest.mark.asyncio
class TestRuleVersioningAndImmutability:
    """Tests for immutable published versions and subsequent version drafting."""

    async def test_draft_is_editable_published_is_immutable(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        payload = {
            "rule_id": "RULE-IMMUT-001",
            "name": "Original Name",
            "description": "Original description",
            "severity": "LOW",
            "event_type": "web",
            "threshold": 10,
            "time_window_seconds": 120,
            "conditions": {"action": "http_401", "group_by": "source_ip"},
        }
        await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )

        # 1. Edit DRAFT version -> succeeds
        edit_resp = await async_client.put(
            "/api/v1/detection-rules/RULE-IMMUT-001/versions/1",
            json={"name": "Updated Draft Name", "threshold": 20},
            headers=auth_headers(token),
        )
        assert edit_resp.status_code == 200
        assert edit_resp.json()["data"]["name"] == "Updated Draft Name"
        assert edit_resp.json()["data"]["threshold"] == 20

        # 2. Activate rule
        await async_client.post(
            "/api/v1/detection-rules/RULE-IMMUT-001/versions/1/activate",
            headers=auth_headers(token),
        )

        # 3. Edit ACTIVE version -> fails with 409 Conflict
        fail_edit = await async_client.put(
            "/api/v1/detection-rules/RULE-IMMUT-001/versions/1",
            json={"name": "Illegal Edit"},
            headers=auth_headers(token),
        )
        assert fail_edit.status_code == 409

    async def test_create_subsequent_version(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        payload = {
            "rule_id": "RULE-VER-001",
            "name": "Version Test Rule",
            "description": "Initial version description",
            "severity": "MEDIUM",
            "event_type": "authentication",
            "threshold": 5,
            "time_window_seconds": 300,
            "conditions": {"group_by": "source_ip"},
        }
        await async_client.post(
            "/api/v1/detection-rules", json=payload, headers=auth_headers(token)
        )

        # Create version 2
        v2_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-VER-001/versions",
            json={"threshold": 15, "description": "Tuned threshold in v2"},
            headers=auth_headers(token),
        )
        assert v2_resp.status_code == 201
        v2_data = v2_resp.json()["data"]
        assert v2_data["version"] == 2
        assert v2_data["status"] == "DRAFT"
        assert v2_data["threshold"] == 15

        # Inspect version history
        hist_resp = await async_client.get(
            "/api/v1/detection-rules/RULE-VER-001/versions",
            headers=auth_headers(token),
        )
        assert hist_resp.status_code == 200
        versions = hist_resp.json()["data"]
        assert len(versions) == 2
        assert versions[0]["version"] == 2
        assert versions[1]["version"] == 1


# ==============================================================================
# 4. Single Active Version Invariant & Concurrency Protection
# ==============================================================================


@pytest.mark.asyncio
class TestActiveVersionInvariant:
    """Tests that only one version per rule_id can be ACTIVE, enforced at DB and service layer."""

    async def test_activating_v2_displaces_v1(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_user")

        # 1. Create v1 and activate
        await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-INVAR-001",
                "name": "Invariant Test Rule",
                "description": "Testing single active version invariant.",
                "severity": "HIGH",
                "event_type": "authentication",
                "threshold": 5,
                "time_window_seconds": 300,
                "conditions": {"group_by": "source_ip"},
            },
            headers=auth_headers(token),
        )
        await async_client.post(
            "/api/v1/detection-rules/RULE-INVAR-001/versions/1/activate",
            headers=auth_headers(token),
        )

        # 2. Create v2
        await async_client.post(
            "/api/v1/detection-rules/RULE-INVAR-001/versions",
            json={"threshold": 10},
            headers=auth_headers(token),
        )

        # 3. Activate v2
        act_v2 = await async_client.post(
            "/api/v1/detection-rules/RULE-INVAR-001/versions/2/activate",
            headers=auth_headers(token),
        )
        assert act_v2.status_code == 200
        assert act_v2.json()["data"]["status"] == "ACTIVE"

        # 4. Verify v1 was displaced to DISABLED
        v1_resp = await async_client.get(
            "/api/v1/detection-rules/RULE-INVAR-001/versions/1",
            headers=auth_headers(token),
        )
        assert v1_resp.status_code == 200
        assert v1_resp.json()["data"]["status"] == "DISABLED"
        assert v1_resp.json()["data"]["enabled"] is False

    async def test_database_partial_unique_index_prevents_dual_active(
        self, test_db_session: AsyncSession
    ) -> None:
        """Verify the database partial unique index enforces uniqueness."""
        rule1 = DetectionRule(
            rule_id="RULE-INDEX-TEST",
            version=1,
            name="Active Rule 1",
            description="Testing DB constraint",
            severity="HIGH",
            event_type="authentication",
            threshold=5,
            time_window_seconds=300,
            status="ACTIVE",
            enabled=True,
            conditions={},
        )
        test_db_session.add(rule1)
        await test_db_session.commit()

        # Attempting to insert another ACTIVE row for same rule_id must raise IntegrityError
        rule2 = DetectionRule(
            rule_id="RULE-INDEX-TEST",
            version=2,
            name="Active Rule 2",
            description="Testing DB constraint violation",
            severity="HIGH",
            event_type="authentication",
            threshold=10,
            time_window_seconds=300,
            status="ACTIVE",
            enabled=True,
            conditions={},
        )
        test_db_session.add(rule2)

        with pytest.raises(IntegrityError):
            await test_db_session.commit()
        await test_db_session.rollback()


# ==============================================================================
# 5. Detection Engine Integration & Alert Traceability Tests
# ==============================================================================


@pytest.mark.asyncio
class TestDetectionEngineIntegrationAndTraceability:
    """Tests that active database rules drive the engine, non-active rules are ignored,

    and generated alerts preserve exact rule_id and rule_version.
    """

    async def test_only_active_rules_execute(self, test_db_session: AsyncSession) -> None:
        # Seed RBAC and default rules
        await seed_rbac_and_admin(test_db_session)

        # Disable RULE-001 in DB
        stmt = select(DetectionRule).where(DetectionRule.rule_id == "RULE-001")
        rule_001 = (await test_db_session.execute(stmt)).scalar_one()
        rule_001.status = "DISABLED"
        rule_001.enabled = False
        await test_db_session.commit()

        engine = DetectionEngine()
        base_time = datetime(2026, 9, 18, 8, 0, 0, tzinfo=UTC)

        # Insert 5 failed logins for source IP
        events = []
        for i in range(5):
            ev = await insert_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="10.10.10.50",
            )
            events.append(ev)

        # Evaluate last event -> should NOT trigger alert because RULE-001 is DISABLED!
        alerts = await engine.evaluate_event(test_db_session, events[-1])
        assert len(alerts) == 0

        # Now re-activate RULE-001
        rule_001.status = "ACTIVE"
        rule_001.enabled = True
        await test_db_session.commit()

        # Evaluate again -> triggers alert!
        alerts_active = await engine.evaluate_event(test_db_session, events[-1])
        assert len(alerts_active) == 1
        assert alerts_active[0].rule_id == "RULE-001"
        assert alerts_active[0].rule_version == 1

    async def test_alert_version_traceability_and_immutability(
        self, test_db_session: AsyncSession
    ) -> None:
        """Verify alert created under v1 retains v1 even after v2 is created and activated."""
        await seed_rbac_and_admin(test_db_session)
        engine = DetectionEngine()
        base_time = datetime(2026, 9, 18, 9, 0, 0, tzinfo=UTC)

        # Trigger initial alert under v1
        for i in range(5):
            ev = await insert_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="10.20.30.40",
            )
        alerts_v1 = await engine.evaluate_event(test_db_session, ev)
        assert len(alerts_v1) == 1
        v1_alert_id = alerts_v1[0].id
        assert alerts_v1[0].rule_version == 1

        # Now create and activate version 2 with threshold = 10
        stmt = select(DetectionRule).where(
            DetectionRule.rule_id == "RULE-001", DetectionRule.status == "ACTIVE"
        )
        rule_v1 = (await test_db_session.execute(stmt)).scalar_one()
        rule_v1.status = "DISABLED"
        rule_v1.enabled = False

        rule_v2 = DetectionRule(
            rule_id="RULE-001",
            version=2,
            name="Brute Force Login v2",
            description="Tuned to 10 failures",
            severity="HIGH",
            event_type="authentication",
            threshold=10,
            time_window_seconds=300,
            status="ACTIVE",
            enabled=True,
            conditions={"action": "login_failed", "group_by": "source_ip"},
        )
        test_db_session.add(rule_v2)
        await test_db_session.commit()

        # Verify historical alert STILL references version 1
        alert_row = (
            await test_db_session.execute(select(Alert).where(Alert.id == v1_alert_id))
        ).scalar_one()
        assert alert_row.rule_id == "RULE-001"
        assert alert_row.rule_version == 1


# ==============================================================================
# 6. RBAC Authorization & Security Tests
# ==============================================================================


@pytest.mark.asyncio
class TestDetectionRulesRBAC:
    """Tests role-based access control across ADMIN, ANALYST, VIEWER, and unauthenticated users."""

    async def test_admin_has_full_rule_management_access(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_rbac")

        # Create rule
        resp = await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-RBAC-ADMIN",
                "name": "Admin Managed Rule",
                "description": "Full lifecycle test",
                "severity": "LOW",
                "event_type": "web",
                "threshold": 5,
                "time_window_seconds": 60,
                "conditions": {"group_by": "source_ip"},
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 201

        # Deprecate rule (admin only)
        dep_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-RBAC-ADMIN/versions/1/deprecate",
            headers=auth_headers(token),
        )
        assert dep_resp.status_code == 200

    async def test_analyst_can_manage_but_cannot_deprecate(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ANALYST, "analyst_rbac")

        # Analyst can create
        resp = await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-RBAC-ANALYST",
                "name": "Analyst Rule",
                "description": "Testing analyst permissions",
                "severity": "MEDIUM",
                "event_type": "authentication",
                "threshold": 5,
                "time_window_seconds": 120,
                "conditions": {"group_by": "source_ip"},
            },
            headers=auth_headers(token),
        )
        assert resp.status_code == 201

        # Analyst can activate
        act_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-RBAC-ANALYST/versions/1/activate",
            headers=auth_headers(token),
        )
        assert act_resp.status_code == 200

        # Analyst cannot deprecate -> 403 Forbidden
        dep_resp = await async_client.post(
            "/api/v1/detection-rules/RULE-RBAC-ANALYST/versions/1/deprecate",
            headers=auth_headers(token),
        )
        assert dep_resp.status_code == 403

    async def test_viewer_is_strictly_read_only(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_VIEWER, "viewer_rbac")

        # Viewer can list rules
        list_resp = await async_client.get("/api/v1/detection-rules", headers=auth_headers(token))
        assert list_resp.status_code == 200

        # Viewer cannot create -> 403
        create_resp = await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-VIEWER-FORBID",
                "name": "Unauthorized Rule",
                "description": "Should fail",
                "severity": "LOW",
                "event_type": "web",
                "threshold": 5,
                "time_window_seconds": 60,
                "conditions": {},
            },
            headers=auth_headers(token),
        )
        assert create_resp.status_code == 403

    async def test_unauthenticated_request_rejected(self, async_client: AsyncClient) -> None:
        resp = await async_client.get("/api/v1/detection-rules")
        assert resp.status_code == 401


# ==============================================================================
# 7. Append-Only Audit Logging Tests
# ==============================================================================


@pytest.mark.asyncio
class TestDetectionRulesAuditLogging:
    """Tests that security-sensitive rule actions generate immutable audit log entries."""

    async def test_audit_logs_recorded_for_rule_lifecycle(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        admin_user, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_audit")

        # 1. Create rule
        await async_client.post(
            "/api/v1/detection-rules",
            json={
                "rule_id": "RULE-AUDIT-001",
                "name": "Audited Rule",
                "description": "Testing audit log creation",
                "severity": "HIGH",
                "event_type": "authentication",
                "threshold": 5,
                "time_window_seconds": 300,
                "conditions": {"group_by": "source_ip"},
            },
            headers=auth_headers(token),
        )

        # 2. Activate rule
        await async_client.post(
            "/api/v1/detection-rules/RULE-AUDIT-001/versions/1/activate",
            headers=auth_headers(token),
        )

        # Query audit logs for this rule
        audit_entries = (
            (
                await test_db_session.execute(
                    select(AuditLog).where(
                        AuditLog.resource_type == "detection_rule",
                        AuditLog.resource_id == "RULE-AUDIT-001:v1",
                    )
                )
            )
            .scalars()
            .all()
        )

        actions = [entry.action for entry in audit_entries]
        assert "RULE_CREATED" in actions
        assert "RULE_ACTIVATED" in actions
        for entry in audit_entries:
            assert entry.actor_user_id == admin_user.id


# ==============================================================================
# 8. Listing, Pagination & Filtering Tests
# ==============================================================================


@pytest.mark.asyncio
class TestDetectionRulesListingAndFiltering:
    """Tests for paginated rule querying, filtering by status, severity, category, event_type."""

    async def test_list_rules_pagination_and_filtering(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, token = await create_test_user(test_db_session, ROLE_ADMIN, "admin_list")

        # Create multiple rules with different statuses and severities
        rules_data = [
            {
                "rule_id": f"RULE-PAGE-{i:02d}",
                "name": f"Rule {i}",
                "severity": "HIGH" if i % 2 == 0 else "LOW",
                "category": "web" if i % 2 == 0 else "network",
            }
            for i in range(1, 6)
        ]
        for r in rules_data:
            await async_client.post(
                "/api/v1/detection-rules",
                json={
                    "rule_id": r["rule_id"],
                    "name": r["name"],
                    "description": "Pagination test rule",
                    "severity": r["severity"],
                    "category": r["category"],
                    "event_type": "web" if r["category"] == "web" else "network",
                    "threshold": 5,
                    "time_window_seconds": 60,
                    "conditions": {"group_by": "source_ip"},
                },
                headers=auth_headers(token),
            )

        # 1. Test pagination limit=2, page=1 for status=DRAFT
        resp_p1 = await async_client.get(
            "/api/v1/detection-rules?status=DRAFT&page=1&limit=2",
            headers=auth_headers(token),
        )
        assert resp_p1.status_code == 200
        data_p1 = resp_p1.json()["data"]
        assert len(data_p1["items"]) == 2
        assert data_p1["page"] == 1
        assert data_p1["limit"] == 2
        assert data_p1["total"] == 5

        # 2. Test filter by severity=HIGH
        resp_sev = await async_client.get(
            "/api/v1/detection-rules?status=DRAFT&severity=HIGH",
            headers=auth_headers(token),
        )
        assert resp_sev.status_code == 200
        data_sev = resp_sev.json()["data"]
        assert all(item["severity"] == "HIGH" for item in data_sev["items"])

        # 3. Test filter by category=network
        resp_cat = await async_client.get(
            "/api/v1/detection-rules?status=DRAFT&category=network",
            headers=auth_headers(token),
        )
        assert resp_cat.status_code == 200
        data_cat = resp_cat.json()["data"]
        assert all(item["category"] == "network" for item in data_cat["items"])


# ==============================================================================
# 9. Custom Declarative Rule Evaluation Tests
# ==============================================================================


@pytest.mark.asyncio
class TestCustomDeclarativeRuleEvaluation:
    """Tests that newly authored custom declarative rules execute within DetectionEngine."""

    async def test_custom_rule_with_filters_and_distinct_aggregation(
        self, test_db_session: AsyncSession
    ) -> None:
        await seed_rbac_and_admin(test_db_session)

        # Create and activate custom rule: detects connection attempts from single IP to >= 3 ports
        custom_rule = DetectionRule(
            rule_id="RULE-CUSTOM-SCAN",
            version=1,
            name="Custom Port Scan Detector",
            description="Detects connection attempts to 3+ ports.",
            severity="MEDIUM",
            category="network",
            status="ACTIVE",
            enabled=True,
            event_type="network",
            threshold=3,
            time_window_seconds=120,
            conditions={
                "action": "connection_attempt",
                "group_by": "source_ip",
                "aggregation": "distinct_count",
                "distinct_field": "destination_port",
            },
        )
        test_db_session.add(custom_rule)
        await test_db_session.commit()

        engine = DetectionEngine()
        base_time = datetime(2026, 9, 18, 10, 0, 0, tzinfo=UTC)

        # Ingest 3 events to distinct destination ports from 192.168.10.100
        events = []
        for port in [80, 443, 8080]:
            event = Event(
                id=uuid.uuid4(),
                timestamp=base_time,
                ingested_at=base_time,
                source="firewall",
                source_type="network",
                source_ip="192.168.10.100",
                destination_port=port,
                event_type="network",
                action="connection_attempt",
                outcome="unknown",
                severity="low",
                normalization_status="normalized",
                raw_payload={"port": port},
            )
            test_db_session.add(event)
            events.append(event)
        await test_db_session.commit()

        alerts = await engine.evaluate_event(test_db_session, events[-1])
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.rule_id == "RULE-CUSTOM-SCAN"
        assert alert.rule_version == 1
        assert alert.observed_count == 3
        assert alert.source_ip == "192.168.10.100"

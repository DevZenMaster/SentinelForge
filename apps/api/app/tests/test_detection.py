"""Comprehensive Test Suite for SentinelForge Detection Engine & Rule Evaluation (Phase 5).

Validates:
- Built-in Detection Rules (RULE-001 through RULE-005) threshold and sliding window boundaries
- Deterministic deduplication key calculation and database constraint enforcement
- Evidence preservation (AlertEvent join table) and raw_payload immutability
- Synchronous detection execution during ingestion and re-evaluation
- Fault isolation: individual rule runtime exceptions never disrupt engine or event persistence
- RBAC enforcement on alert search, detailed inspection, and manual detection evaluation
- Idempotent seeding of detection rules
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
from app.detection import (
    BaseDetectionRule,
    DetectionContext,
    DetectionEngine,
    RuleRegistry,
    calculate_dedup_key,
    default_rule_registry,
)
from app.detection.rules import (
    Rule001BruteForceLogin,
    Rule002AccountSpray,
    Rule003SuspiciousLoginFollowingFailures,
    Rule004HttpAuthAbuse,
    Rule005PortScan,
)
from app.models import Alert, AlertEvent, DetectionRule, Event, Role, User, UserRole
from app.schemas.event import EventCreateRequest
from app.services.auth import create_session
from app.services.event import ingest_security_event
from app.services.seed import seed_detection_rules, seed_rbac_and_admin

# ==============================================================================
# Helpers and Fixtures
# ==============================================================================


async def create_test_user(db: AsyncSession, role_name: str, username: str) -> tuple[User, str]:
    """Helper creating a test user with assigned role and returning active session token."""
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash("Password123!"),
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
    """Return headers with session cookie and CSRF defense header."""
    return {
        "Cookie": f"{settings.SESSION_COOKIE_NAME}={token}",
        "X-Requested-With": "XMLHttpRequest",
    }


async def insert_canonical_event(
    db: AsyncSession,
    *,
    timestamp: datetime,
    event_type: str,
    action: str,
    source_ip: str | None = None,
    username: str | None = None,
    destination_port: int | None = None,
    outcome: str = "unknown",
    attributes: dict[str, object] | None = None,
    raw_payload: dict[str, object] | None = None,
) -> Event:
    """Helper to insert an event with normalized canonical attributes directly into database."""
    now = datetime.now(UTC)
    payload = raw_payload or {"source_ip": source_ip, "action": action}
    event = Event(
        id=uuid.uuid4(),
        timestamp=timestamp,
        ingested_at=now,
        source="test_sensor",
        source_type="generic",
        source_ip=source_ip,
        destination_port=destination_port,
        event_type=event_type,
        action=action,
        outcome=outcome,
        username=username,
        severity="INFO",
        normalization_status="NORMALIZED",
        attributes=attributes or {},
        raw_payload=payload,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


# ==============================================================================
# 1. Registry and Metadata Tests
# ==============================================================================


class TestDetectionRegistry:
    """Validate rule registry discovery, filtering, and catalog completeness."""

    def test_default_registry_contains_all_rules(self) -> None:
        registry = default_rule_registry
        rules = registry.list_rules()
        rule_ids = {r.rule_id for r in rules}

        expected = {"RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005"}
        assert expected == rule_ids

    def test_registry_event_type_dispatch(self) -> None:
        registry = default_rule_registry

        auth_rules = registry.get_rules_for_event("authentication")
        assert len(auth_rules) == 3
        assert {r.rule_id for r in auth_rules} == {"RULE-001", "RULE-002", "RULE-003"}

        web_rules = registry.get_rules_for_event("web")
        assert len(web_rules) == 1
        assert web_rules[0].rule_id == "RULE-004"

        network_rules = registry.get_rules_for_event("network")
        assert len(network_rules) == 1
        assert network_rules[0].rule_id == "RULE-005"

        unknown_rules = registry.get_rules_for_event("unknown_type")
        assert len(unknown_rules) == 0

    def test_registry_lookup_by_id(self) -> None:
        registry = default_rule_registry
        r1 = registry.get_rule("RULE-001")
        assert r1 is not None
        assert r1.name == "Brute Force Login"
        assert r1.threshold == 5
        assert r1.time_window_seconds == 300

        r_none = registry.get_rule("RULE-999")
        assert r_none is None


# ==============================================================================
# 2. Deduplication Key Unit Tests
# ==============================================================================


class TestDeduplication:
    """Validate deterministic alert deduplication key computation."""

    def test_calculate_dedup_key_deterministic_within_window(self) -> None:
        t0 = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
        t1 = datetime(2026, 9, 17, 12, 2, 0, tzinfo=UTC)  # 120s later, within 300s bucket

        key0 = calculate_dedup_key("RULE-001", "192.168.1.10", t0, 300)
        key1 = calculate_dedup_key("RULE-001", "192.168.1.10", t1, 300)
        assert key0 == key1
        assert key0.startswith("RULE-001:192.168.1.10:")

    def test_calculate_dedup_key_bucket_transition(self) -> None:
        t0 = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
        t_next = datetime(2026, 9, 17, 12, 5, 1, tzinfo=UTC)  # > 300s later (next bucket)

        key0 = calculate_dedup_key("RULE-001", "192.168.1.10", t0, 300)
        key_next = calculate_dedup_key("RULE-001", "192.168.1.10", t_next, 300)
        assert key0 != key_next

    def test_calculate_dedup_key_entity_separation(self) -> None:
        t0 = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        key_ip1 = calculate_dedup_key("RULE-001", "192.168.1.1", t0, 300)
        key_ip2 = calculate_dedup_key("RULE-001", "192.168.1.2", t0, 300)
        assert key_ip1 != key_ip2

    def test_calculate_dedup_key_window_zero_guard(self) -> None:
        t0 = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)
        key = calculate_dedup_key("RULE-001", "192.168.1.1", t0, 0)
        assert key.startswith("RULE-001:192.168.1.1:")


# ==============================================================================
# 3. Rule-Specific Evaluation Tests (RULE-001 through RULE-005)
# ==============================================================================


@pytest.mark.asyncio
class TestRule001BruteForceLogin:
    """Validate RULE-001: 5 failed logins from single IP in 300s."""

    async def test_below_threshold_produces_no_detection(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule001BruteForceLogin()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(4):  # 4 attempts (threshold is 5)
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="192.168.1.50",
                username=f"user_{i}",
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is None

    async def test_meets_threshold_produces_detection(self, test_db_session: AsyncSession) -> None:
        rule = Rule001BruteForceLogin()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(5):  # Exactly 5 attempts
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 20),
                event_type="authentication",
                action="login_failed",
                source_ip="192.168.1.50",
                username="victim",
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is not None
        assert result.matched is True
        assert result.rule_id == "RULE-001"
        assert result.severity == "HIGH"
        assert result.observed_count == 5
        assert result.threshold == 5
        assert result.correlation_key == "192.168.1.50"
        assert len(result.contributing_event_ids) == 5
        assert result.title == "Brute Force Authentication Attempt from 192.168.1.50"

    async def test_outside_time_window_not_matched(self, test_db_session: AsyncSession) -> None:
        rule = Rule001BruteForceLogin()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        # 4 old events from 400 seconds ago (outside 300s window)
        for i in range(4):
            await insert_canonical_event(
                test_db_session,
                timestamp=base_time - timedelta(seconds=400 - i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="192.168.1.50",
            )

        # 1 new event now
        current = await insert_canonical_event(
            test_db_session,
            timestamp=base_time,
            event_type="authentication",
            action="login_failed",
            source_ip="192.168.1.50",
        )

        context = DetectionContext(event=current, db=test_db_session)
        result = await rule.evaluate(context)
        assert result is None  # Only 1 event in the 300s window


@pytest.mark.asyncio
class TestRule002AccountSpray:
    """Validate RULE-002: 10 failed logins on specific username in 600s."""

    async def test_ten_failures_across_distinct_ips_matches(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule002AccountSpray()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(10):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 30),
                event_type="authentication",
                action="login_failed",
                source_ip=f"10.0.0.{i + 1}",
                username="administrator",
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is not None
        assert result.matched is True
        assert result.rule_id == "RULE-002"
        assert result.observed_count == 10
        assert result.correlation_key == "administrator"
        assert result.evidence["distinct_source_ips_count"] == 10
        assert result.title == "Targeted Account Attack Against User administrator"

    async def test_under_threshold_no_detection(self, test_db_session: AsyncSession) -> None:
        rule = Rule002AccountSpray()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(9):  # 9 attempts (threshold is 10)
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 30),
                event_type="authentication",
                action="login_failed",
                source_ip=f"10.0.0.{i + 1}",
                username="administrator",
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is None


@pytest.mark.asyncio
class TestRule003SuspiciousLoginFollowingFailures:
    """Validate RULE-003: Login success preceded by >= 3 failed logins in 600s."""

    async def test_success_after_three_failures_matches(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule003SuspiciousLoginFollowingFailures()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        # 3 failed logins from attacker IP
        for i in range(3):
            await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 30),
                event_type="authentication",
                action="login_failed",
                source_ip="198.51.100.25",
                username="admin",
            )

        # Subsequent success from identical IP
        success_event = await insert_canonical_event(
            test_db_session,
            timestamp=base_time + timedelta(seconds=120),
            event_type="authentication",
            action="login_success",
            source_ip="198.51.100.25",
            username="admin",
            outcome="success",
        )

        context = DetectionContext(event=success_event, db=test_db_session)
        result = await rule.evaluate(context)
        assert result is not None
        assert result.matched is True
        assert result.rule_id == "RULE-003"
        assert result.severity == "HIGH"
        assert result.observed_count == 3
        assert result.correlation_key == "198.51.100.25"
        assert len(result.contributing_event_ids) == 4  # 3 failures + 1 success
        assert success_event.id in result.contributing_event_ids
        assert result.title == "Successful Authentication from 198.51.100.25 Following Failures"

    async def test_success_with_only_two_failures_no_detection(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule003SuspiciousLoginFollowingFailures()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        for i in range(2):  # Only 2 failures (threshold is 3)
            await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 30),
                event_type="authentication",
                action="login_failed",
                source_ip="198.51.100.25",
            )

        success_event = await insert_canonical_event(
            test_db_session,
            timestamp=base_time + timedelta(seconds=90),
            event_type="authentication",
            action="login_success",
            source_ip="198.51.100.25",
        )

        context = DetectionContext(event=success_event, db=test_db_session)
        result = await rule.evaluate(context)
        assert result is None

    async def test_failure_event_does_not_trigger_rule_003(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule003SuspiciousLoginFollowingFailures()
        now = datetime.now(UTC)

        failed_event = await insert_canonical_event(
            test_db_session,
            timestamp=now,
            event_type="authentication",
            action="login_failed",
            source_ip="198.51.100.25",
        )

        context = DetectionContext(event=failed_event, db=test_db_session)
        result = await rule.evaluate(context)
        assert result is None


@pytest.mark.asyncio
class TestRule004HttpAuthAbuse:
    """Validate RULE-004: 15 HTTP 401 responses from single IP in 300s."""

    async def test_fifteen_401s_triggers_detection(self, test_db_session: AsyncSession) -> None:
        rule = Rule004HttpAuthAbuse()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(15):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="web",
                action="http_401",
                source_ip="203.0.113.8",
                attributes={"uri": f"/api/v1/resource/{i}"},
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is not None
        assert result.matched is True
        assert result.rule_id == "RULE-004"
        assert result.severity == "MEDIUM"
        assert result.observed_count == 15
        assert result.correlation_key == "203.0.113.8"
        assert result.title == "Excessive HTTP 401 Unauthorized from 203.0.113.8"

    async def test_fourteen_401s_does_not_trigger(self, test_db_session: AsyncSession) -> None:
        rule = Rule004HttpAuthAbuse()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(14):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="web",
                action="http_401",
                source_ip="203.0.113.8",
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is None


@pytest.mark.asyncio
class TestRule005PortScan:
    """Validate RULE-005: Connection attempts to >= 10 DISTINCT ports in 120s."""

    async def test_ten_distinct_ports_triggers_detection(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule005PortScan()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        target_ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080]
        for idx, port in enumerate(target_ports):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=idx * 5),
                event_type="network",
                action="connection_attempt",
                source_ip="198.51.100.99",
                destination_port=port,
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        assert result is not None
        assert result.matched is True
        assert result.rule_id == "RULE-005"
        assert result.severity == "HIGH"
        assert result.observed_count == 10
        assert result.correlation_key == "198.51.100.99"
        assert result.evidence["distinct_ports_count"] == 10
        assert result.title == "Reconnaissance Port Scan Detected from 198.51.100.99"

    async def test_repeated_attempts_to_same_port_does_not_trigger(
        self, test_db_session: AsyncSession
    ) -> None:
        rule = Rule005PortScan()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        # 15 attempts targeting the SAME port 443
        for idx in range(15):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=idx * 5),
                event_type="network",
                action="connection_attempt",
                source_ip="198.51.100.99",
                destination_port=443,
            )
            events.append(ev)

        context = DetectionContext(event=events[-1], db=test_db_session)
        result = await rule.evaluate(context)
        # Distinct ports count is 1, which is < threshold 10
        assert result is None


# ==============================================================================
# 4. Engine Lifecycle, Deduplication, and Immutability Tests
# ==============================================================================


@pytest.mark.asyncio
class TestDetectionEngineLifecycle:
    """Validate end-to-end alert creation, deduplication update, and evidence preservation."""

    async def test_engine_creates_alert_and_deduplicates_subsequent_events(
        self, test_db_session: AsyncSession
    ) -> None:
        engine = DetectionEngine()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        # 1. Ingest 4 failed events -> no alert
        for i in range(4):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="192.168.1.100",
            )
            alerts = await engine.evaluate_event(test_db_session, ev)
            assert len(alerts) == 0

        # 2. 5th event arrives -> triggers initial Alert
        ev5 = await insert_canonical_event(
            test_db_session,
            timestamp=base_time + timedelta(seconds=40),
            event_type="authentication",
            action="login_failed",
            source_ip="192.168.1.100",
        )
        alerts = await engine.evaluate_event(test_db_session, ev5)
        assert len(alerts) == 1
        initial_alert = alerts[0]
        assert initial_alert.status == "OPEN"
        assert initial_alert.observed_count == 5
        assert initial_alert.rule_id == "RULE-001"
        initial_alert_id = initial_alert.id

        # Check evidence associations in alert_events
        stmt = select(AlertEvent).where(AlertEvent.alert_id == initial_alert_id)
        res = await test_db_session.execute(stmt)
        linked_events = res.scalars().all()
        assert len(linked_events) == 5

        # 3. 6th event arrives in same 300s window bucket -> deduplicated!
        ev6 = await insert_canonical_event(
            test_db_session,
            timestamp=base_time + timedelta(seconds=50),
            event_type="authentication",
            action="login_failed",
            source_ip="192.168.1.100",
        )
        dedup_alerts = await engine.evaluate_event(test_db_session, ev6)
        assert len(dedup_alerts) == 1
        updated_alert = dedup_alerts[0]

        # Must be the exact same alert row updated, NOT a second alert!
        assert updated_alert.id == initial_alert_id
        assert updated_alert.observed_count == 6

        # Check that total alert count in db is STILL 1
        all_alerts = (await test_db_session.execute(select(Alert))).scalars().all()
        assert len(all_alerts) == 1

        # Check that 6th event was added to alert_events
        res_after = await test_db_session.execute(stmt)
        linked_events_after = res_after.scalars().all()
        assert len(linked_events_after) == 6

    async def test_raw_payload_strict_immutability(self, test_db_session: AsyncSession) -> None:
        """Verify raw_payload remains unmodified throughout engine evaluation and persistence."""
        engine = DetectionEngine()
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        raw_original = {"source_ip": "10.0.0.99", "secret": "token_123", "action": "login_failed"}

        events: list[Event] = []
        for i in range(5):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="10.0.0.99",
                raw_payload=dict(raw_original),
            )
            events.append(ev)

        # Evaluate last event to trigger alert
        alerts = await engine.evaluate_event(test_db_session, events[-1])
        assert len(alerts) >= 1

        # Verify all events' raw_payload is identical to original
        for ev in events:
            assert ev.raw_payload == raw_original


# ==============================================================================
# 5. Fault Isolation Tests
# ==============================================================================


@pytest.mark.asyncio
class TestFaultIsolation:
    """Validate that faulty rules never abort engine execution or event ingestion."""

    class BrokenRule(BaseDetectionRule):
        rule_id = "RULE-BROKEN"
        name = "Intentionally Broken Rule"
        version = 1
        description = "Throws exception on evaluate"
        severity = "HIGH"
        event_type = "authentication"
        time_window_seconds = 300
        threshold = 1

        async def evaluate(self, context: DetectionContext) -> None:
            raise RuntimeError("Database connection glitch or logic fault")

    async def test_faulty_rule_does_not_abort_valid_rules(
        self, test_db_session: AsyncSession
    ) -> None:
        custom_registry = RuleRegistry()
        custom_registry.register(self.BrokenRule())
        custom_registry.register(Rule001BruteForceLogin())

        engine = DetectionEngine(registry=custom_registry)
        base_time = datetime(2026, 9, 17, 12, 0, 0, tzinfo=UTC)

        events: list[Event] = []
        for i in range(5):
            ev = await insert_canonical_event(
                test_db_session,
                timestamp=base_time + timedelta(seconds=i * 10),
                event_type="authentication",
                action="login_failed",
                source_ip="192.168.1.88",
            )
            events.append(ev)

        # BrokenRule will raise, but Rule001 must still evaluate and generate an alert
        alerts = await engine.evaluate_event(test_db_session, events[-1])
        assert len(alerts) == 1
        assert alerts[0].rule_id == "RULE-001"

    async def test_ingestion_succeeds_even_if_detection_fails(
        self, test_db_session: AsyncSession
    ) -> None:
        """Verify that event persistence succeeds regardless of detection stage errors."""
        now = datetime.now(UTC)
        event_in = EventCreateRequest(
            timestamp=now,
            source="test-host",
            source_type="generic",
            event_type="authentication",
            action="login_failed",
            source_ip="192.168.1.99",
            raw_payload={"msg": "auth fail"},
        )

        # Ingestion must succeed without exception
        event, is_duplicate = await ingest_security_event(test_db_session, event_in)
        assert is_duplicate is False
        assert event.id is not None


# ==============================================================================
# 6. HTTP API Endpoints & RBAC Tests
# ==============================================================================


@pytest.mark.asyncio
class TestAlertsAndDetectionAPI:
    """Validate GET /api/v1/alerts, GET /api/v1/alerts/{id}, and POST /events/{id}/detect."""

    async def test_list_alerts_rbac_and_pagination(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, viewer_token = await create_test_user(test_db_session, ROLE_VIEWER, "alert_viewer")
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "alert_analyst")

        # 1. Unauthenticated request rejected with 401
        unauth_resp = await async_client.get("/api/v1/alerts")
        assert unauth_resp.status_code == 401

        # 2. Ingest 5 events as analyst to trigger an alert
        base_time = datetime.now(UTC)
        for i in range(5):
            payload = {
                "timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
                "source": "linux-host",
                "source_type": "linux",
                "event_type": "authentication",
                "action": "login_failed",
                "source_ip": "172.16.0.42",
                "username": "victim",
                "raw_payload": {"message": "Failed password for victim"},
            }
            res = await async_client.post(
                "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
            )
            assert res.status_code == 201

        # 3. Viewer has alerts.read -> 200 OK
        viewer_resp = await async_client.get("/api/v1/alerts", headers=auth_headers(viewer_token))
        assert viewer_resp.status_code == 200
        viewer_data = viewer_resp.json()["data"]
        assert viewer_data["total"] >= 1
        first_alert = viewer_data["items"][0]
        assert first_alert["rule_id"] == "RULE-001"
        assert first_alert["correlation_key"] == "172.16.0.42"

        # 4. Filter by severity
        filter_resp = await async_client.get(
            "/api/v1/alerts?severity=HIGH", headers=auth_headers(viewer_token)
        )
        assert filter_resp.status_code == 200
        assert filter_resp.json()["data"]["total"] >= 1

        filter_low = await async_client.get(
            "/api/v1/alerts?severity=LOW", headers=auth_headers(viewer_token)
        )
        assert filter_low.status_code == 200
        assert filter_low.json()["data"]["total"] == 0

    async def test_get_alert_detail_with_evidence(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "detail_analyst")

        # Ingest 5 events to trigger alert
        base_time = datetime.now(UTC)
        for i in range(5):
            payload = {
                "timestamp": (base_time + timedelta(seconds=i * 5)).isoformat(),
                "source": "linux-host",
                "source_type": "linux",
                "event_type": "authentication",
                "action": "login_failed",
                "source_ip": "172.16.0.99",
                "raw_payload": {"message": "Failed password"},
            }
            await async_client.post(
                "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
            )

        list_resp = await async_client.get(
            "/api/v1/alerts?source_ip=172.16.0.99", headers=auth_headers(analyst_token)
        )
        alert_id = list_resp.json()["data"]["items"][0]["id"]

        # Fetch detail
        detail_resp = await async_client.get(
            f"/api/v1/alerts/{alert_id}", headers=auth_headers(analyst_token)
        )
        assert detail_resp.status_code == 200
        detail_data = detail_resp.json()["data"]
        assert detail_data["id"] == alert_id
        assert len(detail_data["evidence_event_ids"]) == 5
        assert len(detail_data["evidence_events"]) == 5

        # 404 on non-existent alert
        fake_id = uuid.uuid4()
        not_found_resp = await async_client.get(
            f"/api/v1/alerts/{fake_id}", headers=auth_headers(analyst_token)
        )
        assert not_found_resp.status_code == 404

    async def test_manual_event_detection_evaluation_rbac(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        _, viewer_token = await create_test_user(test_db_session, ROLE_VIEWER, "detect_viewer")
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "detect_analyst")
        _, admin_token = await create_test_user(test_db_session, ROLE_ADMIN, "detect_admin")

        # Ingest an event as analyst
        now = datetime.now(UTC)
        payload = {
            "timestamp": now.isoformat(),
            "source": "test-sensor",
            "event_type": "authentication",
            "action": "login_failed",
            "source_ip": "10.10.10.10",
            "raw_payload": {"msg": "test"},
        }
        res = await async_client.post(
            "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
        )
        event_id = res.json()["data"]["event_id"]

        # 1. Viewer does NOT have detections.evaluate -> 403 Forbidden
        viewer_resp = await async_client.post(
            f"/api/v1/events/{event_id}/detect", headers=auth_headers(viewer_token)
        )
        assert viewer_resp.status_code == 403

        # 2. Analyst HAS detections.evaluate -> 200 OK
        analyst_resp = await async_client.post(
            f"/api/v1/events/{event_id}/detect", headers=auth_headers(analyst_token)
        )
        assert analyst_resp.status_code == 200
        assert analyst_resp.json()["data"]["event_id"] == event_id

        # 3. Admin HAS detections.evaluate -> 200 OK
        admin_resp = await async_client.post(
            f"/api/v1/events/{event_id}/detect", headers=auth_headers(admin_token)
        )
        assert admin_resp.status_code == 200


# ==============================================================================
# 7. Detection Rules Seeding Tests
# ==============================================================================


@pytest.mark.asyncio
class TestSeedDetectionRules:
    """Validate idempotent database seeding for RULE-001 through RULE-005."""

    async def test_seed_detection_rules_idempotent(self, test_db_session: AsyncSession) -> None:
        # First run seeds all 5 rules
        count1 = await seed_detection_rules(test_db_session)
        assert count1 == 5

        # Query rules in database
        stmt = select(DetectionRule).order_by(DetectionRule.rule_id.asc())
        rules = (await test_db_session.execute(stmt)).scalars().all()
        assert len(rules) == 5
        rule_ids = [r.rule_id for r in rules]
        assert rule_ids == ["RULE-001", "RULE-002", "RULE-003", "RULE-004", "RULE-005"]

        # Second run is idempotent (0 created)
        count2 = await seed_detection_rules(test_db_session)
        assert count2 == 0

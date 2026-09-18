"""Investigation Analytics and Correlation Test Suite (Phase 8).

Verifies:
1. Investigation Anchor Resolution & Domain Validation
2. Bounded Temporal Window Constraints (max 30 days, UTC timestamps)
3. Cross-Entity Correlation Traversals:
   - Incident -> Alerts -> Events -> Indicators -> Threat Intelligence
   - Alert -> Events -> Indicators -> Incidents
   - Indicator -> Events -> Alerts -> Incidents
   - Source IP, Destination IP, and Username Pivoting
4. Deterministic Investigation Summary Metrics (verified against direct DB truth)
5. Unified Investigation Timeline Ordering & Deterministic Tie-Breaking
6. Evidence Preservation & Forensic Immutability
7. Granular RBAC Permissions (ADMIN, ANALYST, VIEWER, Unauthenticated)
8. Security Edge Cases: IDOR 404s, SQL Injection Resistance, Parameter Tampering
9. Query Result Determinism on Repeated Invocations
10. Multi-Source Threat Intelligence Conflict Handling
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
)
from app.core.security import get_password_hash
from app.models.alert import Alert, AlertEvent
from app.models.auth import Role, User, UserRole
from app.models.event import Event
from app.models.incident import Incident, IncidentAlert, IncidentEvent, IncidentNote
from app.models.indicator import (
    Indicator,
    IndicatorType,
    ThreatClassification,
    ThreatIntelligence,
)
from app.schemas.event import EventCreateRequest
from app.schemas.indicator import ThreatIntelligenceCreateRequest
from app.schemas.investigation import (
    InvestigationAnchor,
    InvestigationAnchorType,
)
from app.services.auth import create_session
from app.services.intelligence import add_threat_intelligence, create_or_get_indicator, enrich_event
from app.services.investigation import (
    InvestigationTargetNotFoundError,
    InvestigationValidationError,
    get_correlated_alerts,
    get_correlated_events,
    get_correlated_incidents,
    get_correlated_indicators,
    get_investigation_context,
    get_investigation_summary,
    get_investigation_timeline,
    resolve_investigation_anchor,
)
from app.services.seed import seed_rbac_and_admin

# ==============================================================================
# Fixtures & Helpers
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
    """Return headers with session cookie and CSRF header."""
    return {
        "Cookie": f"{settings.SESSION_COOKIE_NAME}={token}",
        "X-Requested-With": "XMLHttpRequest",
    }


async def create_test_event(
    db: AsyncSession,
    source_ip: str = "198.51.100.42",
    dest_ip: str = "203.0.113.10",
    username: str = "target_analyst",
    event_type: str = "network",
    action: str = "connection_established",
    severity: str = "HIGH",
    timestamp: datetime | None = None,
) -> Event:
    """Helper to persist a test event with rich telemetry."""
    if timestamp is None:
        timestamp = datetime.now(UTC) - timedelta(minutes=10)
    user, _ = await create_user(db, ROLE_ANALYST, f"ingest_{uuid.uuid4().hex[:6]}")
    payload = EventCreateRequest(
        timestamp=timestamp,
        source="network_sensor",
        source_type="network",
        source_ip=source_ip,
        destination_ip=dest_ip,
        destination_port=443,
        event_type=event_type,
        action=action,
        username=username,
        severity=severity,
        raw_payload={
            "src": source_ip,
            "dst": dest_ip,
            "user": username,
            "signature": "C2 Traffic Detected",
        },
    )
    event = Event(
        timestamp=payload.timestamp,
        source=payload.source,
        source_type=payload.source_type,
        source_ip=payload.source_ip,
        destination_ip=payload.destination_ip,
        destination_port=payload.destination_port,
        event_type=payload.event_type,
        action=payload.action,
        username=payload.username,
        severity=payload.severity,
        raw_payload=payload.raw_payload,
        attributes={"domain": "c2-domain.com"},
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


# ==============================================================================
# 1. Investigation Anchor Resolution & Validation
# ==============================================================================


@pytest.mark.asyncio
async def test_resolve_anchor_by_incident_uuid_and_human_id(test_db_session: AsyncSession) -> None:
    """Verify resolving incident anchors using both UUID primary key and ticket ID."""
    user, _ = await create_user(test_db_session, ROLE_ADMIN, "admin_inc_res")
    incident = Incident(
        incident_id="INC-2026-999901",
        title="Command and Control Investigation",
        description="Active C2 beaconing investigation",
        severity="HIGH",
        priority="HIGH",
        status="OPEN",
        created_by_user_id=user.id,
    )
    test_db_session.add(incident)
    await test_db_session.commit()

    # Resolve by UUID
    anchor1, ctx1 = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INCIDENT,
        anchor_value=str(incident.id),
    )
    assert anchor1.anchor_type == InvestigationAnchorType.INCIDENT
    assert ctx1["incident"].id == incident.id

    # Resolve by human ticket ID
    anchor2, ctx2 = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INCIDENT,
        anchor_value="inc-2026-999901",  # case insensitive
    )
    assert ctx2["incident"].id == incident.id


@pytest.mark.asyncio
async def test_resolve_anchor_by_alert_and_indicator(test_db_session: AsyncSession) -> None:
    """Verify resolving alert and indicator anchors with database validation."""
    alert = Alert(
        rule_id="RULE-NET-01",
        rule_version=1,
        title="High Volume Outbound Traffic",
        description="Host communicated with untrusted IP",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key="198.51.100.77",
        observed_count=1,
        threshold=1,
        source_ip="198.51.100.77",
        first_seen=datetime.now(UTC) - timedelta(minutes=5),
        last_seen=datetime.now(UTC),
    )
    test_db_session.add(alert)

    indicator, _ = await create_or_get_indicator(
        test_db_session, type=IndicatorType.DOMAIN, value="malicious-c2.org"
    )
    await test_db_session.commit()

    # Resolve Alert
    _, ctx_alert = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.ALERT,
        anchor_value=str(alert.id),
    )
    assert ctx_alert["alert"].id == alert.id

    # Resolve Indicator by UUID and normalized value
    _, ctx_ind1 = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INDICATOR,
        anchor_value=str(indicator.id),
    )
    assert ctx_ind1["indicator"].id == indicator.id

    _, ctx_ind2 = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INDICATOR,
        anchor_value="malicious-c2.org",
    )
    assert ctx_ind2["indicator"].id == indicator.id


@pytest.mark.asyncio
async def test_resolve_anchor_validation_failures(test_db_session: AsyncSession) -> None:
    """Verify anchor resolution rejects empty, invalid syntax, or non-existent entities."""
    # Empty anchor value
    with pytest.raises(InvestigationValidationError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.INCIDENT,
            anchor_value="   ",
        )

    # Invalid IP address syntax
    with pytest.raises(InvestigationValidationError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.SOURCE_IP,
            anchor_value="not-an-ip-address",
        )

    # Non-existent Incident UUID
    with pytest.raises(InvestigationTargetNotFoundError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.INCIDENT,
            anchor_value=str(uuid.uuid4()),
        )

    # Non-existent Alert UUID
    with pytest.raises(InvestigationTargetNotFoundError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.ALERT,
            anchor_value=str(uuid.uuid4()),
        )

    # Non-existent Indicator
    with pytest.raises(InvestigationTargetNotFoundError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.INDICATOR,
            anchor_value="non-existent-domain-12345.xyz",
        )


# ==============================================================================
# 2. Bounded Temporal Window Constraints
# ==============================================================================


@pytest.mark.asyncio
async def test_temporal_window_bounds_validation(test_db_session: AsyncSession) -> None:
    """Verify strict rejection of invalid time ranges, start > end, and windows > 30 days."""
    now = datetime.now(UTC)

    # 1. start_time > end_time rejected
    with pytest.raises(InvestigationValidationError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.SOURCE_IP,
            anchor_value="198.51.100.1",
            start_time=now,
            end_time=now - timedelta(hours=1),
        )

    # 2. window_seconds <= 0 rejected
    with pytest.raises(InvestigationValidationError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.SOURCE_IP,
            anchor_value="198.51.100.1",
            window_seconds=0,
        )

    # 3. window_seconds > 30 days (2,592,000 seconds) rejected
    with pytest.raises(InvestigationValidationError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.SOURCE_IP,
            anchor_value="198.51.100.1",
            window_seconds=2592001,
        )

    # 4. Explicit range exceeding 30 days rejected
    with pytest.raises(InvestigationValidationError):
        await resolve_investigation_anchor(
            test_db_session,
            anchor_type=InvestigationAnchorType.SOURCE_IP,
            anchor_value="198.51.100.1",
            start_time=now - timedelta(days=31),
            end_time=now,
        )


# ==============================================================================
# 3. Cross-Entity Correlation Traversal Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_full_incident_investigation_correlation_graph(test_db_session: AsyncSession) -> None:
    """Verify 360-degree traversal: Incident -> Alerts -> Events -> Indicators -> Intel."""
    user, _ = await create_user(test_db_session, ROLE_ADMIN, "admin_graph")
    shared_ip = "198.51.100.55"

    # 1. Create Event 1 (direct to Incident)
    ev1 = await create_test_event(test_db_session, source_ip=shared_ip, username="user_victim")
    await enrich_event(test_db_session, ev1.id)

    # 2. Create Event 2 (linked via Alert)
    ev2 = await create_test_event(test_db_session, source_ip=shared_ip, username="user_victim")
    await enrich_event(test_db_session, ev2.id)

    # 3. Create Alert linked to Event 2
    alert = Alert(
        rule_id="RULE-C2-01",
        rule_version=1,
        title="Beacon to C2 Detected",
        description="Repeated connections to known malicious server",
        severity="CRITICAL",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key=shared_ip,
        observed_count=1,
        threshold=1,
        source_ip=shared_ip,
        username="user_victim",
        first_seen=datetime.now(UTC) - timedelta(minutes=15),
        last_seen=datetime.now(UTC),
    )
    test_db_session.add(alert)
    await test_db_session.flush()
    test_db_session.add(AlertEvent(alert_id=alert.id, event_id=ev2.id))
    await test_db_session.flush()

    # 4. Create Incident linking Alert and Event 1 directly
    incident = Incident(
        incident_id="INC-2026-000555",
        title="Active Compromise Case",
        description="Correlated compromise involving C2 and exfiltration",
        severity="CRITICAL",
        priority="HIGH",
        status="OPEN",
        created_by_user_id=user.id,
    )
    test_db_session.add(incident)
    await test_db_session.flush()

    test_db_session.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    test_db_session.add(IncidentEvent(incident_id=incident.id, event_id=ev1.id))
    test_db_session.add(
        IncidentNote(
            incident_id=incident.id,
            author_user_id=user.id,
            content="Initial containment initiated on infected workstation.",
        )
    )
    await test_db_session.commit()

    # 5. Attach Threat Intelligence to the shared IP indicator
    ind_res = await test_db_session.execute(
        select(Indicator).where(Indicator.normalized_value == shared_ip)
    )
    ind = ind_res.scalar_one()
    await add_threat_intelligence(
        test_db_session,
        indicator_id=ind.id,
        payload=ThreatIntelligenceCreateRequest(
            source="SOC_THREAT_FEED",
            threat_classification=ThreatClassification.MALICIOUS,
            confidence=95,
            threat_actor="APT28",
        ),
    )

    # 6. Execute Correlation from Incident Anchor
    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INCIDENT,
        anchor_value="INC-2026-000555",
    )

    # Verify correlated events: must contain BOTH ev1 (direct) and ev2 (via alert)
    events, total_events = await get_correlated_events(test_db_session, anchor, ctx)
    assert total_events >= 2
    event_ids = {e.id for e in events}
    assert ev1.id in event_ids
    assert ev2.id in event_ids

    # Verify correlated alerts
    alerts, total_alerts = await get_correlated_alerts(test_db_session, anchor, ctx)
    assert total_alerts >= 1
    assert any(a.id == alert.id for a in alerts)

    # Verify correlated indicators & threat intelligence
    indicators, total_ind = await get_correlated_indicators(test_db_session, anchor, ctx)
    assert total_ind >= 1
    target_ind = next(i for i in indicators if i.normalized_value == shared_ip)
    assert target_ind.is_threat is True
    assert "SOC_THREAT_FEED" in target_ind.threat_sources

    # Verify timeline contains all distinct entity types
    timeline = await get_investigation_timeline(test_db_session, anchor, ctx)
    entity_types = {t.entity_type for t in timeline.entries}
    assert "EVENT" in entity_types
    assert "ALERT" in entity_types
    assert "INCIDENT" in entity_types
    assert "NOTE" in entity_types
    assert "INDICATOR" in entity_types


@pytest.mark.asyncio
async def test_entity_pivoting_by_source_ip_and_username(test_db_session: AsyncSession) -> None:
    """Verify correlated investigation views anchored on Source IP and Username."""
    source_ip = "198.51.100.88"
    username = "compromised_user_88"

    ev = await create_test_event(test_db_session, source_ip=source_ip, username=username)
    await enrich_event(test_db_session, ev.id)

    # 1. Pivot by Source IP
    anchor_ip, ctx_ip = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.SOURCE_IP,
        anchor_value=source_ip,
    )
    events_ip, total_ip = await get_correlated_events(test_db_session, anchor_ip, ctx_ip)
    assert total_ip >= 1
    assert any(e.id == ev.id for e in events_ip)

    # 2. Pivot by Username
    anchor_u, ctx_u = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.USERNAME,
        anchor_value=username,
    )
    events_u, total_u = await get_correlated_events(test_db_session, anchor_u, ctx_u)
    assert total_u >= 1
    assert any(e.id == ev.id for e in events_u)


# ==============================================================================
# 4. Deterministic Investigation Summary Metrics
# ==============================================================================


@pytest.mark.asyncio
async def test_investigation_summary_database_truth(test_db_session: AsyncSession) -> None:
    """Verify aggregate summary metrics match direct database truth."""
    user, _ = await create_user(test_db_session, ROLE_ADMIN, "admin_metrics")
    test_ip = "198.51.100.70"

    t1 = datetime.now(UTC) - timedelta(hours=3)
    t2 = datetime.now(UTC) - timedelta(hours=1)

    ev1 = await create_test_event(
        test_db_session, source_ip=test_ip, dest_ip="203.0.113.1", timestamp=t1
    )
    ev2 = await create_test_event(
        test_db_session, source_ip=test_ip, dest_ip="203.0.113.2", timestamp=t2
    )
    await enrich_event(test_db_session, ev1.id)
    await enrich_event(test_db_session, ev2.id)

    incident = Incident(
        incident_id="INC-2026-000777",
        title="Summary Accuracy Test",
        description="Verify metrics calculations",
        severity="MEDIUM",
        priority="MEDIUM",
        status="OPEN",
        created_by_user_id=user.id,
    )
    test_db_session.add(incident)
    await test_db_session.flush()
    test_db_session.add(IncidentEvent(incident_id=incident.id, event_id=ev1.id))
    test_db_session.add(IncidentEvent(incident_id=incident.id, event_id=ev2.id))
    await test_db_session.commit()

    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INCIDENT,
        anchor_value="INC-2026-000777",
    )
    summary = await get_investigation_summary(test_db_session, anchor, ctx)

    assert summary.event_count == 2
    assert summary.incident_count == 1
    assert summary.unique_source_ips == 1
    assert summary.unique_destination_ips == 2
    assert summary.first_seen is not None
    assert summary.last_seen is not None
    assert summary.first_seen <= summary.last_seen


# ==============================================================================
# 5. Timeline Determinism & Tie-Breaking
# ==============================================================================


@pytest.mark.asyncio
async def test_investigation_timeline_deterministic_tie_breaking(
    test_db_session: AsyncSession,
) -> None:
    """Verify timeline ordering with identical timestamps breaks ties deterministically."""
    user, _ = await create_user(test_db_session, ROLE_ADMIN, "admin_tie")
    exact_ts = datetime.now(UTC) - timedelta(hours=2)

    ev = await create_test_event(test_db_session, source_ip="198.51.100.91", timestamp=exact_ts)

    alert = Alert(
        rule_id="RULE-TIE-01",
        rule_version=1,
        title="Tie Test Alert",
        description="Alert for tie breaking test",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key="198.51.100.91",
        observed_count=1,
        threshold=1,
        source_ip="198.51.100.91",
        first_seen=exact_ts,
        last_seen=exact_ts,
    )
    alert.created_at = exact_ts
    test_db_session.add(alert)
    await test_db_session.flush()

    incident = Incident(
        incident_id="INC-2026-000999",
        title="Tie Test Incident",
        description="Incident for tie breaking test",
        severity="HIGH",
        priority="HIGH",
        status="OPEN",
        created_by_user_id=user.id,
    )
    incident.created_at = exact_ts
    test_db_session.add(incident)
    await test_db_session.flush()

    test_db_session.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    test_db_session.add(IncidentEvent(incident_id=incident.id, event_id=ev.id))
    await test_db_session.commit()

    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INCIDENT,
        anchor_value="INC-2026-000999",
    )

    # Run timeline twice and verify 100% identical sequence
    res1 = await get_investigation_timeline(test_db_session, anchor, ctx)
    res2 = await get_investigation_timeline(test_db_session, anchor, ctx)

    ids1 = [e.id for e in res1.entries]
    ids2 = [e.id for e in res2.entries]
    assert ids1 == ids2
    assert len(ids1) >= 3


# ==============================================================================
# 6. Evidence Preservation & Immutability
# ==============================================================================


@pytest.mark.asyncio
async def test_evidence_forensic_immutability_during_investigation(
    test_db_session: AsyncSession,
) -> None:
    """Verify raw_payload, timestamp, and network fields remain strictly unmutated."""
    original_raw = {"sensor_data": "raw_evidence", "nested": {"key": 42}}
    ev = await create_test_event(test_db_session, source_ip="198.51.100.30")
    ev.raw_payload = original_raw
    await test_db_session.commit()

    orig_timestamp = ev.timestamp
    orig_source_ip = ev.source_ip
    orig_destination_ip = ev.destination_ip

    # Run investigation context
    anchor = InvestigationAnchor(
        anchor_type=InvestigationAnchorType.SOURCE_IP,
        anchor_value="198.51.100.30",
    )
    await get_investigation_context(test_db_session, anchor)

    # Re-fetch event from DB and assert identical state
    refreshed = (await test_db_session.execute(select(Event).where(Event.id == ev.id))).scalar_one()

    assert refreshed.raw_payload == original_raw
    assert refreshed.timestamp == orig_timestamp
    assert refreshed.source_ip == orig_source_ip
    assert refreshed.destination_ip == orig_destination_ip


# ==============================================================================
# 7. RBAC Boundaries & API Endpoints
# ==============================================================================


@pytest.mark.asyncio
async def test_investigations_api_rbac_permissions(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify RBAC boundaries across ADMIN, ANALYST, VIEWER, and unauthenticated clients."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "inv_admin")
    analyst_user, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "inv_analyst")
    viewer_user, viewer_token = await create_user(test_db_session, ROLE_VIEWER, "inv_viewer")

    # Create event to anchor on
    await create_test_event(test_db_session, source_ip="198.51.100.100")

    # 1. Unauthenticated request: 401 Unauthorized
    unauth_res = await async_client.get(
        "/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value=198.51.100.100"
    )
    assert unauth_res.status_code == 401

    # 2. VIEWER has read permission: 200 OK
    viewer_res = await async_client.get(
        "/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value=198.51.100.100",
        headers=auth_headers(viewer_token),
    )
    assert viewer_res.status_code == 200

    # 3. ANALYST has read permission: 200 OK
    analyst_res = await async_client.get(
        "/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value=198.51.100.100",
        headers=auth_headers(analyst_token),
    )
    assert analyst_res.status_code == 200

    # 4. ADMIN has read permission: 200 OK
    admin_res = await async_client.get(
        "/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value=198.51.100.100",
        headers=auth_headers(admin_token),
    )
    assert admin_res.status_code == 200


@pytest.mark.asyncio
async def test_granular_investigation_endpoints(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify /summary, /events, /alerts, /incidents, /indicators, and /timeline endpoints."""
    analyst_user, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "gran_analyst")
    ev = await create_test_event(test_db_session, source_ip="198.51.100.101")
    await enrich_event(test_db_session, ev.id)

    headers = auth_headers(analyst_token)
    base_params = "anchor_type=SOURCE_IP&anchor_value=198.51.100.101"

    # GET /summary
    sum_res = await async_client.get(
        f"/api/v1/investigations/summary?{base_params}", headers=headers
    )
    assert sum_res.status_code == 200
    assert sum_res.json()["data"]["event_count"] >= 1

    # GET /events
    ev_res = await async_client.get(f"/api/v1/investigations/events?{base_params}", headers=headers)
    assert ev_res.status_code == 200
    assert ev_res.json()["data"]["total"] >= 1

    # GET /alerts
    al_res = await async_client.get(f"/api/v1/investigations/alerts?{base_params}", headers=headers)
    assert al_res.status_code == 200

    # GET /incidents
    inc_res = await async_client.get(
        f"/api/v1/investigations/incidents?{base_params}", headers=headers
    )
    assert inc_res.status_code == 200

    # GET /indicators
    ind_res = await async_client.get(
        f"/api/v1/investigations/indicators?{base_params}", headers=headers
    )
    assert ind_res.status_code == 200
    assert ind_res.json()["data"]["total"] >= 1

    # GET /timeline
    tl_res = await async_client.get(
        f"/api/v1/investigations/timeline?{base_params}", headers=headers
    )
    assert tl_res.status_code == 200
    assert tl_res.json()["data"]["total_entries"] >= 1


# ==============================================================================
# 8. Negative Security & Boundary Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_investigation_security_edge_cases(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify IDOR 404, SQL injection resilience, and missing anchor rejection."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "sec_tester_inv")
    headers = auth_headers(admin_token)

    # 1. Missing anchor parameters returns 422
    missing_res = await async_client.get("/api/v1/investigations/context", headers=headers)
    assert missing_res.status_code == 422

    # 2. Non-existent anchor UUID returns 404
    non_existent = str(uuid.uuid4())
    res_404 = await async_client.get(
        f"/api/v1/investigations/context?anchor_type=INCIDENT&anchor_value={non_existent}",
        headers=headers,
    )
    assert res_404.status_code == 404

    # 3. SQL injection payload in anchor value is safely handled without error
    sqli_res = await async_client.get(
        "/api/v1/investigations/events?anchor_type=USERNAME&anchor_value=' OR 1=1 --",
        headers=headers,
    )
    assert sqli_res.status_code == 200
    assert sqli_res.json()["data"]["total"] == 0

    # 4. Oversized pagination limit bounded by validator (422 for limit > 500)
    over_limit_res = await async_client.get(
        "/api/v1/investigations/events?anchor_type=SOURCE_IP&anchor_value=198.51.100.1&limit=1000",
        headers=headers,
    )
    assert over_limit_res.status_code == 422


# ==============================================================================
# 9. Concurrency & Determinism Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_concurrent_investigation_queries(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify concurrent requests for the same investigation anchor return cleanly."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "conc_inv_admin")
    ev = await create_test_event(test_db_session, source_ip="198.51.100.120")

    url = f"/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value={ev.source_ip}"
    req1 = async_client.get(url, headers=auth_headers(admin_token))
    req2 = async_client.get(url, headers=auth_headers(admin_token))

    res1, res2 = await asyncio.gather(req1, req2)
    assert res1.status_code == 200
    assert res2.status_code == 200
    assert (
        res1.json()["data"]["summary"]["event_count"]
        == res2.json()["data"]["summary"]["event_count"]
    )


# ==============================================================================
# 10. Multi-Source Threat Intelligence Conflict Handling
# ==============================================================================


@pytest.mark.asyncio
async def test_multi_source_threat_intel_conflict_preservation(
    test_db_session: AsyncSession,
) -> None:
    """Verify conflicting classifications from multiple sources are both preserved."""
    indicator, _ = await create_or_get_indicator(
        test_db_session, type=IndicatorType.IP, value="198.51.100.200"
    )

    # Source 1: MALICIOUS
    await add_threat_intelligence(
        test_db_session,
        indicator_id=indicator.id,
        payload=ThreatIntelligenceCreateRequest(
            source="FEED_ALPHA",
            threat_classification=ThreatClassification.MALICIOUS,
            confidence=90,
            source_reference="REF-001",
        ),
    )

    # Source 2: BENIGN
    await add_threat_intelligence(
        test_db_session,
        indicator_id=indicator.id,
        payload=ThreatIntelligenceCreateRequest(
            source="FEED_BETA",
            threat_classification=ThreatClassification.BENIGN,
            confidence=50,
            source_reference="REF-002",
        ),
    )

    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INDICATOR,
        anchor_value=str(indicator.id),
    )
    indicators, _ = await get_correlated_indicators(test_db_session, anchor, ctx)
    assert len(indicators) == 1
    assert "FEED_ALPHA" in indicators[0].threat_sources
    assert "FEED_BETA" in indicators[0].threat_sources
    # System preserves both sources rather than forcing an artificial singular verdict
    raw_intel = (
        (
            await test_db_session.execute(
                select(ThreatIntelligence).where(ThreatIntelligence.indicator_id == indicator.id)
            )
        )
        .scalars()
        .all()
    )
    assert len(raw_intel) == 2
    classifications = {ti.threat_classification for ti in raw_intel}
    assert ThreatClassification.MALICIOUS in classifications
    assert ThreatClassification.BENIGN in classifications


# ==============================================================================
# 11. Additional Correlation & Temporal Filtering Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_entity_pivoting_by_destination_ip(test_db_session: AsyncSession) -> None:
    """Verify correlated investigation views anchored on Destination IP."""
    dest_ip = "203.0.113.199"
    ev = await create_test_event(test_db_session, source_ip="198.51.100.12", dest_ip=dest_ip)
    await enrich_event(test_db_session, ev.id)

    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.DESTINATION_IP,
        anchor_value=dest_ip,
    )
    events, total = await get_correlated_events(test_db_session, anchor, ctx)
    assert total >= 1
    assert any(e.id == ev.id for e in events)


@pytest.mark.asyncio
async def test_alert_anchor_correlation(test_db_session: AsyncSession) -> None:
    """Verify Alert anchor traversal to events, indicators, and sibling alerts."""
    ev = await create_test_event(test_db_session, source_ip="198.51.100.222")
    await enrich_event(test_db_session, ev.id)

    alert1 = Alert(
        rule_id="RULE-CORR-01",
        rule_version=1,
        title="Alert 1 for Correlation",
        description="Alert 1",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key="198.51.100.222",
        observed_count=1,
        threshold=1,
        source_ip="198.51.100.222",
        first_seen=datetime.now(UTC) - timedelta(minutes=5),
        last_seen=datetime.now(UTC),
    )
    alert2 = Alert(
        rule_id="RULE-CORR-02",
        rule_version=1,
        title="Alert 2 with Shared Correlation Key",
        description="Alert 2",
        severity="MEDIUM",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key="198.51.100.222",
        observed_count=1,
        threshold=1,
        source_ip="198.51.100.222",
        first_seen=datetime.now(UTC) - timedelta(minutes=4),
        last_seen=datetime.now(UTC),
    )
    test_db_session.add_all([alert1, alert2])
    await test_db_session.flush()

    test_db_session.add(AlertEvent(alert_id=alert1.id, event_id=ev.id))
    await test_db_session.commit()

    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.ALERT,
        anchor_value=str(alert1.id),
    )
    # Correlated events include ev
    events, ev_total = await get_correlated_events(test_db_session, anchor, ctx)
    assert ev_total >= 1
    assert any(e.id == ev.id for e in events)

    # Correlated alerts include alert1 and alert2 (shared correlation_key)
    alerts, al_total = await get_correlated_alerts(test_db_session, anchor, ctx)
    assert al_total >= 2
    alert_ids = {a.id for a in alerts}
    assert alert1.id in alert_ids
    assert alert2.id in alert_ids


@pytest.mark.asyncio
async def test_indicator_anchor_correlation(test_db_session: AsyncSession) -> None:
    """Verify Indicator anchor traversal down to events, alerts, and incidents."""
    user, _ = await create_user(test_db_session, ROLE_ADMIN, "admin_ind_corr")
    target_ip = "198.51.100.250"

    ev = await create_test_event(test_db_session, source_ip=target_ip)
    enrich_res = await enrich_event(test_db_session, ev.id)
    ip_ind_id = next(
        i.indicator_id for i in enrich_res.indicators if i.normalized_value == target_ip
    )

    alert = Alert(
        rule_id="RULE-IND-01",
        rule_version=1,
        title="Alert Triggered by Indicator Event",
        description="Alert for indicator test",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key=target_ip,
        observed_count=1,
        threshold=1,
        source_ip=target_ip,
        first_seen=datetime.now(UTC) - timedelta(minutes=10),
        last_seen=datetime.now(UTC),
    )
    test_db_session.add(alert)
    await test_db_session.flush()

    test_db_session.add(AlertEvent(alert_id=alert.id, event_id=ev.id))

    incident = Incident(
        incident_id="INC-2026-000333",
        title="Incident Containing Indicator",
        description="Case with indicator correlation",
        severity="HIGH",
        priority="HIGH",
        status="OPEN",
        created_by_user_id=user.id,
    )
    test_db_session.add(incident)
    await test_db_session.flush()

    test_db_session.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    test_db_session.add(IncidentEvent(incident_id=incident.id, event_id=ev.id))
    await test_db_session.commit()

    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.INDICATOR,
        anchor_value=str(ip_ind_id),
    )

    # Correlated events
    events, total_ev = await get_correlated_events(test_db_session, anchor, ctx)
    assert total_ev >= 1
    assert any(e.id == ev.id for e in events)

    # Correlated alerts
    alerts, total_al = await get_correlated_alerts(test_db_session, anchor, ctx)
    assert total_al >= 1
    assert any(a.id == alert.id for a in alerts)

    # Correlated incidents
    incidents, total_inc = await get_correlated_incidents(test_db_session, anchor, ctx)
    assert total_inc >= 1
    assert any(i.id == incident.id for i in incidents)


@pytest.mark.asyncio
async def test_investigation_events_time_window_filtering(test_db_session: AsyncSession) -> None:
    """Verify temporal bounds correctly include in-window and exclude out-of-window events."""
    test_ip = "198.51.100.175"
    t_inside = datetime.now(UTC) - timedelta(hours=2)
    t_outside_past = datetime.now(UTC) - timedelta(hours=10)
    t_outside_recent = datetime.now(UTC) - timedelta(minutes=10)

    ev_inside = await create_test_event(test_db_session, source_ip=test_ip, timestamp=t_inside)
    ev_past = await create_test_event(test_db_session, source_ip=test_ip, timestamp=t_outside_past)
    ev_recent = await create_test_event(
        test_db_session, source_ip=test_ip, timestamp=t_outside_recent
    )

    # Query with window [now - 4h, now - 1h]
    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.SOURCE_IP,
        anchor_value=test_ip,
        start_time=datetime.now(UTC) - timedelta(hours=4),
        end_time=datetime.now(UTC) - timedelta(hours=1),
    )

    events, total = await get_correlated_events(test_db_session, anchor, ctx)
    event_ids = {e.id for e in events}
    assert ev_inside.id in event_ids
    assert ev_past.id not in event_ids
    assert ev_recent.id not in event_ids


@pytest.mark.asyncio
async def test_investigation_empty_correlations(test_db_session: AsyncSession) -> None:
    """Verify querying an anchor with zero telemetry returns clean empty lists and 0 counts."""
    anchor, ctx = await resolve_investigation_anchor(
        test_db_session,
        anchor_type=InvestigationAnchorType.SOURCE_IP,
        anchor_value="198.51.100.240",
    )
    summary = await get_investigation_summary(test_db_session, anchor, ctx)
    assert summary.event_count == 0
    assert summary.alert_count == 0
    assert summary.incident_count == 0
    assert summary.indicator_count == 0
    assert summary.first_seen is None
    assert summary.last_seen is None

    events, total_ev = await get_correlated_events(test_db_session, anchor, ctx)
    assert total_ev == 0
    assert len(events) == 0

    timeline = await get_investigation_timeline(test_db_session, anchor, ctx)
    assert timeline.total_entries == 0
    assert len(timeline.entries) == 0


@pytest.mark.asyncio
async def test_investigation_invalid_time_windows_api(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify API rejects invalid time window combinations with HTTP 422."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "sec_time_test")
    headers = auth_headers(admin_token)

    # 1. start_time > end_time -> 422
    t_start = (datetime.now(UTC)).isoformat()
    t_end = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
    res1 = await async_client.get(
        f"/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value=198.51.100.1&start_time={t_start}&end_time={t_end}",
        headers=headers,
    )
    assert res1.status_code == 422

    # 2. window_seconds > 30 days -> 422
    res2 = await async_client.get(
        "/api/v1/investigations/context?anchor_type=SOURCE_IP&anchor_value=198.51.100.1&window_seconds=3000000",
        headers=headers,
    )
    assert res2.status_code == 422

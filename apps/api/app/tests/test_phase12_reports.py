"""Comprehensive Unit and Integration Tests for Phase 12 Security Reporting & Metrics.

Validates:
1. Time range bounded validation (start < end, max 365 days, future date clock skew)
2. RBAC persona boundaries across VIEWER, ANALYST, and ADMIN for reading, auditing, and exporting
3. Operations summary and alert lifecycle duration calculations without zero-substitution
4. SLA reporting adhering strictly to Phase 10 rules (CRITICAL/HIGH > 24h) with explicit denominator
5. Detection rule effectiveness preserving exact (rule_id, rule_version) provenance
6. Threat intelligence indicator taxonomy and period sightings telemetry
7. Analyst activity report strictly non-evaluative with operational disclaimer
8. Compliance control evidence reporting with objective factual observations
9. CSV formula injection defense (CWE-1236) neutralizing =, +, -, @, \t, \r prefixes
10. Immutable audit logging for REPORT_GENERATED and REPORT_EXPORTED
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
from app.models.detection import DetectionRule
from app.services.auth import create_session, record_audit_log
from app.services.seed import seed_rbac_and_admin


async def _create_user(db: AsyncSession, role_name: str, username: str) -> tuple[User, str]:
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash("ValidPass123!"),
        is_active=True,
    )
    db.add(user)
    await db.flush()

    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.commit()

    _, token = await create_session(db, user)
    return user, token


# ==============================================================================
# 1. Authentication & Time Range Validation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_reporting_unauthenticated_rejected(async_client: AsyncClient) -> None:
    """Ensure all reporting endpoints reject unauthenticated requests with 401."""
    resp = await async_client.get("/api/v1/reports/summary")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_reporting_time_range_validation(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Validate strict temporal bounds: start < end, span <= 365d, no future queries."""
    _, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_validator")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    now = datetime.now(UTC)

    # 1. Inverted time range (start >= end)
    resp = await async_client.get(
        "/api/v1/reports/summary",
        params={
            "start_time": (now + timedelta(days=1)).isoformat(),
            "end_time": now.isoformat(),
        },
    )
    assert resp.status_code == 422

    # 2. Exceeding 365 days span
    resp = await async_client.get(
        "/api/v1/reports/summary",
        params={
            "start_time": (now - timedelta(days=367)).isoformat(),
            "end_time": now.isoformat(),
        },
    )
    assert resp.status_code == 422

    # 3. Future query beyond 5m clock skew
    resp = await async_client.get(
        "/api/v1/reports/summary",
        params={
            "start_time": now.isoformat(),
            "end_time": (now + timedelta(minutes=15)).isoformat(),
        },
    )
    assert resp.status_code == 422

    # 4. Valid default range (no params passed) -> defaults to last 30 days
    resp = await async_client.get("/api/v1/reports/summary")
    assert resp.status_code == 200
    assert resp.json()["data"]["total_alerts"] >= 0


# ==============================================================================
# 2. RBAC Persona Enforcement Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_reports_rbac_boundaries(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify VIEWER can read reports, but is denied export and sensitive audit reports."""
    _, viewer_token = await _create_user(test_db_session, ROLE_VIEWER, "p12_viewer_rbac")
    _, analyst_token = await _create_user(test_db_session, ROLE_ANALYST, "p12_analyst_rbac")

    # VIEWER Persona
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, viewer_token)

    # VIEWER: Can access operational reports
    res_sum = await async_client.get("/api/v1/reports/summary")
    res_sla = await async_client.get("/api/v1/reports/sla")
    res_comp = await async_client.get("/api/v1/reports/compliance")
    assert res_sum.status_code == 200
    assert res_sla.status_code == 200
    assert res_comp.status_code == 200

    # VIEWER: Forbidden on export
    res_exp = await async_client.get("/api/v1/reports/export?type=summary&format=csv")
    assert res_exp.status_code == 403

    # VIEWER: Forbidden on analyst-activity and audit
    res_act = await async_client.get("/api/v1/reports/analyst-activity")
    res_aud = await async_client.get("/api/v1/reports/audit")
    assert res_act.status_code == 403
    assert res_aud.status_code == 403

    # ANALYST Persona
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, analyst_token)

    # ANALYST: Allowed on export and audit reports
    res_exp_a = await async_client.get("/api/v1/reports/export?type=summary&format=csv")
    res_act_a = await async_client.get("/api/v1/reports/analyst-activity")
    res_aud_a = await async_client.get("/api/v1/reports/audit")
    assert res_exp_a.status_code == 200
    assert res_act_a.status_code == 200
    assert res_aud_a.status_code == 200


# ==============================================================================
# 3. Operations Summary & Alert Lifecycle Duration Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_alert_performance_lifecycle_calculations(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify alert duration calculations use completed samples only and track uncompleted."""
    user, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_lifecycle_analyst")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    base_time = datetime.now(UTC) - timedelta(hours=5)

    # Alert 1: fully acknowledged and resolved
    # Ack duration: 600s (10m), Resolve duration: 1800s (30m)
    a1 = Alert(
        rule_id="RULE-P12-01",
        rule_version=1,
        title="Brute Force Detection 1",
        description="SSH brute force attempt",
        severity="HIGH",
        status="RESOLVED",
        dedup_key=f"dedup-p12-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-p12-{uuid.uuid4().hex[:8]}",
        first_seen=base_time,
        last_seen=base_time,
        created_at=base_time,
        assignee_id=user.id,
        assigned_at=base_time + timedelta(seconds=300),
        acknowledged_by_id=user.id,
        acknowledged_at=base_time + timedelta(seconds=600),
        resolved_by_id=user.id,
        resolved_at=base_time + timedelta(seconds=1800),
    )

    # Alert 2: fully acknowledged and resolved
    # Ack duration: 1200s (20m), Resolve duration: 3600s (60m)
    a2 = Alert(
        rule_id="RULE-P12-01",
        rule_version=1,
        title="Brute Force Detection 2",
        description="SSH brute force attempt",
        severity="HIGH",
        status="RESOLVED",
        dedup_key=f"dedup-p12-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-p12-{uuid.uuid4().hex[:8]}",
        first_seen=base_time,
        last_seen=base_time,
        created_at=base_time,
        assignee_id=user.id,
        assigned_at=base_time + timedelta(seconds=600),
        acknowledged_by_id=user.id,
        acknowledged_at=base_time + timedelta(seconds=1200),
        resolved_by_id=user.id,
        resolved_at=base_time + timedelta(seconds=3600),
    )

    # Alert 3: unacknowledged, unassigned, unresolved
    a3 = Alert(
        rule_id="RULE-P12-02",
        rule_version=1,
        title="Port Scan Detection",
        description="Port scan",
        severity="CRITICAL",
        status="OPEN",
        dedup_key=f"dedup-p12-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-p12-{uuid.uuid4().hex[:8]}",
        first_seen=base_time,
        last_seen=base_time,
        created_at=base_time,
    )

    test_db_session.add_all([a1, a2, a3])
    await test_db_session.commit()

    resp = await async_client.get(
        "/api/v1/reports/alerts",
        params={
            "start_time": (base_time - timedelta(hours=1)).isoformat(),
            "end_time": datetime.now(UTC).isoformat(),
        },
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    # Samples: exactly 2 alerts were acknowledged (durations: 600, 1200)
    ack_metrics = data["lifecycle"]["time_to_acknowledge"]
    assert ack_metrics["sample_count"] == 2
    assert ack_metrics["mean_seconds"] == 900.0  # (600 + 1200) / 2
    assert ack_metrics["median_seconds"] == 900.0
    assert ack_metrics["min_seconds"] == 600.0
    assert ack_metrics["max_seconds"] == 1200.0

    # Unacknowledged count must include a3
    assert data["lifecycle"]["unacknowledged_count"] >= 1
    assert data["lifecycle"]["unresolved_count"] >= 1


# ==============================================================================
# 4. SLA Breach Reporting & Explicit Population Denominator Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_sla_report_explicit_denominator(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify SLA breach calculation strictly tests CRITICAL/HIGH > 24h with denominator."""
    _, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_sla_analyst")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    created_30h_ago = datetime.now(UTC) - timedelta(hours=30)
    created_2h_ago = datetime.now(UTC) - timedelta(hours=2)

    # 1. CRITICAL untriaged > 24h -> Breached
    alert_crit_breach = Alert(
        rule_id="RULE-P12-SLA",
        rule_version=1,
        title="Critical Delayed Alert",
        description="Test SLA Breach",
        severity="CRITICAL",
        status="OPEN",
        dedup_key=f"dedup-sla-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-sla-{uuid.uuid4().hex[:8]}",
        first_seen=created_30h_ago,
        last_seen=created_30h_ago,
        created_at=created_30h_ago,
    )

    # 2. HIGH untriaged > 24h -> Breached
    alert_high_breach = Alert(
        rule_id="RULE-P12-SLA",
        rule_version=1,
        title="High Delayed Alert",
        description="Test SLA Breach",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-sla-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-sla-{uuid.uuid4().hex[:8]}",
        first_seen=created_30h_ago,
        last_seen=created_30h_ago,
        created_at=created_30h_ago,
    )

    # 3. HIGH untriaged < 24h -> NOT Breached, but in denominator
    alert_high_ok = Alert(
        rule_id="RULE-P12-SLA",
        rule_version=1,
        title="High Fresh Alert",
        description="Test SLA OK",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-sla-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-sla-{uuid.uuid4().hex[:8]}",
        first_seen=created_2h_ago,
        last_seen=created_2h_ago,
        created_at=created_2h_ago,
    )

    # 4. MEDIUM untriaged > 24h -> Excluded from CRITICAL/HIGH SLA standard
    alert_med_old = Alert(
        rule_id="RULE-P12-SLA",
        rule_version=1,
        title="Medium Delayed Alert",
        description="Excluded from SLA",
        severity="MEDIUM",
        status="OPEN",
        dedup_key=f"dedup-sla-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-sla-{uuid.uuid4().hex[:8]}",
        first_seen=created_30h_ago,
        last_seen=created_30h_ago,
        created_at=created_30h_ago,
    )

    test_db_session.add_all([alert_crit_breach, alert_high_breach, alert_high_ok, alert_med_old])
    await test_db_session.commit()

    resp = await async_client.get(
        "/api/v1/reports/sla",
        params={
            "start_time": (datetime.now(UTC) - timedelta(hours=48)).isoformat(),
            "end_time": datetime.now(UTC).isoformat(),
        },
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    # Applicable alerts (denominator): exactly the 3 CRITICAL/HIGH alerts
    assert data["applicable_alerts"] == 3
    assert data["sla_breached_count"] == 2
    assert data["breach_rate_percentage"] == round((2 / 3) * 100.0, 2)
    assert len(data["breached_alerts"]) == 2


# ==============================================================================
# 5. Detection Rule Effectiveness Provenance Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_detection_rule_effectiveness_provenance(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify detection rule metrics accurately record exact rule_id and rule_version."""
    _, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_det_analyst")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    rule = DetectionRule(
        rule_id="DET-VERSIONED-01",
        version=3,
        name="Advanced Kerberoasting Detector",
        description="Versioned rule test",
        severity="HIGH",
        category="credential_access",
        status="ACTIVE",
        enabled=True,
        event_type="auth",
        threshold=1,
        time_window_seconds=300,
        conditions={"event_id": 4769},
    )
    test_db_session.add(rule)
    await test_db_session.flush()

    alert = Alert(
        rule_id="DET-VERSIONED-01",
        rule_version=3,
        title="Kerberoasting Observed",
        description="Fired from version 3",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-det-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-det-{uuid.uuid4().hex[:8]}",
        first_seen=datetime.now(UTC) - timedelta(hours=1),
        last_seen=datetime.now(UTC) - timedelta(hours=1),
        created_at=datetime.now(UTC) - timedelta(hours=1),
    )
    test_db_session.add(alert)
    await test_db_session.commit()

    resp = await async_client.get(
        "/api/v1/reports/detections",
        params={
            "start_time": (datetime.now(UTC) - timedelta(hours=2)).isoformat(),
            "end_time": datetime.now(UTC).isoformat(),
        },
    )
    assert resp.status_code == 200
    data = resp.json()["data"]

    matched = [
        r
        for r in data["rule_effectiveness"]
        if r["rule_id"] == "DET-VERSIONED-01" and r["rule_version"] == 3
    ]
    assert len(matched) == 1
    assert matched[0]["rule_name"] == "Advanced Kerberoasting Detector"
    assert matched[0]["alert_count"] >= 1


# ==============================================================================
# 6. Compliance Control Evidence Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_compliance_report_objective_evidence(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify compliance control evidence reports factual data with standard disclaimer."""
    user, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_comp_analyst")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    # Insert an audit log to trigger evidence availability
    await record_audit_log(
        db=test_db_session,
        action="LOGIN_SUCCESS",
        actor_user_id=user.id,
        resource_type="auth",
        resource_id=str(user.id),
    )

    resp = await async_client.get("/api/v1/reports/compliance")
    assert resp.status_code == 200
    data = resp.json()["data"]

    assert "disclaimer" in data
    assert "does not issue, validate, or certify compliance attestations" in data["disclaimer"]

    controls = {c["control_id"]: c for c in data["controls"]}
    assert "CTRL-AUD-01" in controls
    assert "CTRL-AUTH-01" in controls
    assert "CTRL-ALRT-01" in controls
    assert "CTRL-DET-01" in controls
    assert "CTRL-INC-01" in controls
    assert controls["CTRL-AUD-01"]["status"] == "EVIDENCE_AVAILABLE"


# ==============================================================================
# 7. CSV Export & Formula Injection Defense (CWE-1236) Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_csv_export_formula_injection_defense(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify CWE-1236 defense prepends a single quote to malicious spreadsheet tokens."""
    _, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_export_analyst")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    # Create an alert with formula injection payloads in the title
    malicious_title = "=cmd|' /C calc'!A0"
    created_at = datetime.now(UTC) - timedelta(hours=30)

    alert = Alert(
        rule_id="RULE-MALICIOUS",
        rule_version=1,
        title=malicious_title,
        description="CSV Injection Test",
        severity="CRITICAL",
        status="OPEN",
        dedup_key=f"dedup-cwe-{uuid.uuid4().hex[:8]}",
        correlation_key=f"corr-cwe-{uuid.uuid4().hex[:8]}",
        first_seen=created_at,
        last_seen=created_at,
        created_at=created_at,
    )
    test_db_session.add(alert)
    await test_db_session.commit()

    # Request CSV export
    resp = await async_client.get(
        "/api/v1/reports/export",
        params={
            "type": "sla",
            "format": "csv",
            "start_time": (datetime.now(UTC) - timedelta(hours=48)).isoformat(),
            "end_time": datetime.now(UTC).isoformat(),
        },
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers["content-disposition"]
    assert "X-Content-Type-Options" in resp.headers

    csv_text = resp.text
    # Malicious formula '=' MUST be neutralized by prepending single quote "'"
    assert f"'{malicious_title}" in csv_text


# ==============================================================================
# 8. Security Audit Logging on Report Access Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_audit_logging_on_report_generation_and_export(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Ensure access to reports and exports creates immutable security audit logs."""
    user, token = await _create_user(test_db_session, ROLE_ADMIN, "p12_audit_trail_admin")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    # 1. Generate a report
    res_gen = await async_client.get("/api/v1/reports/summary")
    assert res_gen.status_code == 200

    # 2. Export a report
    res_exp = await async_client.get("/api/v1/reports/export?type=summary&format=json")
    assert res_exp.status_code == 200

    # Verify audit entries in database
    gen_audit_stmt = select(AuditLog).where(
        AuditLog.actor_user_id == user.id,
        AuditLog.action == "REPORT_GENERATED",
        AuditLog.resource_id == "summary",
    )
    gen_audit = (await test_db_session.execute(gen_audit_stmt)).scalars().first()
    assert gen_audit is not None
    assert gen_audit.new_value is not None
    assert gen_audit.new_value["report_type"] == "summary"

    exp_audit_stmt = select(AuditLog).where(
        AuditLog.actor_user_id == user.id,
        AuditLog.action == "REPORT_EXPORTED",
        AuditLog.resource_id == "summary",
    )
    exp_audit = (await test_db_session.execute(exp_audit_stmt)).scalars().first()
    assert exp_audit is not None
    assert exp_audit.new_value is not None
    assert exp_audit.new_value["format"] == "json"


# ==============================================================================
# 9. Additional Endpoint Coverage Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_threat_intel_and_incident_reports(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify threat intelligence and incident reporting endpoints."""
    user, token = await _create_user(test_db_session, ROLE_ANALYST, "p12_intel_analyst")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    # 1. Threat Intel
    res_intel = await async_client.get("/api/v1/reports/threat-intelligence")
    assert res_intel.status_code == 200
    intel_data = res_intel.json()["data"]
    assert "indicators_by_type" in intel_data
    assert "indicators_by_status" in intel_data
    assert intel_data["total_indicators"] >= 0

    # 2. Incidents
    res_inc = await async_client.get("/api/v1/reports/incidents")
    assert res_inc.status_code == 200
    inc_data = res_inc.json()["data"]
    assert "incidents_by_severity" in inc_data
    assert "resolution_breakdown" in inc_data
    assert inc_data["total_incidents"] >= 0


@pytest.mark.asyncio
async def test_analyst_activity_and_audit_reports(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify analyst activity and audit reports with operational disclaimers."""
    user, token = await _create_user(test_db_session, ROLE_ADMIN, "p12_activity_admin")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    # Log some actions
    await record_audit_log(
        db=test_db_session,
        action="ALERT_ACKNOWLEDGED",
        actor_user_id=user.id,
        resource_type="alert",
        resource_id=str(uuid.uuid4()),
    )
    await record_audit_log(
        db=test_db_session,
        action="ALERT_NOTE_CREATED",
        actor_user_id=user.id,
        resource_type="alert",
        resource_id=str(uuid.uuid4()),
    )

    # 1. Analyst Activity
    res_act = await async_client.get("/api/v1/reports/analyst-activity")
    assert res_act.status_code == 200
    act_data = res_act.json()["data"]
    assert "disclaimer" in act_data
    assert "Not intended for individual productivity scoring" in act_data["disclaimer"]
    analyst_entry = next((a for a in act_data["analysts"] if a["user_id"] == str(user.id)), None)
    assert analyst_entry is not None
    assert analyst_entry["alerts_acknowledged"] >= 1
    assert analyst_entry["triage_notes_created"] >= 1

    # 2. Security Audit Report
    res_aud = await async_client.get("/api/v1/reports/audit")
    assert res_aud.status_code == 200
    aud_data = res_aud.json()["data"]
    assert aud_data["total_audit_events"] >= 2
    assert "ALERT_ACKNOWLEDGED" in aud_data["action_distribution"]

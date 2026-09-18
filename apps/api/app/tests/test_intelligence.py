"""Comprehensive Test Suite for SentinelForge Threat Intelligence & IOC Enrichment (Phase 7).

Validates:
- Indicator Normalization & Validation (IP, Domain, URL, Email, MD5, SHA1, SHA256)
- Event IOC Extraction & Field Provenance Preservation
- Database Constraints & Evidence Preservation (RESTRICT on event deletion)
- Multi-Source Attribution & Expiration Semantics
- Deterministic and Idempotent Event Enrichment
- Evidence Immutability (raw_payload, timestamp, source_ip unchanged)
- Cross-Entity Pivoting (Event -> Alert -> Incident -> Indicator -> Intelligence)
- RBAC Access Controls (ADMIN, ANALYST, VIEWER, Unauthenticated)
- Security Negative Testing & Audit Trail Verification
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash
from app.models import (
    Alert,
    AlertEvent,
    AuditLog,
    Event,
    Incident,
    IncidentAlert,
    IncidentEvent,
    Role,
    User,
    UserRole,
)
from app.models.indicator import (
    Indicator,
    IndicatorType,
    IntelligenceSeverity,
    ThreatClassification,
)
from app.schemas.event import EventCreateRequest
from app.schemas.indicator import ThreatIntelligenceCreateRequest
from app.services.auth import create_session
from app.services.event import ingest_security_event
from app.services.intelligence import (
    ThreatIntelligenceConflictError,
    add_threat_intelligence,
    create_or_get_indicator,
    enrich_event,
    get_alert_indicators,
    get_event_indicators,
    get_incident_indicators,
)
from app.services.ioc_normalizer import (
    IOCValidationError,
    extract_iocs_from_event,
    infer_indicator_type,
    normalize_domain,
    normalize_email,
    normalize_file_hash,
    normalize_ip,
    normalize_url,
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
    username: str = "compromised@target.com",
    attributes: dict[str, Any] | None = None,
) -> Event:
    """Helper to persist a test event with rich telemetry."""
    user, _ = await create_user(db, ROLE_ANALYST, f"ingest_{uuid.uuid4().hex[:6]}")
    payload = EventCreateRequest(
        timestamp=datetime.now(UTC) - timedelta(minutes=10),
        source="network_sensor",
        source_type="network",
        source_ip=source_ip,
        destination_ip=dest_ip,
        destination_port=443,
        event_type="network",
        action="connection_established",
        username=username,
        severity="HIGH",
        raw_payload={
            "src": source_ip,
            "dst": dest_ip,
            "user": username,
            "details": attributes or {},
        },
    )
    res, _ = await ingest_security_event(db, payload, actor_user_id=user.id)
    event_stmt = select(Event).where(Event.id == res.id)
    event = (await db.execute(event_stmt)).scalar_one()

    # If extra attributes provided, attach them to the normalized attributes
    if attributes:
        event.attributes = {**(event.attributes or {}), **attributes}
        await db.commit()
        await db.refresh(event)

    return event


# ==============================================================================
# 1. Normalization & Validation Unit Tests
# ==============================================================================


def test_ip_normalization_valid() -> None:
    """Verify standard IPv4 and IPv6 canonicalization."""
    assert normalize_ip("192.168.1.1") == "192.168.1.1"
    assert normalize_ip("  10.0.0.1  ") == "10.0.0.1"
    # IPv6 uppercase and uncompressed -> compressed canonical
    assert normalize_ip("2001:0DB8:0000:0000:0000:0000:1428:57AB") == "2001:db8::1428:57ab"
    assert normalize_ip("::1") == "::1"


def test_ip_normalization_invalid() -> None:
    """Verify rejection of invalid IP representations."""
    with pytest.raises(IOCValidationError):
        normalize_ip("999.999.999.999")
    with pytest.raises(IOCValidationError):
        normalize_ip("not_an_ip")
    with pytest.raises(IOCValidationError):
        normalize_ip("")


def test_domain_normalization_valid() -> None:
    """Verify domain lowercase and trailing dot stripping."""
    assert normalize_domain("EVIL-DOMAIN.COM") == "evil-domain.com"
    assert normalize_domain("sub.command-control.org.") == "sub.command-control.org"
    assert normalize_domain("  malware.ru  ") == "malware.ru"


def test_domain_normalization_invalid() -> None:
    """Verify rejection of malformed domains and IP confusion."""
    with pytest.raises(IOCValidationError):
        normalize_domain("192.168.1.1")  # IP address is not domain
    with pytest.raises(IOCValidationError):
        normalize_domain("singleword")  # Must have at least two labels
    with pytest.raises(IOCValidationError):
        normalize_domain("-invalid-.com")  # Label starts/ends with hyphen
    with pytest.raises(IOCValidationError):
        normalize_domain("evil..com")  # Empty label


def test_url_normalization_credential_stripping() -> None:
    """Verify URL normalization strips embedded credentials to prevent leakage (T-26)."""
    # Embedded credentials must be stripped
    url_with_creds = "https://analyst:SuperSecretPassword123@c2-server.evil.com/payload.bin"
    normalized = normalize_url(url_with_creds)
    assert "SuperSecretPassword123" not in normalized
    assert "analyst" not in normalized
    assert normalized == "https://c2-server.evil.com/payload.bin"

    # Default port stripping
    assert normalize_url("http://evil.com:80/gate.php") == "http://evil.com/gate.php"
    assert normalize_url("https://evil.com:443/gate.php") == "https://evil.com/gate.php"
    # Non-default port retention
    assert normalize_url("https://evil.com:8443/gate.php") == "https://evil.com:8443/gate.php"
    # Empty path normalized to /
    assert normalize_url("http://evil.com") == "http://evil.com/"


def test_url_normalization_invalid() -> None:
    """Verify URL validation rejects unsupported schemes and missing hosts."""
    with pytest.raises(IOCValidationError):
        normalize_url("file:///etc/passwd")
    with pytest.raises(IOCValidationError):
        normalize_url("javascript:alert(1)")
    with pytest.raises(IOCValidationError):
        normalize_url("http://")


def test_email_normalization() -> None:
    """Verify email lowercasing and RFC checks."""
    assert normalize_email("Phisher@EvilCorp.Org") == "phisher@evilcorp.org"
    with pytest.raises(IOCValidationError):
        normalize_email("not_an_email")
    with pytest.raises(IOCValidationError):
        normalize_email("@missinglocal.com")


def test_file_hash_normalization() -> None:
    """Verify MD5, SHA1, and SHA256 hex string normalization and length validation."""
    md5_val = "E99A18C428CB38D5F260853678922E03"
    assert normalize_file_hash(md5_val, IndicatorType.HASH_MD5) == md5_val.lower()

    sha1_val = "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12"
    assert normalize_file_hash(sha1_val, IndicatorType.HASH_SHA1) == sha1_val.lower()

    sha256_val = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert normalize_file_hash(sha256_val, IndicatorType.HASH_SHA256) == sha256_val.lower()

    # Invalid length
    with pytest.raises(IOCValidationError):
        normalize_file_hash("abc123", IndicatorType.HASH_MD5)

    # Non-hex characters
    with pytest.raises(IOCValidationError):
        normalize_file_hash("z" * 32, IndicatorType.HASH_MD5)


def test_infer_indicator_type() -> None:
    """Verify auto-detection of IOC types."""
    assert infer_indicator_type("198.51.100.1") == (
        IndicatorType.IP,
        "198.51.100.1",
    )
    assert infer_indicator_type("https://evil.com/dropper") == (
        IndicatorType.URL,
        "https://evil.com/dropper",
    )
    assert infer_indicator_type("badactor@phish.com") == (
        IndicatorType.EMAIL,
        "badactor@phish.com",
    )
    assert infer_indicator_type("a" * 32) == (
        IndicatorType.HASH_MD5,
        "a" * 32,
    )
    assert infer_indicator_type("b" * 40) == (
        IndicatorType.HASH_SHA1,
        "b" * 40,
    )
    assert infer_indicator_type("c" * 64) == (
        IndicatorType.HASH_SHA256,
        "c" * 64,
    )
    assert infer_indicator_type("badguy-domain.net") == (
        IndicatorType.DOMAIN,
        "badguy-domain.net",
    )
    assert infer_indicator_type("just a random sentence here") is None


# ==============================================================================
# 2. Event IOC Extraction & Provenance
# ==============================================================================


@pytest.mark.asyncio
async def test_extract_iocs_from_event(test_db_session: AsyncSession) -> None:
    """Verify extraction from top-level fields and nested attributes with provenance."""
    sha256_hash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    event = await create_test_event(
        test_db_session,
        source_ip="198.51.100.77",
        dest_ip="203.0.113.88",
        username="victim@enterprise.com",
        attributes={
            "c2_domain": "attacker-c2.org",
            "download_url": "http://attacker-c2.org:8080/stage2.exe",
            "file_sha256": sha256_hash,
            "nested": {"pivot_ip": "192.0.2.1"},
        },
    )

    extracted = extract_iocs_from_event(event)
    extracted_fields = {e.extracted_from_field: e for e in extracted}

    assert "source_ip" in extracted_fields
    assert extracted_fields["source_ip"].normalized_value == "198.51.100.77"
    assert extracted_fields["source_ip"].type == IndicatorType.IP

    assert "destination_ip" in extracted_fields
    assert extracted_fields["destination_ip"].normalized_value == "203.0.113.88"

    assert "username" in extracted_fields
    assert extracted_fields["username"].type == IndicatorType.EMAIL

    assert "attributes.c2_domain" in extracted_fields
    assert extracted_fields["attributes.c2_domain"].normalized_value == "attacker-c2.org"

    assert "attributes.download_url" in extracted_fields
    assert (
        extracted_fields["attributes.download_url"].normalized_value
        == "http://attacker-c2.org:8080/stage2.exe"
    )

    assert "attributes.file_sha256" in extracted_fields
    assert extracted_fields["attributes.file_sha256"].normalized_value == sha256_hash

    assert "attributes.nested.pivot_ip" in extracted_fields
    assert extracted_fields["attributes.nested.pivot_ip"].normalized_value == "192.0.2.1"


# ==============================================================================
# 3. Database Constraints & Referential Integrity
# ==============================================================================


@pytest.mark.asyncio
async def test_indicator_uniqueness_constraint(test_db_session: AsyncSession) -> None:
    """Verify unique constraint on (type, normalized_value)."""
    ind1, created1 = await create_or_get_indicator(
        test_db_session,
        type=IndicatorType.DOMAIN,
        value="Malicious-C2.com",
    )
    assert created1 is True

    # Re-insert with different casing/whitespace must resolve to same existing record
    ind2, created2 = await create_or_get_indicator(
        test_db_session,
        type=IndicatorType.DOMAIN,
        value="  malicious-c2.com.  ",
    )
    assert created2 is False
    assert ind1.id == ind2.id


@pytest.mark.asyncio
async def test_event_deletion_restricted_when_linked(
    test_db_session: AsyncSession,
) -> None:
    """Verify RESTRICT foreign key prevents deleting events linked to indicators."""
    event = await create_test_event(test_db_session, source_ip="198.51.100.99")
    enrichment = await enrich_event(test_db_session, event.id)
    assert enrichment.total_indicators > 0

    # Attempting to delete the event must fail due to RESTRICT constraint
    with pytest.raises(IntegrityError):
        await test_db_session.delete(event)
        await test_db_session.commit()

    await test_db_session.rollback()


# ==============================================================================
# 4. Multi-Source Threat Intelligence & TTL Expiration
# ==============================================================================


@pytest.mark.asyncio
async def test_multi_source_threat_intel_attribution(
    test_db_session: AsyncSession,
) -> None:
    """Verify multiple independent intelligence sources can attach to one indicator."""
    indicator, _ = await create_or_get_indicator(
        test_db_session,
        type=IndicatorType.IP,
        value="198.51.100.5",
    )

    # Attach Source 1: INTERNAL SOC
    intel1 = await add_threat_intelligence(
        test_db_session,
        indicator_id=indicator.id,
        payload=ThreatIntelligenceCreateRequest(
            source="INTERNAL_SOC",
            threat_classification=ThreatClassification.SUSPICIOUS,
            severity=IntelligenceSeverity.MEDIUM,
            confidence=60,
            source_reference="INC-2026-001",
            description="Observed during reconnaissance probe",
        ),
    )

    # Attach Source 2: COMMERCIAL FEED
    intel2 = await add_threat_intelligence(
        test_db_session,
        indicator_id=indicator.id,
        payload=ThreatIntelligenceCreateRequest(
            source="THREAT_STREAM_ALPHA",
            threat_classification=ThreatClassification.MALICIOUS,
            severity=IntelligenceSeverity.CRITICAL,
            confidence=95,
            source_reference="ADV-9942",
            threat_actor="APT29",
            tags=["c2", "cobalt_strike"],
        ),
    )

    assert intel1.id != intel2.id
    assert intel1.source == "INTERNAL_SOC"
    assert intel2.source == "THREAT_STREAM_ALPHA"
    assert intel2.threat_actor == "APT29"

    # Verify duplicate source reference detection
    with pytest.raises(ThreatIntelligenceConflictError):
        await add_threat_intelligence(
            test_db_session,
            indicator_id=indicator.id,
            payload=ThreatIntelligenceCreateRequest(
                source="INTERNAL_SOC",
                confidence=50,
                source_reference="INC-2026-001",  # Duplicate reference for this source
            ),
        )


@pytest.mark.asyncio
async def test_threat_intel_ttl_expiration_semantics(
    test_db_session: AsyncSession,
) -> None:
    """Verify expired threat intelligence retains audit history but is marked expired."""
    indicator, _ = await create_or_get_indicator(
        test_db_session,
        type=IndicatorType.DOMAIN,
        value="temporary-c2.net",
    )

    # Expired 2 hours ago
    past_expiry = datetime.now(UTC) - timedelta(hours=2)
    intel_expired = await add_threat_intelligence(
        test_db_session,
        indicator_id=indicator.id,
        payload=ThreatIntelligenceCreateRequest(
            source="SHORT_LIVED_FEED",
            threat_classification=ThreatClassification.MALICIOUS,
            confidence=80,
            expires_at=past_expiry,
        ),
    )
    assert intel_expired.is_expired is True

    # Active future expiry
    future_expiry = datetime.now(UTC) + timedelta(days=30)
    intel_active = await add_threat_intelligence(
        test_db_session,
        indicator_id=indicator.id,
        payload=ThreatIntelligenceCreateRequest(
            source="LONG_TERM_FEED",
            threat_classification=ThreatClassification.MALICIOUS,
            confidence=90,
            expires_at=future_expiry,
        ),
    )
    assert intel_active.is_expired is False


# ==============================================================================
# 5. Deterministic & Idempotent Event Enrichment
# ==============================================================================


@pytest.mark.asyncio
async def test_event_enrichment_deterministic_and_idempotent(
    test_db_session: AsyncSession,
) -> None:
    """Verify running enrichment repeatedly yields identical results without duplicate links."""
    event = await create_test_event(
        test_db_session,
        source_ip="203.0.113.50",
        dest_ip="198.51.100.12",
    )

    # First enrichment run
    resp1 = await enrich_event(test_db_session, event.id)
    assert resp1.total_indicators >= 2

    # Second enrichment run on same event
    resp2 = await enrich_event(test_db_session, event.id)
    assert resp1.total_indicators == resp2.total_indicators
    assert [i.indicator_id for i in resp1.indicators] == [i.indicator_id for i in resp2.indicators]

    # Verify sightings count on indicator is exactly 1 (not incremented on duplicate run)
    ind_res = await test_db_session.execute(
        select(Indicator).where(Indicator.id == resp1.indicators[0].indicator_id)
    )
    ind = ind_res.scalar_one()
    assert ind.sightings_count == 1


@pytest.mark.asyncio
async def test_event_payload_forensic_immutability(
    test_db_session: AsyncSession,
) -> None:
    """Verify raw_payload, timestamp, and source fields remain 100% unmutated after enrichment."""
    original_raw = {
        "msg": "Critical access",
        "custom": {"nested": "value", "id": 123},
    }
    event = await create_test_event(test_db_session, source_ip="198.51.100.22")
    event.raw_payload = original_raw
    await test_db_session.commit()

    orig_timestamp = event.timestamp
    orig_source_ip = event.source_ip
    orig_dest_ip = event.destination_ip

    # Perform enrichment
    await enrich_event(test_db_session, event.id)

    # Re-fetch event from database
    refreshed = (
        await test_db_session.execute(select(Event).where(Event.id == event.id))
    ).scalar_one()

    assert refreshed.raw_payload == original_raw
    assert refreshed.timestamp == orig_timestamp
    assert refreshed.source_ip == orig_source_ip
    assert refreshed.destination_ip == orig_dest_ip


@pytest.mark.asyncio
async def test_concurrent_enrichment_race_safety(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify concurrent enrichment calls on events sharing indicators execute cleanly."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "concurrent_admin")
    event1 = await create_test_event(test_db_session, source_ip="198.51.100.33")
    event2 = await create_test_event(test_db_session, source_ip="198.51.100.33")

    req1 = async_client.post(
        f"/api/v1/events/{event1.id}/enrich",
        headers=auth_headers(admin_token),
    )
    req2 = async_client.post(
        f"/api/v1/events/{event2.id}/enrich",
        headers=auth_headers(admin_token),
    )

    results = await asyncio.gather(req1, req2)

    assert len(results) == 2
    assert results[0].status_code == 200
    assert results[1].status_code == 200
    assert results[0].json()["data"]["total_indicators"] > 0
    assert results[1].json()["data"]["total_indicators"] > 0


# ==============================================================================
# 6. Evidence Chain Explainability (Incident -> Alert -> Event -> Indicator)
# ==============================================================================


@pytest.mark.asyncio
async def test_cross_entity_indicator_pivoting(test_db_session: AsyncSession) -> None:
    """Verify analyst can pivot from Incident or Alert down to correlated indicators."""
    user, _ = await create_user(test_db_session, ROLE_ADMIN, "admin_pivot")

    # 1. Create Event with a known malicious indicator
    malicious_ip = "198.51.100.66"
    event = await create_test_event(test_db_session, source_ip=malicious_ip)

    # 2. Enrich the event and attach threat intelligence
    enrichment = await enrich_event(test_db_session, event.id)
    ip_indicator = next(i for i in enrichment.indicators if i.normalized_value == malicious_ip)

    await add_threat_intelligence(
        test_db_session,
        indicator_id=ip_indicator.indicator_id,
        payload=ThreatIntelligenceCreateRequest(
            source="CROWD_THREAT",
            threat_classification=ThreatClassification.MALICIOUS,
            severity=IntelligenceSeverity.HIGH,
            confidence=90,
            threat_actor="FancyBear",
        ),
    )

    # 3. Create an Alert linked to this Event
    alert = Alert(
        rule_id="RULE-NET-01",
        rule_version=1,
        title="Suspicious Outbound Connection",
        description="Outbound connection to untrusted network",
        severity="HIGH",
        status="OPEN",
        dedup_key=f"dedup-{uuid.uuid4().hex[:8]}",
        correlation_key=malicious_ip,
        observed_count=1,
        threshold=1,
        source_ip=malicious_ip,
        first_seen=datetime.now(UTC) - timedelta(minutes=5),
        last_seen=datetime.now(UTC),
    )
    test_db_session.add(alert)
    await test_db_session.flush()

    test_db_session.add(AlertEvent(alert_id=alert.id, event_id=event.id))
    await test_db_session.flush()

    # 4. Create an Incident linking both the Alert and the Event
    incident = Incident(
        incident_id=f"INC-{datetime.now(UTC).strftime('%Y%m%d')}-0001",
        title="C2 Communication Investigation",
        description="Host communicated with known malicious C2 IP",
        severity="HIGH",
        priority="HIGH",
        status="OPEN",
        created_by_user_id=user.id,
    )
    test_db_session.add(incident)
    await test_db_session.flush()

    test_db_session.add(IncidentAlert(incident_id=incident.id, alert_id=alert.id))
    test_db_session.add(IncidentEvent(incident_id=incident.id, event_id=event.id))
    await test_db_session.commit()

    # Pivot from Event
    event_iocs = await get_event_indicators(test_db_session, event.id)
    assert any(i.normalized_value == malicious_ip for i in event_iocs)

    # Pivot from Alert
    alert_iocs = await get_alert_indicators(test_db_session, alert.id)
    assert any(i.normalized_value == malicious_ip for i in alert_iocs)

    # Pivot from Incident (by incident UUID and human ID)
    inc_iocs = await get_incident_indicators(test_db_session, incident.incident_id)
    assert any(i.normalized_value == malicious_ip for i in inc_iocs)
    target_ioc = next(i for i in inc_iocs if i.normalized_value == malicious_ip)
    assert target_ioc.is_threat is True
    assert target_ioc.threat_intelligences[0].threat_actor == "FancyBear"


# ==============================================================================
# 7. RBAC Enforcement & API Endpoints
# ==============================================================================


@pytest.mark.asyncio
async def test_indicator_api_rbac_permissions(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify RBAC boundaries across ADMIN, ANALYST, VIEWER, and unauthenticated clients."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "admin_sec")
    analyst_user, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "analyst_sec")
    viewer_user, viewer_token = await create_user(test_db_session, ROLE_VIEWER, "viewer_sec")

    # Unauthenticated request: 401 Unauthorized
    unauth_resp = await async_client.get("/api/v1/indicators")
    assert unauth_resp.status_code == 401

    # VIEWER can read indicators (200 OK)
    viewer_resp = await async_client.get("/api/v1/indicators", headers=auth_headers(viewer_token))
    assert viewer_resp.status_code == 200

    # VIEWER cannot create an indicator (403 Forbidden)
    viewer_create_resp = await async_client.post(
        "/api/v1/indicators",
        headers=auth_headers(viewer_token),
        json={"type": "DOMAIN", "value": "forbidden-create.com"},
    )
    assert viewer_create_resp.status_code == 403

    # ANALYST can create an indicator (201 Created)
    analyst_create_resp = await async_client.post(
        "/api/v1/indicators",
        headers=auth_headers(analyst_token),
        json={
            "type": "DOMAIN",
            "value": "analyst-created.com",
            "description": "Reported by threat hunting",
        },
    )
    assert analyst_create_resp.status_code == 201
    created_id = analyst_create_resp.json()["data"]["id"]

    # ANALYST can attach threat intelligence (201 Created)
    intel_post_resp = await async_client.post(
        f"/api/v1/indicators/{created_id}/intelligence",
        headers=auth_headers(analyst_token),
        json={
            "source": "INTERNAL_ANALYSIS",
            "threat_classification": "SUSPICIOUS",
            "severity": "HIGH",
            "confidence": 75,
            "description": "Suspicious dynamic DNS",
        },
    )
    assert intel_post_resp.status_code == 201
    intel_id = intel_post_resp.json()["data"]["id"]

    # ANALYST cannot delete threat intelligence (403 Forbidden: intelligence.delete is ADMIN only)
    analyst_del_resp = await async_client.delete(
        f"/api/v1/indicators/intelligence/{intel_id}",
        headers=auth_headers(analyst_token),
    )
    assert analyst_del_resp.status_code == 403

    # ADMIN can delete threat intelligence (204 No Content)
    admin_del_resp = await async_client.delete(
        f"/api/v1/indicators/intelligence/{intel_id}",
        headers=auth_headers(admin_token),
    )
    assert admin_del_resp.status_code == 204


@pytest.mark.asyncio
async def test_event_enrichment_api_endpoint(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify POST /api/v1/events/{id}/enrich and GET /api/v1/events/{id}/indicators."""
    analyst_user, analyst_token = await create_user(test_db_session, ROLE_ANALYST, "enricher")
    event = await create_test_event(test_db_session, source_ip="198.51.100.89")

    # Call enrich endpoint
    enrich_resp = await async_client.post(
        f"/api/v1/events/{event.id}/enrich",
        headers=auth_headers(analyst_token),
    )
    assert enrich_resp.status_code == 200
    data = enrich_resp.json()["data"]
    assert data["event_id"] == str(event.id)
    assert data["total_indicators"] >= 1

    # Call get indicators endpoint
    get_resp = await async_client.get(
        f"/api/v1/events/{event.id}/indicators",
        headers=auth_headers(analyst_token),
    )
    assert get_resp.status_code == 200
    indicators = get_resp.json()["data"]
    assert len(indicators) >= 1
    assert any(i["normalized_value"] == "198.51.100.89" for i in indicators)


# ==============================================================================
# 8. Audit Logging Verification
# ==============================================================================


@pytest.mark.asyncio
async def test_intelligence_audit_log_generation(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify append-only audit trail captures indicator and intelligence operations."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "auditor_admin")

    # 1. Create indicator via API
    create_resp = await async_client.post(
        "/api/v1/indicators",
        headers=auth_headers(admin_token),
        json={"type": "IP", "value": "203.0.113.99"},
    )
    indicator_id = create_resp.json()["data"]["id"]

    # 2. Update indicator status
    await async_client.patch(
        f"/api/v1/indicators/{indicator_id}",
        headers=auth_headers(admin_token),
        json={"status": "WATCHLIST", "description": "High priority watchlist"},
    )

    # 3. Attach intelligence
    intel_resp = await async_client.post(
        f"/api/v1/indicators/{indicator_id}/intelligence",
        headers=auth_headers(admin_token),
        json={
            "source": "ABUSE_CH",
            "threat_classification": "MALICIOUS",
            "severity": "CRITICAL",
            "confidence": 98,
            "source_reference": "REF-1002",
        },
    )
    intel_id = intel_resp.json()["data"]["id"]

    # 4. Delete intelligence
    await async_client.delete(
        f"/api/v1/indicators/intelligence/{intel_id}",
        headers=auth_headers(admin_token),
    )

    # Query audit logs
    logs_res = await test_db_session.execute(select(AuditLog).order_by(AuditLog.timestamp.asc()))
    logs = logs_res.scalars().all()
    actions = [log.action for log in logs]

    assert "INDICATOR_CREATED" in actions
    assert "INDICATOR_UPDATED" in actions
    assert "INTELLIGENCE_CREATED" in actions
    assert "INTELLIGENCE_DELETED" in actions


# ==============================================================================
# 9. Negative Security Tests & Edge Cases
# ==============================================================================


@pytest.mark.asyncio
async def test_negative_security_edge_cases(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify IDOR 404, SQL injection resistance, and invalid confidence bounds."""
    admin_user, admin_token = await create_user(test_db_session, ROLE_ADMIN, "sec_tester")

    # Non-existent indicator UUID returns 404
    non_existent = str(uuid.uuid4())
    res_404 = await async_client.get(
        f"/api/v1/indicators/{non_existent}",
        headers=auth_headers(admin_token),
    )
    assert res_404.status_code == 404

    # Search with SQL injection attempt is safely parameterized and returns 200 with 0 results
    sqli_res = await async_client.get(
        "/api/v1/indicators?search=' OR 1=1 --",
        headers=auth_headers(admin_token),
    )
    assert sqli_res.status_code == 200
    assert sqli_res.json()["data"]["total"] == 0

    # Invalid confidence score > 100 rejected by Pydantic (422 Unprocessable Entity)
    indicator, _ = await create_or_get_indicator(
        test_db_session, type=IndicatorType.IP, value="198.51.100.1"
    )
    invalid_conf_res = await async_client.post(
        f"/api/v1/indicators/{indicator.id}/intelligence",
        headers=auth_headers(admin_token),
        json={
            "source": "TEST",
            "confidence": 150,  # Invalid: must be <= 100
        },
    )
    assert invalid_conf_res.status_code == 422

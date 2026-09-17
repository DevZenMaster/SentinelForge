"""Comprehensive tests for SentinelForge Event Ingestion Pipeline (Phase 3).

Validates:
1. Authentication & Authorization boundaries (401 unauth, 403 viewer, 201 analyst/admin)
2. Strict Pydantic schema validation:
   - IPv4 / IPv6 addresses via standard library ipaddress (no DNS lookup)
   - Invalid IP rejection
   - Timezone-aware UTC timestamp validation and future/past bounds
   - Port bounds (0-65535)
   - Controlled severity enum
   - Supported source types
   - Extra forbidden fields
3. Idempotency & Deduplication:
   - First submission returns 201 Created with status="ingested"
   - Replay returns 200 OK with status="duplicate" and identical event_id and ingested_at
   - Idempotency-Key HTTP header support
   - Header vs payload mismatch rejection (422)
   - Concurrency race handling via database unique constraint
4. Evidentiary integrity (raw_payload preserved verbatim in JSONB)
5. Audit logging (EVENT_INGEST_SUCCESS and EVENT_INGEST_DUPLICATE without raw payload)
6. Rate limiting (429 with Retry-After header)
7. Oversized payload rejection (413 Payload Too Large)
8. X-Request-ID header sanitization against log injection
9. Event retrieval endpoint GET /api/v1/events/{event_id}
"""

import asyncio
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limit import event_rate_limiter
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import hash_password
from app.models import AuditLog, Event, Role, User, UserRole
from app.services.auth import create_session
from app.services.seed import seed_rbac_and_admin


async def create_test_persona(db: AsyncSession, role_name: str, username: str) -> tuple[User, str]:
    """Helper creating a test user, binding a role, and issuing a session token."""
    await seed_rbac_and_admin(db)

    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=hash_password("TestPassword123!"),
        is_active=True,
    )
    db.add(user)
    await db.flush()

    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.commit()

    _, raw_token = await create_session(db, user)
    return user, raw_token


def auth_headers(raw_token: str | None = None) -> dict[str, str]:
    """Build request headers with session cookie and CSRF defense header."""
    headers = {"X-Requested-With": "XMLHttpRequest"}
    if raw_token:
        headers["Cookie"] = f"{settings.SESSION_COOKIE_NAME}={raw_token}"
    return headers


# ==============================================================================
# 1. Authentication and Authorization Guard Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_event_ingest_unauthenticated_rejected(async_client: AsyncClient) -> None:
    """Verify unauthenticated requests return 401 Unauthorized."""
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "firewall-01",
        "event_type": "firewall_drop",
        "raw_payload": {"rule": "drop_all"},
    }
    resp = await async_client.post("/api/v1/events", json=payload, headers=auth_headers())
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_event_ingest_viewer_forbidden(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify VIEWER persona is blocked with 403 Forbidden from ingesting events."""
    _, token = await create_test_persona(test_db_session, ROLE_VIEWER, "viewer_ingest_test")
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "sensor-01",
        "event_type": "network_flow",
        "raw_payload": {"src": "10.0.0.1"},
    }
    resp = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"
    assert "events.create" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_event_ingest_analyst_and_admin_allowed(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify ANALYST and ADMIN personas can successfully ingest security events."""
    _, analyst_token = await create_test_persona(
        test_db_session, ROLE_ANALYST, "analyst_ingest_test"
    )
    _, admin_token = await create_test_persona(test_db_session, ROLE_ADMIN, "admin_ingest_test")

    payload_analyst = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "host-web-01",
        "source_type": "web",
        "event_type": "http_request",
        "severity": "INFO",
        "raw_payload": {"url": "/api/v1/login", "method": "POST"},
    }
    resp_analyst = await async_client.post(
        "/api/v1/events", json=payload_analyst, headers=auth_headers(analyst_token)
    )
    assert resp_analyst.status_code == 201
    assert resp_analyst.json()["data"]["status"] == "ingested"

    payload_admin = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "host-db-01",
        "source_type": "application",
        "event_type": "db_auth",
        "severity": "LOW",
        "raw_payload": {"user": "postgres"},
    }
    resp_admin = await async_client.post(
        "/api/v1/events", json=payload_admin, headers=auth_headers(admin_token)
    )
    assert resp_admin.status_code == 201
    assert resp_admin.json()["data"]["status"] == "ingested"


# ==============================================================================
# 2. Schema Validation Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_event_validation_required_fields(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify missing required fields trigger 422 Unprocessable Entity."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_val_req")

    # Missing raw_payload and source
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "event_type": "test_event",
    }
    resp = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "VALIDATION_ERROR"


@pytest.mark.asyncio
async def test_event_validation_ipv4_and_ipv6(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify valid IPv4 and IPv6 addresses are accepted and preserved."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_val_ip")

    # Valid IPv4
    resp_v4 = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "edge-router",
            "source_type": "network",
            "source_ip": "192.168.10.15",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "event_type": "packet_inspect",
            "raw_payload": {"proto": "tcp"},
        },
        headers=auth_headers(token),
    )
    assert resp_v4.status_code == 201

    # Valid IPv6
    resp_v6 = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "edge-router",
            "source_type": "network",
            "source_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "destination_ip": "::1",
            "destination_port": 80,
            "event_type": "packet_inspect",
            "raw_payload": {"proto": "ipv6"},
        },
        headers=auth_headers(token),
    )
    assert resp_v6.status_code == 201


@pytest.mark.asyncio
async def test_event_validation_invalid_ip_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify invalid IP addresses are rejected with 422 without DNS lookups."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_inv_ip")

    # Invalid octet
    resp = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "firewall",
            "source_ip": "300.168.1.1",
            "event_type": "network_flow",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp.status_code == 422
    assert "Invalid IP address format" in str(resp.json()["error"]["details"])

    # Hostname (must not resolve DNS)
    resp_dns = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "firewall",
            "source_ip": "evil.malicious.attacker.com",
            "event_type": "network_flow",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_dns.status_code == 422


@pytest.mark.asyncio
async def test_event_validation_destination_port_bounds(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify destination_port must be in range 0-65535."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_port")

    # Port below 0
    resp_low = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "firewall",
            "destination_port": -1,
            "event_type": "conn",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_low.status_code == 422

    # Port above 65535
    resp_high = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "firewall",
            "destination_port": 65536,
            "event_type": "conn",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_high.status_code == 422


@pytest.mark.asyncio
async def test_event_validation_timestamp_bounds_and_tz(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify timezone-aware requirement and past/future sanity bounds."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_ts")

    # Naive timestamp (no UTC offset or Z)
    resp_naive = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": "2026-09-17T09:00:00",
            "source": "syslog",
            "event_type": "log",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_naive.status_code == 422
    assert "timezone-aware" in str(resp_naive.json()["error"]["details"])

    # Timestamp far in future (> 5 mins)
    future_ts = (datetime.now(UTC) + timedelta(hours=2)).isoformat()
    resp_future = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": future_ts,
            "source": "syslog",
            "event_type": "log",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_future.status_code == 422
    assert "future" in str(resp_future.json()["error"]["details"])

    # Timestamp older than 365 days
    ancient_ts = (datetime.now(UTC) - timedelta(days=400)).isoformat()
    resp_ancient = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": ancient_ts,
            "source": "syslog",
            "event_type": "log",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_ancient.status_code == 422
    assert "older than 365 days" in str(resp_ancient.json()["error"]["details"])


@pytest.mark.asyncio
async def test_event_validation_severity_and_source_type_enums(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify controlled severity enum and source classifications."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_enums")

    # Valid case-insensitive severity and source_type
    resp_valid = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "linux-agent",
            "source_type": "LINUX",
            "severity": "high",
            "event_type": "auth_failure",
            "raw_payload": {"user": "daemon"},
        },
        headers=auth_headers(token),
    )
    assert resp_valid.status_code == 201

    # Invalid severity
    resp_inv_sev = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "linux-agent",
            "severity": "CATASTROPHIC",
            "event_type": "auth_failure",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_inv_sev.status_code == 422

    # Invalid source_type
    resp_inv_src = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "linux-agent",
            "source_type": "super_custom_unsupported",
            "event_type": "auth_failure",
            "raw_payload": {},
        },
        headers=auth_headers(token),
    )
    assert resp_inv_src.status_code == 422


@pytest.mark.asyncio
async def test_event_validation_extra_fields_forbidden(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify unmapped or injected extra fields in payload trigger 422."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_extra")
    resp = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "linux-agent",
            "event_type": "auth_failure",
            "raw_payload": {},
            "unauthorized_field": "injected_data",
        },
        headers=auth_headers(token),
    )
    assert resp.status_code == 422


# ==============================================================================
# 3. Idempotency and Deduplication Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_event_idempotency_external_event_id(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify initial submission returns 201 Created and duplicate replay returns 200 OK."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_idemp")

    ext_id = "agent-event-unique-998811"
    payload = {
        "external_event_id": ext_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "edr-agent",
        "source_type": "windows",
        "event_type": "process_creation",
        "severity": "MEDIUM",
        "raw_payload": {"cmdline": "powershell.exe -enc ...", "pid": 4120},
    }

    # 1. Initial ingestion -> 201 Created
    resp_1 = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp_1.status_code == 201
    data_1 = resp_1.json()["data"]
    assert data_1["status"] == "ingested"
    assert data_1["external_event_id"] == ext_id
    initial_event_id = data_1["event_id"]
    initial_ingested_at = data_1["ingested_at"]

    # 2. Duplicate submission -> 200 OK
    resp_2 = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp_2.status_code == 200
    data_2 = resp_2.json()["data"]
    assert data_2["status"] == "duplicate"
    assert data_2["event_id"] == initial_event_id
    assert data_2["ingested_at"] == initial_ingested_at
    assert data_2["external_event_id"] == ext_id


@pytest.mark.asyncio
async def test_event_idempotency_via_header(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify Idempotency-Key HTTP header functions as external_event_id."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_idemp_hdr")

    idemp_header_key = "idemp-key-xyz-777"
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "syslog-gateway",
        "event_type": "auth_attempt",
        "raw_payload": {"msg": "accepted password for user root"},
    }

    headers = auth_headers(token)
    headers["Idempotency-Key"] = idemp_header_key

    # 1. First attempt with header -> 201 Created
    resp_1 = await async_client.post("/api/v1/events", json=payload, headers=headers)
    assert resp_1.status_code == 201
    data_1 = resp_1.json()["data"]
    assert data_1["status"] == "ingested"
    assert data_1["external_event_id"] == idemp_header_key

    # 2. Second attempt with same header -> 200 OK
    resp_2 = await async_client.post("/api/v1/events", json=payload, headers=headers)
    assert resp_2.status_code == 200
    data_2 = resp_2.json()["data"]
    assert data_2["status"] == "duplicate"
    assert data_2["event_id"] == data_1["event_id"]


@pytest.mark.asyncio
async def test_event_idempotency_mismatched_header_and_body_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify conflict between Idempotency-Key header and external_event_id returns 422."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_mismatch")

    headers = auth_headers(token)
    headers["Idempotency-Key"] = "header-key-1"

    payload = {
        "external_event_id": "body-key-2",
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "syslog",
        "event_type": "log",
        "raw_payload": {},
    }

    resp = await async_client.post("/api/v1/events", json=payload, headers=headers)
    assert resp.status_code == 422
    assert "Mismatched" in resp.json()["error"]["message"]


@pytest.mark.asyncio
async def test_event_idempotency_concurrency_race(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify concurrent requests with identical external_event_id resolve cleanly without 500."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_concurr")

    race_ext_id = "concurrent-race-key-555"
    payload = {
        "external_event_id": race_ext_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "vpn-gateway",
        "event_type": "vpn_login",
        "raw_payload": {"vpn_user": "analyst"},
    }

    # Launch two simultaneous requests
    req1 = async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    req2 = async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))

    resp1, resp2 = await asyncio.gather(req1, req2)

    status_codes = sorted([resp1.status_code, resp2.status_code])
    assert status_codes == [200, 201]

    # Exactly 1 row in database
    stmt = select(Event).where(Event.external_event_id == race_ext_id)
    events = (await test_db_session.execute(stmt)).scalars().all()
    assert len(events) == 1


# ==============================================================================
# 4. Evidentiary Integrity & Audit Logging Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_event_raw_payload_preserved_verbatim(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify full raw_payload structure is stored verbatim in PostgreSQL JSONB column."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_verbatim")

    complex_raw_payload = {
        "nested_dict": {
            "key1": "value1",
            "nested_list": [1, 2, "three", {"inner": True}],
        },
        "flag": False,
        "null_val": None,
        "numeric_val": 42.123,
    }

    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "json-logger",
        "event_type": "complex_telemetry",
        "raw_payload": complex_raw_payload,
    }

    resp = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp.status_code == 201
    event_id = resp.json()["data"]["event_id"]

    # Verify directly in database
    stmt = select(Event).where(Event.id == uuid.UUID(event_id))
    event_record = (await test_db_session.execute(stmt)).scalar_one()
    assert event_record.raw_payload == complex_raw_payload


@pytest.mark.asyncio
async def test_event_ingest_audit_log_telemetry(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify append-only audit entries are created without leaking raw payload."""
    analyst, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_audit_test")

    ext_id = "audit-telemetry-id-123"
    payload = {
        "external_event_id": ext_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "waf",
        "event_type": "sql_injection_attempt",
        "severity": "CRITICAL",
        "raw_payload": {"sensitive_internal_query": "SELECT password FROM accounts"},
    }

    # Ingest once
    resp1 = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp1.status_code == 201

    # Ingest duplicate
    resp2 = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp2.status_code == 200

    # Inspect audit log records
    stmt = (
        select(AuditLog)
        .where(AuditLog.actor_user_id == analyst.id)
        .order_by(AuditLog.timestamp.asc())
    )
    audit_entries = (await test_db_session.execute(stmt)).scalars().all()
    actions = [e.action for e in audit_entries]

    assert "EVENT_INGEST_SUCCESS" in actions
    assert "EVENT_INGEST_DUPLICATE" in actions

    for entry in audit_entries:
        assert entry.resource_type == "event"
        # Ensure sensitive raw_payload was not dumped into audit new_value
        if entry.new_value:
            assert "sensitive_internal_query" not in str(entry.new_value)


# ==============================================================================
# 5. Security Controls: Rate Limiting, Payload Size, Request ID Sanitization
# ==============================================================================


@pytest.mark.asyncio
async def test_event_ingest_rate_limiting(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify exceeding rate limit triggers 429 Too Many Requests with Retry-After header."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_ratelimit")

    # Manually configure a tight window for test
    event_rate_limiter.clear()

    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "spam-agent",
        "event_type": "ping",
        "raw_payload": {"msg": "ping"},
    }

    # Simulate hitting rate limit by artificially registering events in limiter
    client_ip = "127.0.0.1"
    for _ in range(settings.EVENTS_RATE_LIMIT_PER_MINUTE):
        event_rate_limiter.is_rate_limited(
            f"event:ip:{client_ip}",
            max_requests=settings.EVENTS_RATE_LIMIT_PER_MINUTE,
            window_seconds=60,
        )

    # Next request must be rate limited
    resp = await async_client.post("/api/v1/events", json=payload, headers=auth_headers(token))
    assert resp.status_code == 429
    assert resp.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in resp.headers

    event_rate_limiter.clear()


@pytest.mark.asyncio
async def test_event_oversized_payload_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify payloads exceeding MAX_EVENT_PAYLOAD_BYTES return 413 Payload Too Large."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_oversized")

    headers = auth_headers(token)
    headers["Content-Length"] = str(settings.MAX_EVENT_PAYLOAD_BYTES + 1024)

    resp = await async_client.post(
        "/api/v1/events",
        content=b"{}",
        headers=headers,
    )
    assert resp.status_code == 413
    assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.asyncio
async def test_event_request_id_sanitization(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify malicious X-Request-ID headers (e.g. CRLF injection) are sanitized."""
    _, token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_req_id")

    malicious_header = "injected\r\nSet-Cookie: evil=true"
    headers = auth_headers(token)
    headers["X-Request-ID"] = malicious_header

    resp = await async_client.post(
        "/api/v1/events",
        json={
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "syslog",
            "event_type": "log",
            "raw_payload": {},
        },
        headers=headers,
    )
    # The returned X-Request-ID must NOT be the malicious header
    returned_id = resp.headers.get("X-Request-ID")
    assert returned_id != malicious_header
    assert returned_id.startswith("req-")


# ==============================================================================
# 6. Event Retrieval Endpoint (GET /api/v1/events/{event_id})
# ==============================================================================


@pytest.mark.asyncio
async def test_get_event_by_id_lifecycle(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify GET /api/v1/events/{event_id} permissions and response content."""
    _, analyst_token = await create_test_persona(test_db_session, ROLE_ANALYST, "analyst_reader")
    _, viewer_token = await create_test_persona(test_db_session, ROLE_VIEWER, "viewer_reader")

    # Ingest event as analyst
    payload = {
        "timestamp": datetime.now(UTC).isoformat(),
        "source": "k8s-cluster",
        "source_type": "cloud",
        "source_ip": "10.244.0.5",
        "event_type": "pod_exec",
        "severity": "HIGH",
        "message": "exec into container",
        "raw_payload": {"namespace": "prod", "pod": "api-server-xyz"},
        "metadata": {"cluster_id": "us-east-1"},
    }
    create_resp = await async_client.post(
        "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
    )
    assert create_resp.status_code == 201
    event_id = create_resp.json()["data"]["event_id"]

    # 1. VIEWER cannot fetch event (events.read restricted to ANALYST and ADMIN) -> 403
    viewer_resp = await async_client.get(
        f"/api/v1/events/{event_id}", headers=auth_headers(viewer_token)
    )
    assert viewer_resp.status_code == 403
    assert viewer_resp.json()["error"]["code"] == "FORBIDDEN"

    # 2. ANALYST can fetch event (has events.read) -> 200 OK
    get_resp = await async_client.get(
        f"/api/v1/events/{event_id}", headers=auth_headers(analyst_token)
    )
    assert get_resp.status_code == 200
    event_data = get_resp.json()["data"]
    assert event_data["id"] == event_id
    assert event_data["source"] == "k8s-cluster"
    assert event_data["source_type"] == "cloud"
    assert event_data["source_ip"] == "10.244.0.5"
    assert event_data["severity"] == "HIGH"
    assert event_data["raw_payload"]["namespace"] == "prod"
    assert event_data["metadata"]["cluster_id"] == "us-east-1"
    assert event_data["normalization_status"] in ("NORMALIZED", "PARTIAL")
    assert event_data["parser_name"] is not None
    assert "outcome" in event_data
    assert "attributes" in event_data

    # 3. Nonexistent UUID returns 404
    fake_uuid = "00000000-0000-0000-0000-000000000000"
    missing_resp = await async_client.get(
        f"/api/v1/events/{fake_uuid}", headers=auth_headers(analyst_token)
    )
    assert missing_resp.status_code == 404
    assert missing_resp.json()["error"]["code"] == "NOT_FOUND"

    # 3. Unauthenticated request returns 401
    unauth_resp = await async_client.get(
        f"/api/v1/events/{event_id}", headers={"X-Requested-With": "XMLHttpRequest"}
    )
    assert unauth_resp.status_code == 401

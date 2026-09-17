"""Comprehensive Test Suite for SentinelForge Phase 4: Event Normalization & Canonicalization.

Validates:
1. Field Normalizers (IP, port, username, timestamp, severity)
2. Parsers: GenericParser, LinuxAuthParser, WebParser
3. ParserRegistry selection and fallback behavior
4. Dispatcher execution and raw_payload immutability
5. End-to-end ingestion pipeline normalization and persistence
6. Reprocessing endpoint (POST /api/v1/events/{id}/normalize)
7. RBAC enforcement (Viewer 403, Analyst 200, Admin 200)
8. Failure tolerance and partial normalization
9. Streaming body size enforcement and nesting depth recursion guards
"""

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import hash_password
from app.models import AuditLog, Event, Role, User, UserRole
from app.normalization.base import (
    normalize_ip,
    normalize_port,
    normalize_severity,
    normalize_timestamp,
    normalize_username,
)
from app.normalization.dispatcher import apply_normalization_to_event, normalize_event
from app.normalization.models import (
    EventOutcome,
    NormalizationErrorCode,
    NormalizationStatus,
)
from app.normalization.parsers.generic import GenericParser
from app.normalization.parsers.linux_auth import LinuxAuthParser
from app.normalization.parsers.web import WebParser
from app.normalization.registry import default_registry
from app.schemas.event import EventSeverity
from app.services.auth import create_session
from app.services.event import get_event_by_id
from app.services.seed import seed_rbac_and_admin


async def create_test_user(db: AsyncSession, role_name: str, username: str) -> tuple[User, str]:
    """Helper creating a test user with assigned role and returning active session token."""
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=hash_password("Password123!"),
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


# ==============================================================================
# 1. Individual Field Normalizers
# ==============================================================================


class TestFieldNormalizers:
    """Test individual scalar field normalizers for determinism and strict validation."""

    def test_normalize_ip_valid_ipv4_and_ipv6(self) -> None:
        ip4, err = normalize_ip(" 192.168.1.100 ", "source_ip")
        assert err is None
        assert ip4 == "192.168.1.100"

        ip6, err = normalize_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "destination_ip")
        assert err is None
        assert ip6 == "2001:db8:85a3::8a2e:370:7334"

        # None / empty should return None without error
        assert normalize_ip(None, "source_ip") == (None, None)
        assert normalize_ip("   ", "source_ip") == (None, None)

    def test_normalize_ip_invalid_formats(self) -> None:
        # Invalid IP string
        ip, err = normalize_ip("not-an-ip", "source_ip")
        assert ip is None
        assert err is not None
        assert err.code == NormalizationErrorCode.INVALID_IP
        assert err.field == "source_ip"

        # Out-of-range octet
        ip, err = normalize_ip("256.1.1.1", "source_ip")
        assert ip is None
        assert err is not None

        # Domain names rejected (no DNS lookup)
        ip, err = normalize_ip("malicious.domain.com", "source_ip")
        assert ip is None
        assert err is not None

    def test_normalize_port_valid_and_bounds(self) -> None:
        assert normalize_port(80, "port") == (80, None)
        assert normalize_port("443", "port") == (443, None)
        assert normalize_port(0, "port") == (0, None)
        assert normalize_port(65535, "port") == (65535, None)
        assert normalize_port(None, "port") == (None, None)
        assert normalize_port("", "port") == (None, None)

    def test_normalize_port_invalid_and_out_of_bounds(self) -> None:
        port, err = normalize_port(70000, "source_port")
        assert port is None
        assert err is not None
        assert err.code == NormalizationErrorCode.INVALID_PORT

        port, err = normalize_port(-1, "destination_port")
        assert port is None
        assert err is not None

        port, err = normalize_port("not_a_port", "source_port")
        assert port is None
        assert err is not None

    def test_normalize_username(self) -> None:
        assert normalize_username("  admin  ") == "admin"
        assert normalize_username("root") == "root"
        assert normalize_username(None) is None
        assert normalize_username("   ") is None
        # Max length truncation/sanitization
        long_user = "a" * 200
        assert len(normalize_username(long_user) or "") == 128

    def test_normalize_timestamp_valid_formats(self) -> None:
        ref_dt = (datetime.now(UTC) - timedelta(minutes=2)).replace(microsecond=0)

        # datetime object
        dt, err = normalize_timestamp(ref_dt, "timestamp")
        assert err is None
        assert dt == ref_dt

        # ISO 8601 string
        dt, err = normalize_timestamp(ref_dt.isoformat(), "timestamp")
        assert err is None
        assert dt == ref_dt

        # Unix epoch int / float
        dt, err = normalize_timestamp(ref_dt.timestamp(), "timestamp")
        assert err is None
        assert dt == ref_dt

    def test_normalize_timestamp_invalid(self) -> None:
        dt, err = normalize_timestamp("unparseable_time", "timestamp")
        assert dt is None
        assert err is not None
        assert err.code == NormalizationErrorCode.INVALID_TIMESTAMP

    def test_normalize_severity(self) -> None:
        assert normalize_severity("high") == (EventSeverity.HIGH, None)
        assert normalize_severity("CRITICAL") == (EventSeverity.CRITICAL, None)
        assert normalize_severity(EventSeverity.MEDIUM) == (EventSeverity.MEDIUM, None)
        assert normalize_severity("unknown")[0] == EventSeverity.INFO
        assert normalize_severity(None) == (EventSeverity.INFO, None)


# ==============================================================================
# 2. Source-Specific Parsers Unit Tests
# ==============================================================================


class TestGenericParser:
    """Validate GenericParser behavior, outcome inference, and attribute preservation."""

    def test_generic_parser_outcome_inference(self) -> None:
        parser = GenericParser()
        base_meta = {"event_type": "process", "action": "login_failed"}
        now = datetime.now(UTC)

        # Action implies failure
        res = parser.parse(
            raw_payload={"message": "Failed attempt"},
            source="custom_app",
            source_type="generic",
            fallback_timestamp=now,
            base_metadata=base_meta,
        )
        assert res.status == NormalizationStatus.NORMALIZED
        assert res.canonical_data is not None
        assert res.canonical_data.outcome == EventOutcome.FAILURE
        assert res.canonical_data.action == "login_failed"

        # Explicit outcome takes precedence
        res2 = parser.parse(
            raw_payload={"outcome": "success", "action": "login_attempt"},
            source="custom_app",
            source_type="generic",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res2.canonical_data is not None
        assert res2.canonical_data.outcome == EventOutcome.SUCCESS

    def test_generic_parser_attribute_preservation_and_immutability(self) -> None:
        parser = GenericParser()
        now = datetime.now(UTC)
        raw = {
            "source_ip": "10.0.0.1",
            "custom_metric": 42.5,
            "tags": ["env:prod", "tier:frontend"],
            "nested_info": {"datacenter": "dc-1"},
        }
        raw_copy = dict(raw)

        res = parser.parse(
            raw_payload=raw,
            source="agent-01",
            source_type="syslog",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res.canonical_data is not None
        # source_ip was mapped to canonical field, rest kept in attributes
        assert res.canonical_data.source_ip == "10.0.0.1"
        assert res.canonical_data.attributes["custom_metric"] == 42.5
        assert res.canonical_data.attributes["tags"] == ["env:prod", "tier:frontend"]
        assert res.canonical_data.attributes["nested_info"] == {"datacenter": "dc-1"}
        assert "source_ip" not in res.canonical_data.attributes

        # Raw payload was not altered
        assert raw == raw_copy


class TestLinuxAuthParser:
    """Validate LinuxAuthParser against syslog patterns for RULE-001, RULE-002, RULE-003."""

    def test_sshd_failed_password_rule_001_and_002(self) -> None:
        parser = LinuxAuthParser()
        now = datetime.now(UTC)
        msg = "Failed password for invalid user attacker from 198.51.100.42 port 49152 ssh2"
        raw = {"message": msg, "service": "sshd"}

        res = parser.parse(
            raw_payload=raw,
            source="host-web-01",
            source_type="linux",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res.status == NormalizationStatus.NORMALIZED
        assert res.canonical_data is not None
        assert res.canonical_data.event_type == "authentication"
        assert res.canonical_data.action == "login_failed"
        assert res.canonical_data.outcome == EventOutcome.FAILURE
        assert res.canonical_data.username == "attacker"
        assert res.canonical_data.source_ip == "198.51.100.42"
        assert res.canonical_data.source_port == 49152
        assert res.canonical_data.severity == EventSeverity.MEDIUM

    def test_sshd_accepted_password_rule_003(self) -> None:
        parser = LinuxAuthParser()
        now = datetime.now(UTC)
        msg = "Accepted publickey for secops from 203.0.113.10 port 51234 ssh2"
        raw = {"message": msg, "service": "sshd"}

        res = parser.parse(
            raw_payload=raw,
            source="bastion-01",
            source_type="authentication",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res.status == NormalizationStatus.NORMALIZED
        assert res.canonical_data is not None
        assert res.canonical_data.event_type == "authentication"
        assert res.canonical_data.action == "login_success"
        assert res.canonical_data.outcome == EventOutcome.SUCCESS
        assert res.canonical_data.username == "secops"
        assert res.canonical_data.source_ip == "203.0.113.10"
        assert res.canonical_data.source_port == 51234
        assert res.canonical_data.severity == EventSeverity.INFO

    def test_pam_failure_pattern(self) -> None:
        parser = LinuxAuthParser()
        now = datetime.now(UTC)
        msg = (
            "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.0.2.1 user=root"
        )
        raw = {"message": msg, "service": "pam"}

        res = parser.parse(
            raw_payload=raw,
            source="db-server-01",
            source_type="linux",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res.canonical_data is not None
        assert res.canonical_data.action == "login_failed"
        assert res.canonical_data.outcome == EventOutcome.FAILURE
        assert res.canonical_data.username == "root"
        assert res.canonical_data.source_ip == "192.0.2.1"


class TestWebParser:
    """Validate WebParser against HTTP access patterns for RULE-004."""

    def test_web_parser_401_unauthorized_rule_004(self) -> None:
        parser = WebParser()
        now = datetime.now(UTC)
        raw = {
            "status_code": 401,
            "http_method": "POST",
            "http_path": "/api/v1/auth/login",
            "client_ip": "198.51.100.77",
            "user_agent": "Mozilla/5.0 Scanner",
            "username": "admin",
        }

        res = parser.parse(
            raw_payload=raw,
            source="nginx-ingress",
            source_type="web",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res.status == NormalizationStatus.NORMALIZED
        assert res.canonical_data is not None
        assert res.canonical_data.event_type == "web"
        assert res.canonical_data.action == "http_401"
        assert res.canonical_data.outcome == EventOutcome.FAILURE
        assert res.canonical_data.source_ip == "198.51.100.77"
        assert res.canonical_data.username == "admin"
        assert res.canonical_data.severity == EventSeverity.MEDIUM
        assert res.canonical_data.attributes["status_code"] == 401
        assert res.canonical_data.attributes["http_method"] == "POST"
        assert res.canonical_data.attributes["http_path"] == "/api/v1/auth/login"
        assert res.canonical_data.attributes["user_agent"] == "Mozilla/5.0 Scanner"

    def test_web_parser_200_ok(self) -> None:
        parser = WebParser()
        now = datetime.now(UTC)
        raw = {
            "status_code": 200,
            "http_method": "GET",
            "http_path": "/dashboard",
            "source_ip": "192.168.1.50",
        }
        res = parser.parse(
            raw_payload=raw,
            source="web-app",
            source_type="application",
            fallback_timestamp=now,
            base_metadata={},
        )
        assert res.canonical_data is not None
        assert res.canonical_data.action == "http_200"
        assert res.canonical_data.outcome == EventOutcome.SUCCESS
        assert res.canonical_data.severity == EventSeverity.INFO


# ==============================================================================
# 3. Registry & Dispatcher Tests
# ==============================================================================


class TestRegistryAndDispatcher:
    """Validate parser discovery priority, fallback behavior, and error capture."""

    def test_registry_priority_selection(self) -> None:
        registry = default_registry

        # Linux telemetry selects LinuxAuthParser
        p_linux = registry.get_parser("linux", {"message": "sshd"})
        assert isinstance(p_linux, LinuxAuthParser)

        # Web telemetry selects WebParser
        p_web = registry.get_parser("web", {"status_code": 200})
        assert isinstance(p_web, WebParser)

        # Unrecognized telemetry falls back to GenericParser
        p_fallback = registry.get_parser("custom_sensor", {"data": 123})
        assert isinstance(p_fallback, GenericParser)

    def test_dispatcher_immutability_guarantee(self) -> None:
        now = datetime.now(UTC)
        raw_original = {"event_type": "auth", "deep": {"k": "v"}, "source_ip": "1.2.3.4"}
        event = Event(
            id=uuid.uuid4(),
            timestamp=now,
            ingested_at=now,
            source="syslog",
            source_type="generic",
            event_type="auth",
            action="login",
            raw_payload=dict(raw_original),
        )

        res = normalize_event(event)
        assert res.status == NormalizationStatus.NORMALIZED
        # Verify raw_payload was not modified in any way
        assert event.raw_payload == raw_original

        # Applying normalization sets canonical fields
        apply_normalization_to_event(event, res)
        assert event.normalization_status == NormalizationStatus.NORMALIZED.value
        assert event.parser_name == "generic"
        assert event.parser_version == "1.0.0"
        assert event.source_ip == "1.2.3.4"
        assert event.attributes["deep"] == {"k": "v"}

    def test_dispatcher_deterministic_repeated_runs(self) -> None:
        now = datetime.now(UTC)
        event = Event(
            id=uuid.uuid4(),
            timestamp=now,
            ingested_at=now,
            source="sshd-host",
            source_type="linux",
            event_type="auth",
            action="observed",
            raw_payload={"message": "Failed password for root from 192.168.1.1 port 2222"},
        )

        res1 = normalize_event(event)
        res2 = normalize_event(event)

        assert res1.status == res2.status
        assert res1.parser_name == res2.parser_name
        assert res1.canonical_data is not None and res2.canonical_data is not None
        assert res1.canonical_data.model_dump() == res2.canonical_data.model_dump()

    def test_partial_normalization_with_invalid_ip(self) -> None:
        now = datetime.now(UTC)
        event = Event(
            id=uuid.uuid4(),
            timestamp=now,
            ingested_at=now,
            source="test",
            source_type="generic",
            event_type="test",
            action="login",
            raw_payload={"source_ip": "invalid-ip-address", "username": "valid_user"},
        )

        res = normalize_event(event)
        # Invalid IP generates warning/error, yielding PARTIAL status
        assert res.status == NormalizationStatus.PARTIAL
        assert len(res.errors) == 1
        assert res.errors[0].code == NormalizationErrorCode.INVALID_IP
        assert res.canonical_data is not None
        assert res.canonical_data.username == "valid_user"
        assert res.canonical_data.source_ip is None

        apply_normalization_to_event(event, res)
        assert event.normalization_status == NormalizationStatus.PARTIAL.value
        assert len(event.normalization_errors) == 1


# ==============================================================================
# 4. HTTP API End-to-End Pipeline & Reprocessing Tests
# ==============================================================================


@pytest.mark.asyncio
class TestNormalizationPipelineAPI:
    """Test full HTTP pipeline: ingestion normalization, RBAC, and reprocessing."""

    async def test_e2e_ingestion_automatic_normalization(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        """Verify events ingested via POST /events are immediately normalized in storage."""
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "norm_analyst")

        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "web-gateway",
            "source_type": "web",
            "event_type": "web",
            "action": "login",
            "raw_payload": {
                "status_code": 401,
                "http_method": "POST",
                "http_path": "/login",
                "source_ip": "198.51.100.99",
                "username": "victim_user",
            },
        }

        resp = await async_client.post(
            "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
        )
        assert resp.status_code == 201
        event_id = uuid.UUID(resp.json()["data"]["event_id"])

        # Fetch event directly from database to verify canonical fields
        event = await get_event_by_id(test_db_session, event_id)
        assert event is not None
        assert event.normalization_status == NormalizationStatus.NORMALIZED.value
        assert event.parser_name == "web"
        assert event.outcome == EventOutcome.FAILURE.value
        assert event.action == "http_401"
        assert event.source_ip == "198.51.100.99"
        assert event.username == "victim_user"
        assert event.attributes["status_code"] == 401
        assert event.attributes["http_method"] == "POST"

        # Verify via GET /api/v1/events/{id}
        get_resp = await async_client.get(
            f"/api/v1/events/{event_id}", headers=auth_headers(analyst_token)
        )
        assert get_resp.status_code == 200
        get_data = get_resp.json()["data"]
        assert get_data["normalization_status"] == "NORMALIZED"
        assert get_data["outcome"] == "failure"
        assert get_data["action"] == "http_401"

    async def test_rbac_get_event_by_id_boundaries(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        """Verify Viewer gets 403, Analyst gets 200, Admin gets 200 on GET /events/{id}."""
        _, viewer_token = await create_test_user(test_db_session, ROLE_VIEWER, "norm_viewer")
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "norm_analyst2")
        _, admin_token = await create_test_user(test_db_session, ROLE_ADMIN, "norm_admin")

        # Ingest an event as analyst
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "sensor-1",
            "event_type": "test",
            "raw_payload": {"hello": "world"},
        }
        create_resp = await async_client.post(
            "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
        )
        assert create_resp.status_code == 201
        event_id = create_resp.json()["data"]["event_id"]

        # 1. Viewer -> 403 Forbidden
        viewer_resp = await async_client.get(
            f"/api/v1/events/{event_id}", headers=auth_headers(viewer_token)
        )
        assert viewer_resp.status_code == 403
        assert viewer_resp.json()["error"]["code"] == "FORBIDDEN"

        # 2. Analyst -> 200 OK
        analyst_resp = await async_client.get(
            f"/api/v1/events/{event_id}", headers=auth_headers(analyst_token)
        )
        assert analyst_resp.status_code == 200

        # 3. Admin -> 200 OK
        admin_resp = await async_client.get(
            f"/api/v1/events/{event_id}", headers=auth_headers(admin_token)
        )
        assert admin_resp.status_code == 200

    async def test_reprocess_normalization_endpoint_lifecycle(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        """Verify POST /events/{id}/normalize re-evaluates event,
        checks RBAC and logs audit entry.
        """
        _, viewer_token = await create_test_user(test_db_session, ROLE_VIEWER, "reproc_viewer")
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "reproc_analyst")

        # Ingest an event initially with raw sshd message
        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "bastion-sshd",
            "source_type": "linux",
            "event_type": "auth",
            "raw_payload": {
                "message": "Failed password for root from 198.51.100.22 port 22 ssh2",
                "service": "sshd",
            },
        }
        create_resp = await async_client.post(
            "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
        )
        assert create_resp.status_code == 201
        event_id = create_resp.json()["data"]["event_id"]

        # 1. Viewer cannot reprocess -> 403 Forbidden
        viewer_reproc = await async_client.post(
            f"/api/v1/events/{event_id}/normalize", headers=auth_headers(viewer_token)
        )
        assert viewer_reproc.status_code == 403

        # 2. Analyst can reprocess -> 200 OK
        analyst_reproc = await async_client.post(
            f"/api/v1/events/{event_id}/normalize", headers=auth_headers(analyst_token)
        )
        assert analyst_reproc.status_code == 200
        reproc_data = analyst_reproc.json()["data"]
        assert reproc_data["normalization_status"] == "NORMALIZED"
        assert reproc_data["parser_name"] == "linux_auth"
        assert reproc_data["outcome"] == "failure"
        assert reproc_data["username"] == "root"
        assert reproc_data["source_ip"] == "198.51.100.22"

        # 3. Verify audit log entry was created for reprocessing
        audit_entry = (
            await test_db_session.execute(
                select(AuditLog)
                .where(AuditLog.action == "EVENT_NORMALIZATION_REPROCESSED")
                .where(AuditLog.resource_id == event_id)
            )
        ).scalar_one_or_none()
        assert audit_entry is not None
        assert audit_entry.new_value is not None
        assert audit_entry.new_value["parser_name"] == "linux_auth"

        # 4. Non-existent event returns 404
        fake_id = "00000000-0000-0000-0000-000000000000"
        missing_reproc = await async_client.post(
            f"/api/v1/events/{fake_id}/normalize", headers=auth_headers(analyst_token)
        )
        assert missing_reproc.status_code == 404

    async def test_deeply_nested_payload_recursion_guard(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        """Verify deeply nested dictionary payloads (>8 levels) are rejected with 422."""
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "nest_analyst")

        # Construct deeply nested payload (10 levels)
        deep_dict: dict[str, Any] = {"leaf": "value"}
        for _ in range(10):
            deep_dict = {"nested": deep_dict}

        payload = {
            "timestamp": datetime.now(UTC).isoformat(),
            "source": "sensor",
            "event_type": "nest_test",
            "raw_payload": deep_dict,
        }

        resp = await async_client.post(
            "/api/v1/events", json=payload, headers=auth_headers(analyst_token)
        )
        assert resp.status_code == 422
        assert "exceeds maximum nesting depth" in str(resp.json())

    async def test_streaming_payload_oversized_without_content_length(
        self, async_client: AsyncClient, test_db_session: AsyncSession
    ) -> None:
        """Verify streaming payloads exceeding MAX_EVENT_PAYLOAD_BYTES are rejected with 413."""
        _, analyst_token = await create_test_user(test_db_session, ROLE_ANALYST, "stream_analyst")

        large_string = "x" * (settings.MAX_EVENT_PAYLOAD_BYTES + 1024)
        large_body = json.dumps(
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "source": "sensor",
                "event_type": "large_test",
                "raw_payload": {"blob": large_string},
            }
        ).encode("utf-8")

        headers = auth_headers(analyst_token)
        headers["Content-Type"] = "application/json"

        async def stream_generator() -> AsyncIterator[bytes]:
            chunk_size = 1024 * 64
            for i in range(0, len(large_body), chunk_size):
                yield large_body[i : i + chunk_size]

        resp = await async_client.post(
            "/api/v1/events",
            content=stream_generator(),
            headers=headers,
        )
        assert resp.status_code == 413
        assert resp.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

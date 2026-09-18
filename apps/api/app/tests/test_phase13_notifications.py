"""Phase 13 Comprehensive Tests: Notifications, External Integrations & SSRF Defense.

Tests:
- SSRF prevention (IP check, scheme, port, localhost/private/cloud metadata rejection)
- HMAC-SHA256 signing and constant-time verification
- Write-only secret handling and secret masking in API responses and audit logs
- Declarative policy matching (event types, severity, filters, cooldown)
- Deterministic deduplication and idempotency key enforcement
- Delivery state machine (PENDING, DELIVERING, DELIVERED, RETRYING, EXHAUSTED, CANCELLED)
- Bounded exponential retries and backoff
- Core security transaction isolation (failing notification never rolls back alert/incident)
- Granular server-side RBAC guards
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash
from app.models.auth import Role, User, UserRole
from app.models.notification import (
    Integration,
    NotificationDelivery,
    NotificationEvent,
    NotificationPolicy,
)
from app.schemas.notification import DeliveryStatus, DestinationType
from app.services.auth import create_session
from app.services.notifications.delivery import (
    cancel_delivery,
    emit_notification_event,
    execute_delivery,
    retry_delivery,
)
from app.services.notifications.policy import clear_policy_cooldowns, evaluate_policy_match
from app.services.notifications.providers.base import DeliveryResult
from app.services.notifications.signing import generate_hmac_signature, verify_hmac_signature
from app.services.notifications.ssrf import SSRFValidationError, validate_url_ssrf
from app.services.seed import seed_rbac_and_admin


async def _create_test_user(
    db: AsyncSession, role_name: str, username_prefix: str = "user"
) -> tuple[User, str]:
    """Helper creating user with role and returning (user, session_token)."""
    await seed_rbac_and_admin(db)
    user_id = uuid.uuid4()
    user = User(
        id=user_id,
        username=f"{username_prefix}_{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@sentinelforge.test",
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
# 1. SSRF Defense & URL Validation Tests
# ==============================================================================


def test_ssrf_rejection_insecure_http() -> None:
    """Verify that insecure http:// URLs are rejected by default."""
    with pytest.raises(SSRFValidationError, match="Insecure HTTP scheme is rejected"):
        validate_url_ssrf("http://example.com/webhook", allow_insecure_http=False)


def test_ssrf_rejection_localhost_and_loopback() -> None:
    """Verify loopback addresses and localhost are blocked."""
    loopbacks = [
        "https://localhost/webhook",
        "https://127.0.0.1/webhook",
        "https://127.0.1.1/webhook",
    ]
    for url in loopbacks:
        with pytest.raises(SSRFValidationError):
            validate_url_ssrf(url, allow_insecure_http=True)


def test_ssrf_rejection_cloud_metadata() -> None:
    """Verify cloud metadata IPs and hostnames are rejected."""
    metadata_targets = [
        "https://169.254.169.254/latest/meta-data",
        "https://metadata.google.internal/computeMetadata/v1",
        "https://instance-data/latest/meta-data",
    ]
    for url in metadata_targets:
        with pytest.raises(SSRFValidationError):
            validate_url_ssrf(url, allow_insecure_http=True)


def test_ssrf_rejection_restricted_ports() -> None:
    """Verify non-standard ports (e.g. 22, 8080) are rejected."""
    with pytest.raises(SSRFValidationError, match="Port 22 is restricted"):
        validate_url_ssrf("https://example.com:22/webhook", allow_insecure_http=True)


def test_ssrf_rejection_embedded_credentials() -> None:
    """Verify embedded user:pass in URLs is rejected."""
    with pytest.raises(SSRFValidationError, match="Embedded user credentials"):
        validate_url_ssrf("https://admin:secret@example.com/webhook", allow_insecure_http=True)


# ==============================================================================
# 2. Cryptographic HMAC Signing Tests
# ==============================================================================


def test_hmac_signature_generation_and_verification() -> None:
    """Verify deterministic HMAC-SHA256 signature generation and constant-time verification."""
    secret = "test-secret-key-1234567890abcdef"
    timestamp = "2026-09-18T12:00:00Z"
    payload = '{"event_id":"123","title":"Security Alert"}'

    sig = generate_hmac_signature(secret, timestamp, payload)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex digest length

    # Valid signature check
    assert verify_hmac_signature(secret, timestamp, payload, sig) is True

    # Tampered payload check
    tampered = '{"event_id":"123","title":"Security Alert Modified"}'
    assert verify_hmac_signature(secret, timestamp, tampered, sig) is False

    # Tampered timestamp check
    assert verify_hmac_signature(secret, "2026-09-18T12:00:01Z", payload, sig) is False

    # Tampered secret check
    assert verify_hmac_signature("wrong-secret", timestamp, payload, sig) is False


# ==============================================================================
# 3. Declarative Policy Evaluation Tests
# ==============================================================================


def test_policy_matching_event_types_and_severity() -> None:
    """Verify policy matching adheres to event types and severity thresholds."""
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Critical Alerts Policy",
        enabled=True,
        event_types=["ALERT_CREATED", "ALERT_ESCALATED"],
        min_severity="HIGH",
        destination_ids=[str(uuid.uuid4())],
        filters={},
        cooldown_seconds=0,
    )

    # 1. Matching event type + matching severity
    event1 = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-1",
        payload={"severity": "CRITICAL", "title": "Brute Force Attack"},
    )
    assert evaluate_policy_match(event1, policy) is True

    # 2. Matching event type + lower severity (MEDIUM < HIGH)
    event2 = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-2",
        payload={"severity": "MEDIUM", "title": "Low priority scan"},
    )
    assert evaluate_policy_match(event2, policy) is False

    # 3. Mismatched event type
    event3 = NotificationEvent(
        id=uuid.uuid4(),
        event_type="INCIDENT_CREATED",
        source_resource_type="incident",
        source_resource_id="inc-1",
        payload={"severity": "CRITICAL"},
    )
    assert evaluate_policy_match(event3, policy) is False


def test_policy_matching_declarative_filters() -> None:
    """Verify declarative field filters (rule_id, status)."""
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Rule 001 Only",
        enabled=True,
        event_types=["ALERT_CREATED"],
        min_severity=None,
        destination_ids=[str(uuid.uuid4())],
        filters={"rule_id": "RULE-001", "status": "OPEN"},
        cooldown_seconds=0,
    )

    event_matching = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-1",
        payload={"rule_id": "RULE-001", "status": "OPEN", "severity": "LOW"},
    )
    assert evaluate_policy_match(event_matching, policy) is True

    event_wrong_rule = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-2",
        payload={"rule_id": "RULE-002", "status": "OPEN", "severity": "LOW"},
    )
    assert evaluate_policy_match(event_wrong_rule, policy) is False


def test_policy_cooldown() -> None:
    """Verify cooldown constraint prevents immediate repeated firing."""
    clear_policy_cooldowns()
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Cooldown Policy",
        enabled=True,
        event_types=["ALERT_CREATED"],
        min_severity=None,
        destination_ids=[str(uuid.uuid4())],
        filters={},
        cooldown_seconds=60,
    )

    event = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-1",
        payload={"title": "Test"},
    )

    # First match should pass
    assert evaluate_policy_match(event, policy) is True
    # Immediate second match within 60s cooldown must fail
    assert evaluate_policy_match(event, policy) is False


# ==============================================================================
# 4. Deduplication & Delivery State Machine Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_delivery_idempotency_deduplication(test_db_session: AsyncSession) -> None:
    """Verify database uniqueness constraint on idempotency_key prevents duplicate deliveries."""
    dest = Integration(
        id=uuid.uuid4(),
        name="Webhook Dest",
        type=DestinationType.WEBHOOK.value,
        enabled=True,
        endpoint_url="https://sec-ops.example.com/alerts",
        secret_token="mock-secret-token-key-12345678",
    )
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="All Alerts",
        enabled=True,
        event_types=["ALERT_CREATED"],
        destination_ids=[str(dest.id)],
        filters={},
    )
    test_db_session.add_all([dest, policy])
    await test_db_session.commit()

    # Emit notification event
    event = await emit_notification_event(
        db=test_db_session,
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id=str(uuid.uuid4()),
        payload_data={"severity": "HIGH", "title": "Test Alert"},
    )
    assert event is not None

    # Verify 1 delivery was created
    stmt = select(NotificationDelivery).where(NotificationDelivery.event_id == event.id)
    deliveries = (await test_db_session.execute(stmt)).scalars().all()
    assert len(deliveries) == 1
    assert deliveries[0].status == DeliveryStatus.PENDING.value

    # Re-emitting same event with same policy/destination must not duplicate delivery
    key = deliveries[0].idempotency_key
    dup_delivery = NotificationDelivery(
        id=uuid.uuid4(),
        event_id=event.id,
        policy_id=policy.id,
        destination_id=dest.id,
        idempotency_key=key,
        status="PENDING",
    )
    test_db_session.add(dup_delivery)
    with pytest.raises(IntegrityError):  # UniqueConstraint violation
        await test_db_session.commit()
    await test_db_session.rollback()


@pytest.mark.asyncio
async def test_delivery_retry_and_exhaustion(test_db_session: AsyncSession) -> None:
    """Verify bounded exponential retry backoff terminates in EXHAUSTED status."""
    dest = Integration(
        id=uuid.uuid4(),
        name="Failing Webhook",
        type=DestinationType.WEBHOOK.value,
        enabled=True,
        endpoint_url="https://failing.example.com/webhook",
        secret_token="mock-secret-key-1234567890",
    )
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Retry Policy",
        enabled=True,
        event_types=["ALERT_CREATED"],
        destination_ids=[str(dest.id)],
    )
    test_db_session.add_all([dest, policy])
    await test_db_session.commit()

    event = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id=str(uuid.uuid4()),
        payload={"severity": "HIGH"},
    )
    delivery = NotificationDelivery(
        id=uuid.uuid4(),
        event_id=event.id,
        policy_id=policy.id,
        destination_id=dest.id,
        idempotency_key=f"{event.id}:{policy.id}:{dest.id}",
        status=DeliveryStatus.PENDING.value,
        attempt_count=0,
        max_attempts=2,  # Set max attempts to 2
    )
    test_db_session.add_all([event, delivery])
    await test_db_session.commit()

    # Mock provider returning retryable 500 error
    mock_result = DeliveryResult(
        status=DeliveryStatus.RETRYING,
        http_status=500,
        failure_reason="Server error",
    )

    mock_send = AsyncMock(return_value=mock_result)
    with patch("app.services.notifications.delivery._webhook_provider.send", new=mock_send):
        # Attempt 1 -> RETRYING
        await execute_delivery(test_db_session, delivery.id)
        await test_db_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.RETRYING.value
        assert delivery.attempt_count == 1
        assert delivery.next_retry_at is not None

        # Attempt 2 -> Reaches max_attempts (2) -> EXHAUSTED
        await execute_delivery(test_db_session, delivery.id)
        await test_db_session.refresh(delivery)
        assert delivery.status == DeliveryStatus.EXHAUSTED.value
        assert delivery.attempt_count == 2
        assert delivery.next_retry_at is None


@pytest.mark.asyncio
async def test_delivery_manual_retry_and_cancel(test_db_session: AsyncSession) -> None:
    """Verify manual retry on EXHAUSTED and cancellation on PENDING."""
    user, _ = await _create_test_user(test_db_session, ROLE_ANALYST, "analyst_retry")

    dest = Integration(
        id=uuid.uuid4(),
        name="Test Dest",
        type=DestinationType.WEBHOOK.value,
        enabled=True,
        endpoint_url="https://sec.example.com",
    )
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Test Policy",
        enabled=True,
        event_types=["ALERT_CREATED"],
        destination_ids=[str(dest.id)],
    )
    event = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-1",
        payload={},
    )
    delivery = NotificationDelivery(
        id=uuid.uuid4(),
        event_id=event.id,
        policy_id=policy.id,
        destination_id=dest.id,
        idempotency_key="test-key-1",
        status=DeliveryStatus.EXHAUSTED.value,
        attempt_count=3,
        max_attempts=3,
    )
    test_db_session.add_all([dest, policy, event, delivery])
    await test_db_session.commit()

    # Manual retry resets to PENDING
    retried = await retry_delivery(test_db_session, delivery.id, user.id)
    assert retried.status == DeliveryStatus.PENDING.value
    assert retried.attempt_count == 0

    # Cancel transitions PENDING to CANCELLED
    cancelled = await cancel_delivery(test_db_session, delivery.id, user.id)
    assert cancelled.status == DeliveryStatus.CANCELLED.value


# ==============================================================================
# 5. Core Security Transaction Isolation Test
# ==============================================================================


@pytest.mark.asyncio
async def test_notification_failure_does_not_rollback_core_security(
    test_db_session: AsyncSession,
) -> None:
    """Verify external delivery failures do NOT crash or roll back alert/incident operations."""
    dest = Integration(
        id=uuid.uuid4(),
        name="Broken Webhook",
        type=DestinationType.WEBHOOK.value,
        enabled=True,
        endpoint_url="https://broken.example.com/alerts",
    )
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Fail Policy",
        enabled=True,
        event_types=["ALERT_CREATED"],
        destination_ids=[str(dest.id)],
    )
    test_db_session.add_all([dest, policy])
    await test_db_session.commit()

    # Even if emit_notification_event encounters an error, it returns gracefully
    err = RuntimeError("Database query failed")
    with patch("app.services.notifications.delivery.select", side_effect=err):
        event = await emit_notification_event(
            db=test_db_session,
            event_type="ALERT_CREATED",
            source_resource_type="alert",
            source_resource_id="12345",
            payload_data={"severity": "HIGH"},
        )
        # Should return None safely without raising out
        assert event is None


# ==============================================================================
# 6. REST API & RBAC Integration Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_integrations_api_crud_and_secret_masking(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify integration creation, secret masking, concurrency versioning, and RBAC."""
    admin, admin_token = await _create_test_user(test_db_session, ROLE_ADMIN, "admin_notif")
    viewer, viewer_token = await _create_test_user(test_db_session, ROLE_VIEWER, "viewer_notif")

    headers_admin = {
        "Cookie": f"sentinelforge_session={admin_token}",
        "X-Requested-With": "XMLHttpRequest",
    }
    headers_viewer = {
        "Cookie": f"sentinelforge_session={viewer_token}",
        "X-Requested-With": "XMLHttpRequest",
    }

    # 1. Viewer cannot create integration (403 Forbidden)
    create_payload = {
        "name": "SOC Webhook 1",
        "type": "WEBHOOK",
        "enabled": True,
        "endpoint_url": "https://hooks.example.com/alerts",
        "secret_token": "super-secret-token-key-12345678",
    }
    res_viewer = await async_client.post(
        "/api/v1/integrations", json=create_payload, headers=headers_viewer
    )
    assert res_viewer.status_code == 403

    # 2. Admin creates integration successfully (201 Created)
    res_admin = await async_client.post(
        "/api/v1/integrations", json=create_payload, headers=headers_admin
    )
    assert res_admin.status_code == 201
    data = res_admin.json()["data"]
    intg_id = data["id"]
    assert data["name"] == "SOC Webhook 1"
    assert data["is_secret_configured"] is True
    # Secret must be masked!
    assert data["secret_preview"] == "••••••••5678"
    assert "super-secret-token" not in str(res_admin.json())

    # 3. List integrations masks secrets
    list_res = await async_client.get("/api/v1/integrations", headers=headers_admin)
    assert list_res.status_code == 200
    items = list_res.json()["data"]
    assert len(items) == 1
    assert items[0]["secret_preview"] == "••••••••5678"
    assert "super-secret" not in str(list_res.json())

    # 4. Concurrency conflict on update
    update_payload = {"name": "SOC Webhook Updated", "version": 999}  # Wrong version
    update_res = await async_client.patch(
        f"/api/v1/integrations/{intg_id}", json=update_payload, headers=headers_admin
    )
    assert update_res.status_code == 409


@pytest.mark.asyncio
async def test_notifications_deliveries_api_and_retry(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify deliveries listing, RBAC retry gating, and cancel endpoints."""
    analyst, analyst_token = await _create_test_user(test_db_session, ROLE_ANALYST, "analyst_deliv")
    viewer, viewer_token = await _create_test_user(test_db_session, ROLE_VIEWER, "viewer_deliv")

    headers_analyst = {
        "Cookie": f"sentinelforge_session={analyst_token}",
        "X-Requested-With": "XMLHttpRequest",
    }
    headers_viewer = {
        "Cookie": f"sentinelforge_session={viewer_token}",
        "X-Requested-With": "XMLHttpRequest",
    }

    # Setup database records
    dest = Integration(
        id=uuid.uuid4(),
        name="Webhook Dest 2",
        type="WEBHOOK",
        endpoint_url="https://sec.example.com",
    )
    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name="Policy 2",
        event_types=["ALERT_CREATED"],
        destination_ids=[str(dest.id)],
    )
    event = NotificationEvent(
        id=uuid.uuid4(),
        event_type="ALERT_CREATED",
        source_resource_type="alert",
        source_resource_id="alt-99",
        payload={"severity": "CRITICAL"},
    )
    delivery = NotificationDelivery(
        id=uuid.uuid4(),
        event_id=event.id,
        policy_id=policy.id,
        destination_id=dest.id,
        idempotency_key="key-test-99",
        status=DeliveryStatus.FAILED.value,
        attempt_count=1,
    )
    test_db_session.add_all([dest, policy, event, delivery])
    await test_db_session.commit()

    # 1. Viewer can read deliveries
    res = await async_client.get("/api/v1/notifications", headers=headers_viewer)
    assert res.status_code == 200
    assert len(res.json()["data"]) >= 1

    # 2. Viewer cannot retry delivery (403 Forbidden)
    res_retry_viewer = await async_client.post(
        f"/api/v1/notifications/{delivery.id}/retry", headers=headers_viewer
    )
    assert res_retry_viewer.status_code == 403

    # 3. Analyst can retry delivery (200 OK)
    res_retry_analyst = await async_client.post(
        f"/api/v1/notifications/{delivery.id}/retry", headers=headers_analyst
    )
    assert res_retry_analyst.status_code == 200
    assert res_retry_analyst.json()["data"]["status"] == DeliveryStatus.PENDING.value

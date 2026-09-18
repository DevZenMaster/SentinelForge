"""Notification Dispatch, Orchestration & State Machine Engine (Phase 13).

Manages:
- Transaction-isolated event emission and policy routing
- Deterministic idempotency and deduplication
- Asynchronous delivery dispatch and state transitions
- Bounded retries with exponential backoff and Retry-After support
- Audit logging of all lifecycle milestones
"""

import asyncio
import logging
import uuid
from datetime import timedelta
from typing import Any

from fastapi import BackgroundTasks
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.base import utc_now
from app.db.session import AsyncSessionLocal
from app.models.notification import (
    Integration,
    NotificationDelivery,
    NotificationEvent,
    NotificationPolicy,
)
from app.schemas.notification import DeliveryStatus, DestinationType
from app.services.auth import record_audit_log
from app.services.notifications.metrics import notification_metrics
from app.services.notifications.policy import evaluate_policy_match
from app.services.notifications.providers.base import (
    DeliveryResult,
    NotificationProvider,
)
from app.services.notifications.providers.email import EmailProvider
from app.services.notifications.providers.webhook import WebhookProvider
from app.services.notifications.templates import format_webhook_payload

logger = logging.getLogger("sentinelforge.notifications.delivery")

_webhook_provider = WebhookProvider()
_email_provider = EmailProvider()

# Track active background delivery tasks for graceful shutdown
_active_background_tasks: set[asyncio.Task[Any]] = set()


def spawn_delivery_task(delivery_id: uuid.UUID) -> asyncio.Task[None]:
    """Launch tracked background delivery task with automatic cleanup."""
    task = asyncio.create_task(dispatch_single_delivery_background(delivery_id))
    _active_background_tasks.add(task)
    task.add_done_callback(_active_background_tasks.discard)
    return task


def calculate_exponential_backoff(attempt: int) -> int:
    """Calculate bounded exponential backoff delay in seconds."""
    base = settings.NOTIFICATION_BASE_BACKOFF_SECONDS
    max_sec = settings.NOTIFICATION_MAX_BACKOFF_SECONDS
    factor = 2 ** max(0, attempt - 1)
    return min(int(base * factor), max_sec)


async def emit_notification_event(
    db: AsyncSession,
    event_type: str,
    source_resource_type: str,
    source_resource_id: str,
    payload_data: dict[str, Any],
    correlation_id: str | None = None,
    background_tasks: BackgroundTasks | None = None,
) -> NotificationEvent | None:
    """Emit an authoritative security operations event and schedule deliveries.

    Guaranteed fail-safe: any failure inside notification routing will be caught
    and logged, and will NOT roll back or disrupt the caller's transaction.
    """
    if not settings.NOTIFICATIONS_ENABLED:
        return None

    try:
        # 1. Instantiate authoritative event
        event = NotificationEvent(
            id=uuid.uuid4(),
            event_type=event_type,
            source_resource_type=source_resource_type,
            source_resource_id=str(source_resource_id),
            payload_version=1,
            correlation_id=correlation_id,
            payload=payload_data,
            created_at=utc_now(),
        )
        db.add(event)
        await db.flush()

        # 2. Query enabled policies
        policy_stmt = select(NotificationPolicy).where(NotificationPolicy.enabled.is_(True))
        policies = (await db.execute(policy_stmt)).scalars().all()

        scheduled_delivery_ids: list[uuid.UUID] = []

        for policy in policies:
            if not evaluate_policy_match(event, policy):
                continue

            for dest_id_str in policy.destination_ids:
                try:
                    dest_id = uuid.UUID(str(dest_id_str))
                except ValueError:
                    continue

                # Verify destination exists and is enabled
                dest_stmt = select(Integration).where(
                    Integration.id == dest_id, Integration.enabled.is_(True)
                )
                destination = (await db.execute(dest_stmt)).scalar_one_or_none()
                if not destination:
                    continue

                # Idempotency key: event_id:policy_id:destination_id
                idempotency_key = f"{event.id}:{policy.id}:{destination.id}"

                delivery = NotificationDelivery(
                    id=uuid.uuid4(),
                    event_id=event.id,
                    policy_id=policy.id,
                    destination_id=destination.id,
                    idempotency_key=idempotency_key,
                    status=DeliveryStatus.PENDING.value,
                    attempt_count=0,
                    max_attempts=settings.NOTIFICATION_MAX_RETRIES + 1,
                    created_at=utc_now(),
                    updated_at=utc_now(),
                )
                try:
                    async with db.begin_nested():
                        db.add(delivery)
                        await db.flush()
                    scheduled_delivery_ids.append(delivery.id)
                    notification_metrics.record_created(1)

                    await record_audit_log(
                        db=db,
                        action="NOTIFICATION_CREATED",
                        actor_user_id=None,
                        resource_type="notification_delivery",
                        resource_id=str(delivery.id),
                        new_value={
                            "event_id": str(event.id),
                            "event_type": event.event_type,
                            "destination_id": str(destination.id),
                            "policy_id": str(policy.id),
                        },
                    )
                except IntegrityError:
                    # Duplicate delivery rejected by idempotency constraint
                    logger.info(
                        "Duplicate delivery suppressed by idempotency constraint",
                        extra={"idempotency_key": idempotency_key},
                    )

        await db.commit()

        # 3. Schedule async delivery jobs
        if scheduled_delivery_ids:
            if background_tasks is not None:
                for d_id in scheduled_delivery_ids:
                    background_tasks.add_task(dispatch_single_delivery_background, d_id)
            else:
                for d_id in scheduled_delivery_ids:
                    spawn_delivery_task(d_id)

        return event

    except Exception as exc:
        logger.error(
            "Failed to route notification event; core security transaction preserved",
            extra={
                "event_type": event_type,
                "source_resource_type": source_resource_type,
                "source_resource_id": str(source_resource_id),
                "error": str(exc),
            },
            exc_info=True,
        )
        return None


async def dispatch_single_delivery_background(delivery_id: uuid.UUID) -> None:
    """Background task wrapper opening an isolated database session."""
    async with AsyncSessionLocal() as db:
        try:
            await execute_delivery(db, delivery_id)
        except Exception as exc:
            logger.error(
                f"Error in background delivery dispatch: {exc}",
                extra={"delivery_id": str(delivery_id)},
                exc_info=True,
            )


async def execute_delivery(
    db: AsyncSession,
    delivery_id: uuid.UUID,
) -> DeliveryResult:
    """Execute a single delivery job through its lifecycle state machine."""
    stmt = (
        select(NotificationDelivery).where(NotificationDelivery.id == delivery_id).with_for_update()
    )
    delivery = (await db.execute(stmt)).scalar_one_or_none()

    if not delivery:
        return DeliveryResult(
            status=DeliveryStatus.FAILED, failure_reason="Delivery job not found."
        )

    # Only process PENDING or RETRYING jobs
    if delivery.status not in (DeliveryStatus.PENDING.value, DeliveryStatus.RETRYING.value):
        logger.info(
            f"Delivery {delivery_id} is in non-executable state '{delivery.status}'",
        )
        return DeliveryResult(
            status=DeliveryStatus(delivery.status),
            http_status=delivery.http_status,
            failure_reason=delivery.failure_reason,
        )

    destination = delivery.destination
    if not destination or not destination.enabled:
        delivery.status = DeliveryStatus.FAILED.value
        delivery.failure_reason = "Destination is disabled or deleted."
        delivery.updated_at = utc_now()
        await db.commit()
        notification_metrics.record_failed()
        return DeliveryResult(
            status=DeliveryStatus.FAILED,
            failure_reason="Destination disabled",
        )

    # Transition to DELIVERING
    now = utc_now()
    if delivery.attempt_count == 0:
        delivery.first_attempted_at = now
    delivery.last_attempted_at = now
    delivery.attempt_count += 1
    delivery.status = DeliveryStatus.DELIVERING.value
    delivery.updated_at = now
    await db.commit()

    await record_audit_log(
        db=db,
        action="NOTIFICATION_DELIVERY_STARTED",
        actor_user_id=None,
        resource_type="notification_delivery",
        resource_id=str(delivery.id),
        new_value={"attempt_count": delivery.attempt_count},
    )

    # Prepare payload & select provider
    event = delivery.event
    provider: NotificationProvider
    dest_config: dict[str, Any]
    payload: dict[str, Any]

    if destination.type == DestinationType.WEBHOOK.value:
        provider = _webhook_provider
        dest_config = {"endpoint_url": destination.endpoint_url, "id": str(destination.id)}
        payload = format_webhook_payload(
            event_id=str(event.id),
            event_type=event.event_type,
            created_at=event.created_at,
            payload_version=event.payload_version,
            source_resource_type=event.source_resource_type,
            source_resource_id=event.source_resource_id,
            payload_data=event.payload,
            correlation_id=event.correlation_id,
        )
    elif destination.type == DestinationType.EMAIL.value:
        provider = _email_provider
        dest_config = {
            "email_recipients": destination.email_recipients or [],
            "id": str(destination.id),
        }
        payload = {
            "event_id": str(event.id),
            "event_type": event.event_type,
            "source_resource_type": event.source_resource_type,
            "source_resource_id": event.source_resource_id,
            "data": event.payload,
        }
    else:
        delivery.status = DeliveryStatus.FAILED.value
        delivery.failure_reason = f"Unsupported destination type: '{destination.type}'"
        await db.commit()
        notification_metrics.record_failed()
        return DeliveryResult(
            status=DeliveryStatus.FAILED, failure_reason="Unsupported destination type"
        )

    # Execute Outbound Send
    result = await provider.send(
        destination_config=dest_config,
        payload=payload,
        secret_token=destination.secret_token,
    )

    # Process Result & State Transitions
    now = utc_now()
    delivery.http_status = result.http_status
    delivery.response_metadata = result.response_metadata
    delivery.updated_at = now
    destination.last_delivery_at = now

    if result.status == DeliveryStatus.DELIVERED:
        delivery.status = DeliveryStatus.DELIVERED.value
        delivery.delivered_at = now
        delivery.failure_reason = None
        destination.last_successful_delivery_at = now
        notification_metrics.record_delivered(result.latency_ms)

        await record_audit_log(
            db=db,
            action="NOTIFICATION_DELIVERED",
            actor_user_id=None,
            resource_type="notification_delivery",
            resource_id=str(delivery.id),
            new_value={
                "http_status": result.http_status,
                "attempt_count": delivery.attempt_count,
            },
        )

    elif result.status == DeliveryStatus.RETRYING:
        destination.last_failed_delivery_at = now
        if delivery.attempt_count < delivery.max_attempts:
            delay_sec = (
                result.retry_after
                if result.retry_after is not None
                else calculate_exponential_backoff(delivery.attempt_count)
            )
            delivery.status = DeliveryStatus.RETRYING.value
            delivery.next_retry_at = now + timedelta(seconds=delay_sec)
            delivery.failure_reason = result.failure_reason
            notification_metrics.record_retried()

            await record_audit_log(
                db=db,
                action="NOTIFICATION_RETRY_SCHEDULED",
                actor_user_id=None,
                resource_type="notification_delivery",
                resource_id=str(delivery.id),
                new_value={
                    "attempt_count": delivery.attempt_count,
                    "next_retry_at": delivery.next_retry_at.isoformat(),
                    "failure_reason": result.failure_reason,
                },
            )
        else:
            # Exceeded max retry attempts
            delivery.status = DeliveryStatus.EXHAUSTED.value
            delivery.next_retry_at = None
            delivery.failure_reason = (
                f"Exceeded max attempts ({delivery.max_attempts}). "
                f"Last error: {result.failure_reason}"
            )
            notification_metrics.record_exhausted()

            await record_audit_log(
                db=db,
                action="NOTIFICATION_EXHAUSTED",
                actor_user_id=None,
                resource_type="notification_delivery",
                resource_id=str(delivery.id),
                new_value={
                    "total_attempts": delivery.attempt_count,
                    "failure_reason": delivery.failure_reason,
                },
            )

    else:  # FAILED
        delivery.status = DeliveryStatus.FAILED.value
        delivery.next_retry_at = None
        delivery.failure_reason = result.failure_reason
        destination.last_failed_delivery_at = now
        notification_metrics.record_failed()

        await record_audit_log(
            db=db,
            action="NOTIFICATION_FAILED",
            actor_user_id=None,
            resource_type="notification_delivery",
            resource_id=str(delivery.id),
            new_value={
                "http_status": result.http_status,
                "failure_reason": result.failure_reason,
            },
        )

    await db.commit()
    return result


async def retry_delivery(
    db: AsyncSession,
    delivery_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    background_tasks: BackgroundTasks | None = None,
) -> NotificationDelivery:
    """Manually re-dispatch a failed or exhausted delivery."""
    stmt = (
        select(NotificationDelivery).where(NotificationDelivery.id == delivery_id).with_for_update()
    )
    delivery = (await db.execute(stmt)).scalar_one_or_none()

    if not delivery:
        raise ValueError(f"Delivery '{delivery_id}' not found.")

    if delivery.status not in (DeliveryStatus.FAILED.value, DeliveryStatus.EXHAUSTED.value):
        raise ValueError(
            f"Cannot retry delivery in status '{delivery.status}'. "
            "Only FAILED or EXHAUSTED deliveries can be retried."
        )

    old_status = delivery.status
    delivery.status = DeliveryStatus.PENDING.value
    delivery.attempt_count = 0
    delivery.next_retry_at = None
    delivery.failure_reason = None
    delivery.updated_at = utc_now()
    await db.commit()

    await record_audit_log(
        db=db,
        action="NOTIFICATION_RETRY_SCHEDULED",
        actor_user_id=actor_user_id,
        resource_type="notification_delivery",
        resource_id=str(delivery.id),
        old_value={"status": old_status},
        new_value={"status": delivery.status, "manual": True},
    )

    if background_tasks is not None:
        background_tasks.add_task(dispatch_single_delivery_background, delivery.id)
    else:
        spawn_delivery_task(delivery.id)

    return delivery


async def cancel_delivery(
    db: AsyncSession,
    delivery_id: uuid.UUID,
    actor_user_id: uuid.UUID,
) -> NotificationDelivery:
    """Cancel a pending or retrying delivery."""
    stmt = (
        select(NotificationDelivery).where(NotificationDelivery.id == delivery_id).with_for_update()
    )
    delivery = (await db.execute(stmt)).scalar_one_or_none()

    if not delivery:
        raise ValueError(f"Delivery '{delivery_id}' not found.")

    if delivery.status not in (DeliveryStatus.PENDING.value, DeliveryStatus.RETRYING.value):
        raise ValueError(
            f"Cannot cancel delivery in status '{delivery.status}'. "
            "Only PENDING or RETRYING deliveries can be cancelled."
        )

    old_status = delivery.status
    delivery.status = DeliveryStatus.CANCELLED.value
    delivery.next_retry_at = None
    delivery.updated_at = utc_now()
    await db.commit()

    await record_audit_log(
        db=db,
        action="NOTIFICATION_CANCELLED",
        actor_user_id=actor_user_id,
        resource_type="notification_delivery",
        resource_id=str(delivery.id),
        old_value={"status": old_status},
        new_value={"status": delivery.status},
    )

    return delivery


async def drain_background_tasks(timeout: float = 10.0) -> None:
    """Gracefully wait for active in-flight notification tasks to complete."""
    if not _active_background_tasks:
        return
    pending = list(_active_background_tasks)
    logger.info(f"Draining {len(pending)} in-flight notification delivery task(s)...")
    try:
        await asyncio.wait_for(
            asyncio.gather(*pending, return_exceptions=True),
            timeout=timeout,
        )
    except TimeoutError:
        logger.warning(
            f"Timeout ({timeout}s) exceeded while draining in-flight notification tasks."
        )


async def reconcile_stale_deliveries(db: AsyncSession | None = None) -> int:
    """Reconcile deliveries left stuck in DELIVERING state after an unexpected process crash.

    If attempt_count < max_attempts: resets status to RETRYING with exponential backoff delay.
    If attempt_count >= max_attempts: transitions status to EXHAUSTED.
    """

    async def _reconcile(session: AsyncSession) -> int:
        stmt = (
            select(NotificationDelivery)
            .where(NotificationDelivery.status == DeliveryStatus.DELIVERING.value)
            .with_for_update()
        )
        stale_deliveries = (await session.execute(stmt)).scalars().all()
        if not stale_deliveries:
            return 0

        now = utc_now()
        reconciled_count = 0
        for d in stale_deliveries:
            if d.attempt_count < d.max_attempts:
                d.status = DeliveryStatus.RETRYING.value
                delay = calculate_exponential_backoff(d.attempt_count)
                d.next_retry_at = now + timedelta(seconds=delay)
                d.failure_reason = "Reconciled after server restart while in DELIVERING state."
            else:
                d.status = DeliveryStatus.EXHAUSTED.value
                d.failure_reason = (
                    "Exceeded maximum delivery attempts; reconciled after server restart."
                )
            d.updated_at = now
            reconciled_count += 1

        await session.commit()
        logger.info(f"Reconciled {reconciled_count} stale DELIVERING notification delivery jobs.")
        return reconciled_count

    if db is not None:
        return await _reconcile(db)

    async with AsyncSessionLocal() as session:
        try:
            return await _reconcile(session)
        except Exception as exc:
            logger.error(f"Failed to reconcile stale deliveries: {exc}", exc_info=True)
            return 0

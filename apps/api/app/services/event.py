"""Security Event Ingestion Service.

Provides:
- Idempotency resolution using external_event_id
- High-performance concurrency race handling via database unique constraints
- Verbatim raw payload preservation
- Append-only audit logging for ingestion telemetry
- Sanitized operational logging without raw payload leakage
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event
from app.schemas.event import EventCreateRequest
from app.services.auth import record_audit_log

logger = logging.getLogger("sentinelforge.events")

# In-process lock coordinating concurrent ingestion workers within an application instance
_ingest_lock = asyncio.Lock()


async def ingest_security_event(
    db: AsyncSession,
    event_in: EventCreateRequest,
    request_id: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    actor_user_id: uuid.UUID | None = None,
) -> tuple[Event, bool]:
    """Process and persist a validated security event with strict idempotency semantics.

    Returns:
        tuple[Event, bool]: (event_record, is_duplicate)
        Where is_duplicate is True if the event was previously ingested with the same
        external_event_id, and False if it was newly created.
    """
    async with _ingest_lock:
        # 1. Pre-check idempotency if external_event_id is supplied
        if event_in.external_event_id:
            stmt = select(Event).where(Event.external_event_id == event_in.external_event_id)
            result = await db.execute(stmt)
            existing_event = result.scalar_one_or_none()

            if existing_event is not None:
                # Audit duplicate replay attempt
                await record_audit_log(
                    db=db,
                    action="EVENT_INGEST_DUPLICATE",
                    actor_user_id=actor_user_id,
                    resource_type="event",
                    resource_id=str(existing_event.id),
                    request_id=request_id,
                    source_ip=client_ip,
                    user_agent=user_agent,
                    new_value={
                        "external_event_id": existing_event.external_event_id,
                        "status": "duplicate",
                    },
                )

                logger.info(
                    f"Duplicate event rejected: external_id={existing_event.external_event_id}",
                    extra={
                        "request_id": request_id,
                        "event_id": str(existing_event.id),
                        "external_event_id": existing_event.external_event_id,
                        "status": "duplicate",
                    },
                )
                return existing_event, True

        # 2. Construct new event entity preserving raw_payload verbatim
        now = datetime.now(UTC)
        event_id = uuid.uuid4()
        severity_val = (
            event_in.severity.value
            if hasattr(event_in.severity, "value")
            else str(event_in.severity)
        )
        source_type_val = (
            event_in.source_type.value
            if hasattr(event_in.source_type, "value")
            else str(event_in.source_type)
        )

        new_event = Event(
            id=event_id,
            external_event_id=event_in.external_event_id,
            timestamp=event_in.timestamp,
            ingested_at=now,
            source=event_in.source,
            source_type=source_type_val,
            source_ip=event_in.source_ip,
            destination_ip=event_in.destination_ip,
            destination_port=event_in.destination_port,
            event_type=event_in.event_type,
            action=event_in.action,
            username=event_in.username,
            severity=severity_val,
            message=event_in.message,
            request_id=request_id,
            raw_payload=event_in.raw_payload,
            metadata_=event_in.metadata,
        )

        db.add(new_event)

        # 3. Commit with database uniqueness race handling
        try:
            await db.commit()
        except IntegrityError as exc:
            await db.rollback()

            # Check if error was due to concurrent insert of the same external_event_id
            if event_in.external_event_id:
                stmt = select(Event).where(Event.external_event_id == event_in.external_event_id)
                race_result = await db.execute(stmt)
                raced_event = race_result.scalar_one_or_none()
                if raced_event is not None:
                    await record_audit_log(
                        db=db,
                        action="EVENT_INGEST_DUPLICATE",
                        actor_user_id=actor_user_id,
                        resource_type="event",
                        resource_id=str(raced_event.id),
                        request_id=request_id,
                        source_ip=client_ip,
                        user_agent=user_agent,
                        new_value={
                            "external_event_id": raced_event.external_event_id,
                            "status": "duplicate_race",
                        },
                    )
                    logger.info(
                        "Duplicate event resolved after concurrency race: "
                        f"external_id={raced_event.external_event_id}",
                        extra={
                            "request_id": request_id,
                            "event_id": str(raced_event.id),
                            "external_event_id": raced_event.external_event_id,
                            "status": "duplicate",
                        },
                    )
                    return raced_event, True
            raise exc

    # 4. Audit log successful ingestion (avoid logging raw_payload into audit logs)
    await record_audit_log(
        db=db,
        action="EVENT_INGEST_SUCCESS",
        actor_user_id=actor_user_id,
        resource_type="event",
        resource_id=str(new_event.id),
        request_id=request_id,
        source_ip=client_ip,
        user_agent=user_agent,
        new_value={
            "external_event_id": new_event.external_event_id,
            "source": new_event.source,
            "source_type": new_event.source_type,
            "event_type": new_event.event_type,
            "severity": new_event.severity,
        },
    )

    logger.info(
        f"Event successfully ingested: id={new_event.id}",
        extra={
            "request_id": request_id,
            "event_id": str(new_event.id),
            "external_event_id": new_event.external_event_id,
            "source": new_event.source,
            "event_type": new_event.event_type,
            "severity": new_event.severity,
            "status": "ingested",
        },
    )

    return new_event, False


async def get_event_by_id(db: AsyncSession, event_id: uuid.UUID) -> Event | None:
    """Fetch an event record by internal UUID."""
    stmt = select(Event).where(Event.id == event_id)
    result = await db.execute(stmt)
    return result.scalar_one_or_none()

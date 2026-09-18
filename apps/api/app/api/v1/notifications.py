"""Notification Deliveries and History API Router (Phase 13).

Provides endpoints for inspecting delivery histories, error diagnostics,
manual retries, and delivery cancellations.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_permission
from app.core.rate_limit import enforce_notification_rate_limit
from app.core.rbac import (
    PERMISSION_NOTIFICATIONS_CANCEL,
    PERMISSION_NOTIFICATIONS_READ,
    PERMISSION_NOTIFICATIONS_RETRY,
)
from app.db.session import get_db
from app.models.auth import User
from app.models.notification import NotificationDelivery, NotificationEvent
from app.schemas.notification import DeliveryStatus, NotificationDeliveryResponse
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.notifications.delivery import cancel_delivery, retry_delivery

router = APIRouter(prefix="/notifications", tags=["Notifications"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def _to_response(d: NotificationDelivery) -> NotificationDeliveryResponse:
    event_type = d.event.event_type if d.event else "UNKNOWN"
    src_type = d.event.source_resource_type if d.event else "unknown"
    src_id = d.event.source_resource_id if d.event else "unknown"
    policy_name = d.policy.name if d.policy else "unknown"
    dest_name = d.destination.name if d.destination else "unknown"
    dest_type = d.destination.type if d.destination else "unknown"

    return NotificationDeliveryResponse(
        id=d.id,
        event_id=d.event_id,
        event_type=event_type,
        source_resource_type=src_type,
        source_resource_id=src_id,
        policy_id=d.policy_id,
        policy_name=policy_name,
        destination_id=d.destination_id,
        destination_name=dest_name,
        destination_type=dest_type,
        idempotency_key=d.idempotency_key,
        status=d.status,
        attempt_count=d.attempt_count,
        max_attempts=d.max_attempts,
        first_attempted_at=d.first_attempted_at,
        last_attempted_at=d.last_attempted_at,
        next_retry_at=d.next_retry_at,
        delivered_at=d.delivered_at,
        http_status=d.http_status,
        failure_reason=d.failure_reason,
        response_metadata=d.response_metadata or {},
        created_at=d.created_at,
        updated_at=d.updated_at,
    )


@router.get("", response_model=APIResponse[list[NotificationDeliveryResponse]])
async def list_deliveries(
    request: Request,
    status: DeliveryStatus | None = None,
    event_type: str | None = None,
    destination_id: uuid.UUID | None = None,
    policy_id: uuid.UUID | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATIONS_READ)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[list[NotificationDeliveryResponse]]:
    """List notification delivery jobs with filtering and deterministic ordering."""
    stmt = select(NotificationDelivery).options(
        selectinload(NotificationDelivery.event),
        selectinload(NotificationDelivery.policy),
        selectinload(NotificationDelivery.destination),
    )

    if status is not None:
        stmt = stmt.where(NotificationDelivery.status == status.value)
    if destination_id is not None:
        stmt = stmt.where(NotificationDelivery.destination_id == destination_id)
    if policy_id is not None:
        stmt = stmt.where(NotificationDelivery.policy_id == policy_id)
    if event_type is not None:
        stmt = stmt.join(NotificationDelivery.event).where(
            NotificationEvent.event_type == event_type
        )

    stmt = (
        stmt.order_by(NotificationDelivery.created_at.desc(), NotificationDelivery.id.desc())
        .offset(skip)
        .limit(limit)
    )

    res = await db.execute(stmt)
    deliveries = res.scalars().all()

    return APIResponse(
        data=[_to_response(d) for d in deliveries],
        meta=_build_metadata(request),
    )


@router.get("/{id}", response_model=APIResponse[NotificationDeliveryResponse])
async def get_delivery(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATIONS_READ)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationDeliveryResponse]:
    """Get details of a specific notification delivery attempt."""
    stmt = (
        select(NotificationDelivery)
        .options(
            selectinload(NotificationDelivery.event),
            selectinload(NotificationDelivery.policy),
            selectinload(NotificationDelivery.destination),
        )
        .where(NotificationDelivery.id == id)
    )
    res = await db.execute(stmt)
    delivery = res.scalar_one_or_none()
    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification delivery '{id}' not found.",
        )

    return APIResponse(data=_to_response(delivery), meta=_build_metadata(request))


@router.post("/{id}/retry", response_model=APIResponse[NotificationDeliveryResponse])
async def retry_notification_delivery(
    id: uuid.UUID,
    request: Request,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATIONS_RETRY)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationDeliveryResponse]:
    """Manually re-dispatch a failed or exhausted delivery."""
    enforce_notification_rate_limit(
        request, action="retry_delivery", user_id=current_user.id, max_requests=20
    )

    try:
        delivery = await retry_delivery(
            db=db,
            delivery_id=id,
            actor_user_id=current_user.id,
            background_tasks=background_tasks,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return APIResponse(data=_to_response(delivery), meta=_build_metadata(request))


@router.post("/{id}/cancel", response_model=APIResponse[NotificationDeliveryResponse])
async def cancel_notification_delivery(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATIONS_CANCEL)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationDeliveryResponse]:
    """Cancel a pending or retrying delivery."""
    try:
        delivery = await cancel_delivery(
            db=db,
            delivery_id=id,
            actor_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return APIResponse(data=_to_response(delivery), meta=_build_metadata(request))

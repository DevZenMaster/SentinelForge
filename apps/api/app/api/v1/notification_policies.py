"""Declarative Notification Policies API Router (Phase 13).

Provides endpoints for configuring event routing rules, severity thresholds,
and destination bindings.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import (
    PERMISSION_NOTIFICATION_POLICIES_CREATE,
    PERMISSION_NOTIFICATION_POLICIES_DISABLE,
    PERMISSION_NOTIFICATION_POLICIES_ENABLE,
    PERMISSION_NOTIFICATION_POLICIES_READ,
    PERMISSION_NOTIFICATION_POLICIES_UPDATE,
)
from app.db.base import utc_now
from app.db.session import get_db
from app.models.auth import User
from app.models.notification import Integration, NotificationPolicy
from app.schemas.notification import (
    NotificationPolicyCreate,
    NotificationPolicyResponse,
    NotificationPolicyUpdate,
)
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.auth import record_audit_log

router = APIRouter(prefix="/notification-policies", tags=["Notification Policies"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def _to_response(policy: NotificationPolicy) -> NotificationPolicyResponse:
    return NotificationPolicyResponse(
        id=policy.id,
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        event_types=policy.event_types,
        min_severity=policy.min_severity,
        destination_ids=policy.destination_ids,
        filters=policy.filters or {},
        cooldown_seconds=policy.cooldown_seconds,
        created_by_user_id=policy.created_by_user_id,
        updated_by_user_id=policy.updated_by_user_id,
        version=policy.version,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.get("", response_model=APIResponse[list[NotificationPolicyResponse]])
async def list_policies(
    request: Request,
    enabled: bool | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATION_POLICIES_READ)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[list[NotificationPolicyResponse]]:
    """List declarative notification policies."""
    stmt = select(NotificationPolicy)
    if enabled is not None:
        stmt = stmt.where(NotificationPolicy.enabled.is_(enabled))

    stmt = stmt.order_by(NotificationPolicy.name.asc()).offset(skip).limit(limit)
    res = await db.execute(stmt)
    policies = res.scalars().all()

    return APIResponse(
        data=[_to_response(p) for p in policies],
        meta=_build_metadata(request),
    )


@router.post(
    "",
    response_model=APIResponse[NotificationPolicyResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_policy(
    request: Request,
    payload: NotificationPolicyCreate,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATION_POLICIES_CREATE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationPolicyResponse]:
    """Create a new declarative notification policy."""
    # Verify destination IDs exist
    dest_uuids = payload.destination_ids
    dest_stmt = select(Integration.id).where(Integration.id.in_(dest_uuids))
    existing_dest_ids = set((await db.execute(dest_stmt)).scalars().all())

    missing = set(dest_uuids) - existing_dest_ids
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destinations not found: {sorted([str(m) for m in missing])}",
        )

    policy = NotificationPolicy(
        id=uuid.uuid4(),
        name=payload.name.strip(),
        description=payload.description.strip() if payload.description else None,
        enabled=payload.enabled,
        event_types=[e.value for e in payload.event_types],
        min_severity=payload.min_severity,
        destination_ids=[str(d) for d in payload.destination_ids],
        filters=payload.filters,
        cooldown_seconds=payload.cooldown_seconds,
        created_by_user_id=current_user.id,
        updated_by_user_id=current_user.id,
        version=1,
    )

    try:
        db.add(policy)
        await db.commit()
        await db.refresh(policy)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Notification policy with name '{payload.name}' already exists.",
        ) from exc

    await record_audit_log(
        db=db,
        action="NOTIFICATION_POLICY_CREATED",
        actor_user_id=current_user.id,
        resource_type="notification_policy",
        resource_id=str(policy.id),
        new_value={
            "name": policy.name,
            "event_types": policy.event_types,
            "min_severity": policy.min_severity,
            "destinations_count": len(policy.destination_ids),
        },
    )

    return APIResponse(data=_to_response(policy), meta=_build_metadata(request))


@router.get("/{id}", response_model=APIResponse[NotificationPolicyResponse])
async def get_policy(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATION_POLICIES_READ)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationPolicyResponse]:
    """Get details of a specific notification policy."""
    stmt = select(NotificationPolicy).where(NotificationPolicy.id == id)
    policy = (await db.execute(stmt)).scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification policy '{id}' not found.",
        )

    return APIResponse(data=_to_response(policy), meta=_build_metadata(request))


@router.patch("/{id}", response_model=APIResponse[NotificationPolicyResponse])
async def update_policy(
    id: uuid.UUID,
    payload: NotificationPolicyUpdate,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATION_POLICIES_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationPolicyResponse]:
    """Update notification policy configuration with concurrency checking."""
    stmt = select(NotificationPolicy).where(NotificationPolicy.id == id).with_for_update()
    policy = (await db.execute(stmt)).scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification policy '{id}' not found.",
        )

    if policy.version != payload.version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Conflict: Policy was modified by another operator. Please reload.",
        )

    old_state = {
        "name": policy.name,
        "enabled": policy.enabled,
        "event_types": policy.event_types,
        "min_severity": policy.min_severity,
    }

    if payload.name is not None:
        policy.name = payload.name.strip()
    if payload.description is not None:
        policy.description = payload.description.strip()
    if payload.enabled is not None:
        policy.enabled = payload.enabled
    if payload.event_types is not None:
        policy.event_types = [e.value for e in payload.event_types]
    if payload.min_severity is not None:
        policy.min_severity = payload.min_severity
    if payload.destination_ids is not None:
        # Validate destinations exist
        dest_uuids = payload.destination_ids
        dest_stmt = select(Integration.id).where(Integration.id.in_(dest_uuids))
        existing_dest_ids = set((await db.execute(dest_stmt)).scalars().all())
        missing = set(dest_uuids) - existing_dest_ids
        if missing:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Destinations not found: {sorted([str(m) for m in missing])}",
            )
        policy.destination_ids = [str(d) for d in payload.destination_ids]
    if payload.filters is not None:
        policy.filters = payload.filters
    if payload.cooldown_seconds is not None:
        policy.cooldown_seconds = payload.cooldown_seconds

    policy.updated_by_user_id = current_user.id
    policy.version += 1
    policy.updated_at = utc_now()

    try:
        await db.commit()
        await db.refresh(policy)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A notification policy with this name already exists.",
        ) from exc

    await record_audit_log(
        db=db,
        action="NOTIFICATION_POLICY_UPDATED",
        actor_user_id=current_user.id,
        resource_type="notification_policy",
        resource_id=str(policy.id),
        old_value=old_state,
        new_value={
            "name": policy.name,
            "enabled": policy.enabled,
            "version": policy.version,
        },
    )

    return APIResponse(data=_to_response(policy), meta=_build_metadata(request))


@router.post("/{id}/enable", response_model=APIResponse[NotificationPolicyResponse])
async def enable_policy(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATION_POLICIES_ENABLE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationPolicyResponse]:
    """Enable a notification policy."""
    stmt = select(NotificationPolicy).where(NotificationPolicy.id == id).with_for_update()
    policy = (await db.execute(stmt)).scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification policy '{id}' not found.",
        )

    policy.enabled = True
    policy.updated_by_user_id = current_user.id
    policy.version += 1
    policy.updated_at = utc_now()
    await db.commit()
    await db.refresh(policy)

    await record_audit_log(
        db=db,
        action="NOTIFICATION_POLICY_ENABLED",
        actor_user_id=current_user.id,
        resource_type="notification_policy",
        resource_id=str(policy.id),
    )

    return APIResponse(data=_to_response(policy), meta=_build_metadata(request))


@router.post("/{id}/disable", response_model=APIResponse[NotificationPolicyResponse])
async def disable_policy(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_NOTIFICATION_POLICIES_DISABLE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationPolicyResponse]:
    """Disable a notification policy."""
    stmt = select(NotificationPolicy).where(NotificationPolicy.id == id).with_for_update()
    policy = (await db.execute(stmt)).scalar_one_or_none()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification policy '{id}' not found.",
        )

    policy.enabled = False
    policy.updated_by_user_id = current_user.id
    policy.version += 1
    policy.updated_at = utc_now()
    await db.commit()
    await db.refresh(policy)

    await record_audit_log(
        db=db,
        action="NOTIFICATION_POLICY_DISABLED",
        actor_user_id=current_user.id,
        resource_type="notification_policy",
        resource_id=str(policy.id),
    )

    return APIResponse(data=_to_response(policy), meta=_build_metadata(request))

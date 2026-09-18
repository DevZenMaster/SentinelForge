"""Audit Logs API Endpoints (Phase 11).

Provides paginated, filterable, read-only inspection of immutable security audit records.
"""

import math
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_permission
from app.core.rbac import PERMISSION_AUDIT_READ
from app.db.session import get_db
from app.models.audit import AuditLog
from app.models.auth import User
from app.schemas.audit import AuditLogListResponse, AuditLogResponse
from app.schemas.response import APIResponse, ResponseMetadata

router = APIRouter(prefix="/audit", tags=["Audit"])


def _build_metadata(
    request: Request,
    page: int | None = None,
    limit: int | None = None,
    total: int | None = None,
) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
        page=page,
        limit=limit,
        total=total,
    )


@router.get(
    "/logs",
    response_model=APIResponse[AuditLogListResponse],
    status_code=status.HTTP_200_OK,
    summary="List Security Audit Logs",
)
async def list_audit_logs(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_AUDIT_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page (max 100)"),
    resource_type: str | None = Query(default=None, description="Filter by resource type"),
    action: str | None = Query(default=None, description="Filter by audit action"),
    resource_id: str | None = Query(default=None, description="Filter by resource ID"),
    actor_user_id: uuid.UUID | None = Query(default=None, description="Filter by actor user ID"),
    start_time: datetime | None = Query(default=None, description="UTC start timestamp boundary"),
    end_time: datetime | None = Query(default=None, description="UTC end timestamp boundary"),
    sort_order: str = Query(
        default="desc", pattern="^(asc|desc)$", description="Sort by timestamp"
    ),
) -> APIResponse[AuditLogListResponse]:
    """Retrieve immutable security audit trail records with bounded pagination.

    Requires `audit.read` permission.
    """
    query = select(AuditLog).options(selectinload(AuditLog.actor))

    if resource_type:
        query = query.where(AuditLog.resource_type == resource_type)
    if action:
        query = query.where(AuditLog.action == action)
    if resource_id:
        query = query.where(AuditLog.resource_id == resource_id)
    if actor_user_id:
        query = query.where(AuditLog.actor_user_id == actor_user_id)
    if start_time:
        query = query.where(AuditLog.timestamp >= start_time)
    if end_time:
        query = query.where(AuditLog.timestamp <= end_time)

    # Total count query
    count_query = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_query)).scalar_one() or 0

    # Sorting & pagination
    order_col = AuditLog.timestamp.desc() if sort_order == "desc" else AuditLog.timestamp.asc()
    offset = (page - 1) * limit
    paginated_query = query.order_by(order_col).offset(offset).limit(limit)

    results = (await db.execute(paginated_query)).scalars().all()

    items = [
        AuditLogResponse(
            id=log.id,
            actor_user_id=log.actor_user_id,
            actor_username=log.actor.username if log.actor else None,
            action=log.action,
            resource_type=log.resource_type,
            resource_id=log.resource_id,
            old_value=log.old_value,
            new_value=log.new_value,
            source_ip=log.source_ip,
            user_agent=log.user_agent,
            request_id=log.request_id,
            timestamp=log.timestamp,
        )
        for log in results
    ]

    total_pages = math.ceil(total / limit) if total > 0 else 1

    payload = AuditLogListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )

    return APIResponse(data=payload, meta=_build_metadata(request, page, limit, total))

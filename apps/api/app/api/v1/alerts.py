"""Alerts API Endpoints for SentinelForge.

Provides:
- GET /api/v1/alerts: Paginated search and filtering of detection alerts
- GET /api/v1/alerts/{alert_id}: Detailed alert view with constituent forensic evidence
"""

import math
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_permission
from app.core.rbac import PERMISSION_ALERTS_READ
from app.db.session import get_db
from app.models import User
from app.models.alert import Alert, AlertEvent
from app.schemas.alert import AlertDetailResponse, AlertListResponse, AlertResponse
from app.schemas.event import EventResponse
from app.schemas.response import APIResponse, ResponseMetadata

router = APIRouter(prefix="/alerts", tags=["Alerts"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def _ensure_timezone(alert: Alert) -> None:
    """Ensure all datetime fields on an Alert instance are timezone-aware UTC."""
    if alert.created_at.tzinfo is None:
        alert.created_at = alert.created_at.replace(tzinfo=UTC)
    if alert.updated_at.tzinfo is None:
        alert.updated_at = alert.updated_at.replace(tzinfo=UTC)
    if alert.first_seen.tzinfo is None:
        alert.first_seen = alert.first_seen.replace(tzinfo=UTC)
    if alert.last_seen.tzinfo is None:
        alert.last_seen = alert.last_seen.replace(tzinfo=UTC)
    if alert.acknowledged_at and alert.acknowledged_at.tzinfo is None:
        alert.acknowledged_at = alert.acknowledged_at.replace(tzinfo=UTC)
    if alert.resolved_at and alert.resolved_at.tzinfo is None:
        alert.resolved_at = alert.resolved_at.replace(tzinfo=UTC)


@router.get(
    "",
    response_model=APIResponse[AlertListResponse],
    status_code=status.HTTP_200_OK,
    summary="List Detection Alerts",
)
async def list_alerts(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
    rule_id: str | None = Query(default=None, description="Filter by detection rule ID"),
    severity: str | None = Query(default=None, description="Filter by alert severity"),
    status_filter: str | None = Query(
        default=None, alias="status", description="Filter by triage status"
    ),
    source_ip: str | None = Query(default=None, description="Filter by source IP"),
    username: str | None = Query(default=None, description="Filter by username"),
) -> APIResponse[AlertListResponse]:
    """Retrieve paginated detection alerts with optional criteria filtering.

    Requires `alerts.read` permission.
    """
    stmt = select(Alert)
    count_stmt = select(func.count(Alert.id))

    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
        count_stmt = count_stmt.where(Alert.rule_id == rule_id)
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())
        count_stmt = count_stmt.where(Alert.severity == severity.upper())
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter.upper())
        count_stmt = count_stmt.where(Alert.status == status_filter.upper())
    if source_ip:
        stmt = stmt.where(Alert.source_ip == source_ip)
        count_stmt = count_stmt.where(Alert.source_ip == source_ip)
    if username:
        stmt = stmt.where(Alert.username == username)
        count_stmt = count_stmt.where(Alert.username == username)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one()

    offset = (page - 1) * limit
    stmt = stmt.order_by(Alert.created_at.desc()).offset(offset).limit(limit)
    res = await db.execute(stmt)
    alerts = res.scalars().all()

    for a in alerts:
        _ensure_timezone(a)

    total_pages = math.ceil(total / limit) if total > 0 else 0

    return APIResponse[AlertListResponse](
        data=AlertListResponse(
            items=[AlertResponse.model_validate(a) for a in alerts],
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
        ),
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/{alert_id}",
    response_model=APIResponse[AlertDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Alert Details with Evidence",
)
async def get_alert_by_id(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertDetailResponse]:
    """Retrieve detailed alert telemetry along with all constituent evidence events.

    Requires `alerts.read` permission.
    """
    stmt = (
        select(Alert)
        .where(Alert.id == alert_id)
        .options(selectinload(Alert.alert_events).selectinload(AlertEvent.event))
    )
    res = await db.execute(stmt)
    alert = res.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )

    _ensure_timezone(alert)

    evidence_event_ids: list[uuid.UUID] = []
    evidence_events: list[EventResponse] = []

    for ae in alert.alert_events:
        evidence_event_ids.append(ae.event_id)
        if ae.event:
            ev = ae.event
            if ev.timestamp.tzinfo is None:
                ev.timestamp = ev.timestamp.replace(tzinfo=UTC)
            if ev.ingested_at.tzinfo is None:
                ev.ingested_at = ev.ingested_at.replace(tzinfo=UTC)
            if ev.normalized_at and ev.normalized_at.tzinfo is None:
                ev.normalized_at = ev.normalized_at.replace(tzinfo=UTC)
            evidence_events.append(EventResponse.model_validate(ev))

    alert_dict = {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_version": alert.rule_version,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "dedup_key": alert.dedup_key,
        "correlation_key": alert.correlation_key,
        "observed_count": alert.observed_count,
        "threshold": alert.threshold,
        "evidence": alert.evidence,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "acknowledged_at": alert.acknowledged_at,
        "resolved_at": alert.resolved_at,
        "resolution_notes": alert.resolution_notes,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "evidence_event_ids": evidence_event_ids,
        "evidence_events": evidence_events,
    }

    return APIResponse[AlertDetailResponse](
        data=AlertDetailResponse.model_validate(alert_dict),
        meta=_build_metadata(request),
        error=None,
    )

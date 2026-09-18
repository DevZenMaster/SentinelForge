"""Alerts and Detection Operations API Endpoints for SentinelForge (Phase 10).

Provides:
- GET /api/v1/alerts: Paginated search, filtering, and allowlisted sorting of alerts
- GET /api/v1/alerts/{alert_id}: Detailed alert view with evidence, notes, and links
- POST /api/v1/alerts/{alert_id}/acknowledge: Explicit alert acknowledgement
- POST /api/v1/alerts/{alert_id}/assign: Analyst assignment / reassignment
- POST /api/v1/alerts/{alert_id}/unassign: Analyst unassignment
- POST /api/v1/alerts/{alert_id}/transition: State machine lifecycle transitions
- PATCH /api/v1/alerts/{alert_id}/status: Backward-compatible lifecycle transition endpoint
- POST /api/v1/alerts/{alert_id}/suppress: Controlled alert suppression with reason
- POST /api/v1/alerts/{alert_id}/resolve: Alert resolution with mandatory documentation
- POST /api/v1/alerts/{alert_id}/close: Alert closure
- POST /api/v1/alerts/{alert_id}/notes: Append-only analyst triage note creation
- GET /api/v1/alerts/{alert_id}/notes: Paginated analyst triage notes listing
- POST /api/v1/alerts/{alert_id}/incidents: Link alert to incident case
- GET /api/v1/alerts/{alert_id}/incidents: List linked incident cases
- GET /api/v1/alerts/{alert_id}/investigations: Retrieve Phase 8 investigation link
- GET /api/v1/alerts/{alert_id}/indicators: Retrieve threat intelligence indicators
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
from app.core.rbac import (
    PERMISSION_ALERTS_ACKNOWLEDGE,
    PERMISSION_ALERTS_ASSIGN,
    PERMISSION_ALERTS_CLOSE,
    PERMISSION_ALERTS_INCIDENTS_READ,
    PERMISSION_ALERTS_INVESTIGATIONS_READ,
    PERMISSION_ALERTS_NOTES_CREATE,
    PERMISSION_ALERTS_NOTES_READ,
    PERMISSION_ALERTS_READ,
    PERMISSION_ALERTS_RESOLVE,
    PERMISSION_ALERTS_SUPPRESS,
    PERMISSION_ALERTS_TRIAGE,
    PERMISSION_ALERTS_UPDATE,
    PERMISSION_INTELLIGENCE_READ,
)
from app.db.session import get_db
from app.models import User
from app.models.alert import Alert, AlertEvent, AlertNote
from app.models.incident import IncidentAlert
from app.schemas.alert import (
    AlertAcknowledgeRequest,
    AlertAssignRequest,
    AlertCloseRequest,
    AlertDetailResponse,
    AlertIncidentLinkRequest,
    AlertIncidentSummary,
    AlertInvestigationLink,
    AlertListResponse,
    AlertNoteCreateRequest,
    AlertNoteListResponse,
    AlertNoteResponse,
    AlertResolveRequest,
    AlertResponse,
    AlertStatusTransitionRequest,
    AlertSuppressRequest,
)
from app.schemas.event import EventResponse
from app.schemas.incident import UserSummaryResponse
from app.schemas.indicator import IndicatorEnrichmentDetail
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.alert import (
    ALLOWED_SORT_FIELDS,
    AlertConflictError,
    AlertNotFoundError,
    AlertValidationError,
    DuplicateAlertAttachmentError,
    IncidentNotFoundError,
    InvalidAlertTransitionError,
    UserNotFoundError,
    _ensure_utc,
    _user_summary,
    acknowledge_alert,
    assign_alert,
    build_alert_investigation_link,
    close_alert,
    create_alert_note,
    format_alert_response,
    link_alert_to_incident,
    list_alert_incidents,
    list_alert_notes,
    resolve_alert,
    suppress_alert,
    transition_alert_status,
)
from app.services.intelligence import TargetNotFoundError, get_alert_indicators

router = APIRouter(prefix="/alerts", tags=["Alerts"])


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


def _client_context(request: Request) -> tuple[str | None, str | None, str | None]:
    request_id = getattr(request.state, "request_id", None)
    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return str(request_id) if request_id else None, source_ip, user_agent


# ==============================================================================
# Search & Query Endpoints
# ==============================================================================


@router.get(
    "",
    response_model=APIResponse[AlertListResponse],
    status_code=status.HTTP_200_OK,
    summary="List Detection Alerts",
)
async def list_alerts_endpoint(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=500, description="Items per page (max 500)"),
    rule_id: str | None = Query(default=None, description="Filter by detection rule ID"),
    rule_version: int | None = Query(
        default=None, ge=1, description="Filter by exact rule version"
    ),
    severity: str | None = Query(
        default=None, description="Filter by severity: INFO, LOW, MEDIUM, HIGH, CRITICAL"
    ),
    status_filter: str | None = Query(
        default=None, alias="status", description="Filter by triage status"
    ),
    source_ip: str | None = Query(default=None, description="Filter by source IP"),
    username: str | None = Query(default=None, description="Filter by username"),
    assignee_id: uuid.UUID | None = Query(
        default=None, description="Filter by assigned analyst user ID"
    ),
    is_acknowledged: bool | None = Query(
        default=None, description="Filter by acknowledgement state"
    ),
    created_after: datetime | None = Query(default=None, description="UTC timestamp lower bound"),
    created_before: datetime | None = Query(default=None, description="UTC timestamp upper bound"),
    sort_by: str = Query(default="created_at", description="Field to sort by (allowlisted)"),
    sort_order: str = Query(
        default="desc", pattern="^(asc|desc|ASC|DESC)$", description="Sort direction"
    ),
) -> APIResponse[AlertListResponse]:
    """Retrieve paginated detection alerts with criteria filtering and allowlisted sorting.

    Requires `alerts.read` permission.
    """
    if sort_by not in ALLOWED_SORT_FIELDS:
        fields = sorted(ALLOWED_SORT_FIELDS.keys())
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid sort field '{sort_by}'. Allowed fields: {fields}",
        )

    stmt = select(Alert).options(
        selectinload(Alert.assignee),
        selectinload(Alert.acknowledged_by),
        selectinload(Alert.resolved_by),
        selectinload(Alert.closed_by),
        selectinload(Alert.suppressed_by),
    )
    count_stmt = select(func.count(Alert.id))

    # Apply filtering
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
        count_stmt = count_stmt.where(Alert.rule_id == rule_id)
    if rule_version is not None:
        stmt = stmt.where(Alert.rule_version == rule_version)
        count_stmt = count_stmt.where(Alert.rule_version == rule_version)
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
    if assignee_id:
        stmt = stmt.where(Alert.assignee_id == assignee_id)
        count_stmt = count_stmt.where(Alert.assignee_id == assignee_id)
    if is_acknowledged is not None:
        if is_acknowledged:
            stmt = stmt.where(Alert.acknowledged_at.is_not(None))
            count_stmt = count_stmt.where(Alert.acknowledged_at.is_not(None))
        else:
            stmt = stmt.where(Alert.acknowledged_at.is_(None))
            count_stmt = count_stmt.where(Alert.acknowledged_at.is_(None))
    if created_after:
        stmt = stmt.where(Alert.created_at >= created_after)
        count_stmt = count_stmt.where(Alert.created_at >= created_after)
    if created_before:
        stmt = stmt.where(Alert.created_at <= created_before)
        count_stmt = count_stmt.where(Alert.created_at <= created_before)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one()

    # Apply sorting and pagination
    sort_column = ALLOWED_SORT_FIELDS[sort_by]
    order_clause = sort_column.desc() if sort_order.lower() == "desc" else sort_column.asc()
    offset = (page - 1) * limit
    stmt = stmt.order_by(order_clause, Alert.id.desc()).offset(offset).limit(limit)

    res = await db.execute(stmt)
    alerts = res.scalars().all()

    items = [format_alert_response(a) for a in alerts]
    total_pages = math.ceil(total / limit) if total > 0 else 0

    return APIResponse[AlertListResponse](
        data=AlertListResponse(
            items=items,
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
        ),
        meta=_build_metadata(request, page=page, limit=limit, total=total),
        error=None,
    )


@router.get(
    "/{alert_id}",
    response_model=APIResponse[AlertDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Alert Details with Evidence, Notes, and Links",
)
async def get_alert_by_id_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertDetailResponse]:
    """Retrieve detailed alert telemetry along with forensic evidence, notes, and links.

    Requires `alerts.read` permission.
    """
    stmt = (
        select(Alert)
        .where(Alert.id == alert_id)
        .options(
            selectinload(Alert.assignee),
            selectinload(Alert.acknowledged_by),
            selectinload(Alert.resolved_by),
            selectinload(Alert.closed_by),
            selectinload(Alert.suppressed_by),
            selectinload(Alert.alert_events).selectinload(AlertEvent.event),
            selectinload(Alert.notes).selectinload(AlertNote.author),
            selectinload(Alert.incident_alerts).selectinload(IncidentAlert.incident),
        )
    )
    res = await db.execute(stmt)
    alert = res.scalar_one_or_none()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )

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

    notes: list[AlertNoteResponse] = [
        AlertNoteResponse(
            id=n.id,
            alert_id=n.alert_id,
            author=_user_summary(n.author)
            or UserSummaryResponse(id=n.author_user_id, username="unknown", email="unknown@local"),
            content=n.content,
            created_at=_ensure_utc(n.created_at) or datetime.now(UTC),
            updated_at=_ensure_utc(n.updated_at) or datetime.now(UTC),
        )
        for n in alert.notes
    ]

    linked_incidents: list[AlertIncidentSummary] = [
        AlertIncidentSummary(
            incident_id=ia.incident.id,
            incident_ticket=ia.incident.incident_id,
            title=ia.incident.title,
            severity=ia.incident.severity,
            status=ia.incident.status,
            linked_at=_ensure_utc(ia.added_at) or datetime.now(UTC),
        )
        for ia in alert.incident_alerts
        if ia.incident
    ]

    investigation_link = build_alert_investigation_link(alert.id)
    base_response = format_alert_response(
        alert=alert,
        linked_incidents_count=len(linked_incidents),
        notes_count=len(notes),
        evidence_count=len(evidence_event_ids),
    )

    detail_data = AlertDetailResponse(
        **base_response.model_dump(),
        evidence_event_ids=evidence_event_ids,
        evidence_events=evidence_events,
        notes=notes,
        linked_incidents=linked_incidents,
        investigation=investigation_link,
    )

    return APIResponse[AlertDetailResponse](
        data=detail_data,
        meta=_build_metadata(request),
        error=None,
    )


# ==============================================================================
# Operational Triage Lifecycle Endpoints
# ==============================================================================


@router.post(
    "/{alert_id}/acknowledge",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Acknowledge Alert",
)
async def acknowledge_alert_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_ACKNOWLEDGE))],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: AlertAcknowledgeRequest | None = None,
) -> APIResponse[AlertResponse]:
    """Acknowledge an alert, advancing status to ACKNOWLEDGED and recording attribution.

    Requires `alerts.acknowledge` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    comment = payload.comment if payload else None
    expected_version = payload.expected_version if payload else None
    try:
        alert = await acknowledge_alert(
            db=db,
            alert_id=alert_id,
            actor_user_id=current_user.id,
            comment=comment,
            expected_version=expected_version,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidAlertTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except AlertConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.post(
    "/{alert_id}/assign",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Assign Alert to Analyst",
)
async def assign_alert_endpoint(
    alert_id: uuid.UUID,
    payload: AlertAssignRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_ASSIGN))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    """Assign or reassign an alert to an analyst with active-account validation.

    Requires `alerts.assign` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        alert = await assign_alert(
            db=db,
            alert_id=alert_id,
            assignee_user_id=payload.assigned_to_user_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except UserNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except AlertValidationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.post(
    "/{alert_id}/unassign",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Unassign Alert",
)
async def unassign_alert_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_ASSIGN))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    """Remove analyst assignment from an alert.

    Requires `alerts.assign` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        alert = await assign_alert(
            db=db,
            alert_id=alert_id,
            assignee_user_id=None,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.post(
    "/{alert_id}/transition",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Transition Alert Lifecycle State",
)
async def transition_alert_endpoint(
    alert_id: uuid.UUID,
    payload: AlertStatusTransitionRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_TRIAGE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    """Transition alert lifecycle state according to strict deterministic state machine.

    Requires `alerts.triage` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        alert = await transition_alert_status(
            db=db,
            alert_id=alert_id,
            target_status=payload.status,
            actor_user_id=current_user.id,
            comment=payload.comment,
            expected_version=payload.expected_version,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidAlertTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except AlertConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.patch(
    "/{alert_id}/status",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Alert Status (Compatibility)",
)
async def patch_alert_status_endpoint(
    alert_id: uuid.UUID,
    payload: AlertStatusTransitionRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    """Compatibility transition endpoint using alerts.update permission."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        alert = await transition_alert_status(
            db=db,
            alert_id=alert_id,
            target_status=payload.status,
            actor_user_id=current_user.id,
            comment=payload.comment,
            expected_version=payload.expected_version,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidAlertTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except AlertConflictError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.post(
    "/{alert_id}/suppress",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Suppress Alert",
)
async def suppress_alert_endpoint(
    alert_id: uuid.UUID,
    payload: AlertSuppressRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_SUPPRESS))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    """Suppress an alert with mandatory justification and optional bounded expiration.

    Requires `alerts.suppress` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        alert = await suppress_alert(
            db=db,
            alert_id=alert_id,
            payload=payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidAlertTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except AlertValidationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.post(
    "/{alert_id}/resolve",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Resolve Alert",
)
async def resolve_alert_endpoint(
    alert_id: uuid.UUID,
    payload: AlertResolveRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_RESOLVE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertResponse]:
    """Resolve an alert with mandatory investigation findings and remediation notes.

    Requires `alerts.resolve` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        alert = await resolve_alert(
            db=db,
            alert_id=alert_id,
            payload=payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidAlertTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
    except AlertValidationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


@router.post(
    "/{alert_id}/close",
    response_model=APIResponse[AlertResponse],
    status_code=status.HTTP_200_OK,
    summary="Close Alert",
)
async def close_alert_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_CLOSE))],
    db: Annotated[AsyncSession, Depends(get_db)],
    payload: AlertCloseRequest | None = None,
) -> APIResponse[AlertResponse]:
    """Close an alert with optional closure notes.

    Requires `alerts.close` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    close_payload = payload or AlertCloseRequest()
    try:
        alert = await close_alert(
            db=db,
            alert_id=alert_id,
            payload=close_payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidAlertTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    return APIResponse(data=format_alert_response(alert), meta=_build_metadata(request))


# ==============================================================================
# Analyst Notes Endpoints
# ==============================================================================


@router.post(
    "/{alert_id}/notes",
    response_model=APIResponse[AlertNoteResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Add Analyst Triage Note",
)
async def create_note_endpoint(
    alert_id: uuid.UUID,
    payload: AlertNoteCreateRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_NOTES_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertNoteResponse]:
    """Append a sanitized analyst triage note to an alert.

    Requires `alerts.notes.create` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        note = await create_alert_note(
            db=db,
            alert_id=alert_id,
            raw_content=payload.content,
            author_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except AlertValidationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    author_summary = _user_summary(note.author) or UserSummaryResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
    )

    note_resp = AlertNoteResponse(
        id=note.id,
        alert_id=note.alert_id,
        author=author_summary,
        content=note.content,
        created_at=_ensure_utc(note.created_at) or datetime.now(UTC),
        updated_at=_ensure_utc(note.updated_at) or datetime.now(UTC),
    )
    return APIResponse(data=note_resp, meta=_build_metadata(request))


@router.get(
    "/{alert_id}/notes",
    response_model=APIResponse[AlertNoteListResponse],
    status_code=status.HTTP_200_OK,
    summary="List Analyst Triage Notes",
)
async def list_notes_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_NOTES_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
) -> APIResponse[AlertNoteListResponse]:
    """List chronological triage notes attached to an alert.

    Requires `alerts.notes.read` permission.
    """
    try:
        notes_res = await list_alert_notes(db=db, alert_id=alert_id, page=page, limit=limit)
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    return APIResponse(
        data=notes_res,
        meta=_build_metadata(request, page=page, limit=limit, total=notes_res.total),
    )


# ==============================================================================
# Incident & Investigation Integration Endpoints
# ==============================================================================


@router.post(
    "/{alert_id}/incidents",
    response_model=APIResponse[AlertIncidentSummary],
    status_code=status.HTTP_201_CREATED,
    summary="Link Alert to Incident Case",
)
async def link_incident_endpoint(
    alert_id: uuid.UUID,
    payload: AlertIncidentLinkRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_TRIAGE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertIncidentSummary]:
    """Correlate and link an alert to an existing incident case.

    Requires `alerts.triage` permission.
    """
    request_id, source_ip, user_agent = _client_context(request)
    try:
        link = await link_alert_to_incident(
            db=db,
            alert_id=alert_id,
            incident_id=payload.incident_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except DuplicateAlertAttachmentError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    # Reload incident details
    inc_stmt = (
        select(IncidentAlert)
        .options(selectinload(IncidentAlert.incident))
        .where(IncidentAlert.id == link.id)
    )
    loaded_link = (await db.execute(inc_stmt)).scalar_one()
    inc = loaded_link.incident

    summary = AlertIncidentSummary(
        incident_id=inc.id,
        incident_ticket=inc.incident_id,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        linked_at=_ensure_utc(loaded_link.added_at) or datetime.now(UTC),
    )
    return APIResponse(data=summary, meta=_build_metadata(request))


@router.get(
    "/{alert_id}/incidents",
    response_model=APIResponse[list[AlertIncidentSummary]],
    status_code=status.HTTP_200_OK,
    summary="List Linked Incident Cases",
)
async def list_alert_incidents_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_INCIDENTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[AlertIncidentSummary]]:
    """Retrieve all incident cases linked to an alert.

    Requires `alerts.incidents.read` permission.
    """
    try:
        incidents = await list_alert_incidents(db=db, alert_id=alert_id)
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    return APIResponse(data=incidents, meta=_build_metadata(request))


@router.get(
    "/{alert_id}/investigations",
    response_model=APIResponse[AlertInvestigationLink],
    status_code=status.HTTP_200_OK,
    summary="Get Investigation Analytics Links",
)
async def get_alert_investigations_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[
        User, Depends(require_permission(PERMISSION_ALERTS_INVESTIGATIONS_READ))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[AlertInvestigationLink]:
    """Retrieve canonical Phase 8 investigation correlation query anchors for an alert.

    Requires `alerts.investigations.read` permission.
    """
    stmt = select(Alert.id).where(Alert.id == alert_id)
    exists = (await db.execute(stmt)).scalar_one_or_none()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID '{alert_id}' not found.",
        )

    link = build_alert_investigation_link(alert_id)
    return APIResponse(data=link, meta=_build_metadata(request))


# ==============================================================================
# Existing Threat Intelligence Indicator Integration (Preserved)
# ==============================================================================


@router.get(
    "/{alert_id}/indicators",
    response_model=APIResponse[list[IndicatorEnrichmentDetail]],
    status_code=status.HTTP_200_OK,
    summary="Get Indicators Associated with Alert",
)
async def get_alert_indicators_endpoint(
    alert_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[IndicatorEnrichmentDetail]]:
    """Retrieve all threat intelligence indicators associated with an alert via evidence events."""
    try:
        indicators = await get_alert_indicators(db=db, alert_id=alert_id)
    except TargetNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err

    return APIResponse[list[IndicatorEnrichmentDetail]](
        data=indicators,
        meta=_build_metadata(request),
        error=None,
    )

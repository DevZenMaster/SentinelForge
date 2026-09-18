"""Incidents and Investigation API Endpoints (Phase 6).

Provides comprehensive case management, lifecycle transitions, analyst assignment,
alert correlation, forensic event evidence attachment, notes management,
and unified chronological investigation timeline endpoints.
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import (
    PERMISSION_INCIDENTS_CLOSE,
    PERMISSION_INCIDENTS_CREATE,
    PERMISSION_INCIDENTS_READ,
    PERMISSION_INCIDENTS_UPDATE,
    PERMISSION_INTELLIGENCE_READ,
)
from app.db.session import get_db
from app.models import User
from app.schemas.incident import (
    IncidentAlertAttachRequest,
    IncidentAlertSummaryResponse,
    IncidentAssignRequest,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentEventAttachRequest,
    IncidentEventSummaryResponse,
    IncidentListResponse,
    IncidentNoteCreateRequest,
    IncidentNoteResponse,
    IncidentPriority,
    IncidentSeverity,
    IncidentStatus,
    IncidentStatusTransitionRequest,
    IncidentTimelineResponse,
    IncidentUpdateRequest,
)
from app.schemas.indicator import IndicatorEnrichmentDetail
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.auth import resolve_user_capabilities
from app.services.incident import (
    AlertNotFoundError,
    DuplicateAttachmentError,
    EventNotFoundError,
    IncidentNotFoundError,
    IncidentValidationError,
    InvalidStatusTransitionError,
    UserNotFoundError,
    _ensure_utc,
    _user_summary,
    assign_incident,
    attach_alert_to_incident,
    attach_event_to_incident,
    build_incident_timeline,
    create_incident,
    create_incident_note,
    detach_alert_from_incident,
    detach_event_from_incident,
    format_incident_detail,
    get_incident_by_identifier,
    list_incidents,
    transition_incident_status,
    update_incident,
)
from app.services.intelligence import TargetNotFoundError, get_incident_indicators

router = APIRouter(prefix="/incidents", tags=["Incidents"])


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
    source_ip = getattr(request.client, "host", None) if request.client else None
    user_agent = request.headers.get("user-agent")
    return request_id, source_ip, user_agent


# ==============================================================================
# 1. Incident CRUD Endpoints
# ==============================================================================


@router.post(
    "",
    response_model=APIResponse[IncidentDetailResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create New Incident Case",
)
async def create_incident_endpoint(
    request: Request,
    payload: IncidentCreateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentDetailResponse]:
    """Create a new incident ticket. Requires incidents.create permission."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await create_incident(
            db=db,
            payload=payload,
            created_by_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except UserNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (AlertNotFoundError, EventNotFoundError) as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except IncidentValidationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    data = format_incident_detail(incident)
    return APIResponse(data=data, meta=_build_metadata(request))


@router.get(
    "",
    response_model=APIResponse[IncidentListResponse],
    status_code=status.HTTP_200_OK,
    summary="List and Filter Incidents",
)
async def list_incidents_endpoint(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=100, description="Items per page"),
    incident_status: IncidentStatus | None = Query(
        default=None, alias="status", description="Filter by status"
    ),
    severity: IncidentSeverity | None = Query(default=None, description="Filter by severity"),
    priority: IncidentPriority | None = Query(default=None, description="Filter by priority"),
    assigned_to_user_id: uuid.UUID | None = Query(
        default=None, description="Filter by assigned analyst"
    ),
    created_by_user_id: uuid.UUID | None = Query(default=None, description="Filter by creator"),
    search: str | None = Query(
        default=None, description="Search across ticket ID, title, and description"
    ),
) -> APIResponse[IncidentListResponse]:
    """Search and filter incident tickets. Requires incidents.read permission."""
    items, total = await list_incidents(
        db=db,
        page=page,
        limit=limit,
        status=incident_status,
        severity=severity,
        priority=priority,
        assigned_to_user_id=assigned_to_user_id,
        created_by_user_id=created_by_user_id,
        search=search,
    )
    return APIResponse(
        data=IncidentListResponse(items=items, total=total, page=page, limit=limit),
        meta=_build_metadata(request, page=page, limit=limit, total=total),
    )


@router.get(
    "/{incident_identifier}",
    response_model=APIResponse[IncidentDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Incident Details",
)
async def get_incident_endpoint(
    request: Request,
    incident_identifier: str,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentDetailResponse]:
    """Retrieve full incident details by UUID or ticket identifier. Requires incidents.read."""
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    data = format_incident_detail(incident)
    return APIResponse(data=data, meta=_build_metadata(request))


@router.patch(
    "/{incident_identifier}",
    response_model=APIResponse[IncidentDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Incident Properties",
)
async def update_incident_endpoint(
    request: Request,
    incident_identifier: str,
    payload: IncidentUpdateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentDetailResponse]:
    """Update title, description, severity, or priority. Requires incidents.update."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        updated = await update_incident(
            db=db,
            incident=incident,
            payload=payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    data = format_incident_detail(updated)
    return APIResponse(data=data, meta=_build_metadata(request))


# ==============================================================================
# 2. Lifecycle State & Assignment Endpoints
# ==============================================================================


@router.post(
    "/{incident_identifier}/status",
    response_model=APIResponse[IncidentDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Transition Incident Lifecycle Status",
)
async def transition_status_endpoint(
    request: Request,
    incident_identifier: str,
    payload: IncidentStatusTransitionRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentDetailResponse]:
    """Transition lifecycle status with state machine validation. Requires incidents.update."""
    request_id, source_ip, user_agent = _client_context(request)

    # Closing an incident requires dedicated incidents.close permission
    if payload.status == IncidentStatus.CLOSED:
        roles, permissions = await resolve_user_capabilities(db, current_user.id)
        if not current_user.is_superuser and PERMISSION_INCIDENTS_CLOSE not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Forbidden: You do not possess the required permission "
                    f"'{PERMISSION_INCIDENTS_CLOSE}' to close an incident."
                ),
            )

    try:
        incident = await get_incident_by_identifier(db, incident_identifier, for_update=True)
        updated = await transition_incident_status(
            db=db,
            incident=incident,
            payload=payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except InvalidStatusTransitionError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    data = format_incident_detail(updated)
    return APIResponse(data=data, meta=_build_metadata(request))


@router.post(
    "/{incident_identifier}/assign",
    response_model=APIResponse[IncidentDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Assign Analyst to Incident",
)
async def assign_incident_endpoint(
    request: Request,
    incident_identifier: str,
    payload: IncidentAssignRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentDetailResponse]:
    """Assign or reassign analyst. Requires incidents.update permission."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        updated = await assign_incident(
            db=db,
            incident=incident,
            assigned_to_user_id=payload.assigned_to_user_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except UserNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    data = format_incident_detail(updated)
    return APIResponse(data=data, meta=_build_metadata(request))


# ==============================================================================
# 3. Alert Grouping Endpoints
# ==============================================================================


@router.post(
    "/{incident_identifier}/alerts",
    response_model=APIResponse[IncidentAlertSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="Attach Alert to Incident",
)
async def attach_alert_endpoint(
    request: Request,
    incident_identifier: str,
    payload: IncidentAlertAttachRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentAlertSummaryResponse]:
    """Correlate and attach an alert to the incident. Requires incidents.update."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        alert_summary = await attach_alert_to_incident(
            db=db,
            incident=incident,
            alert_id=payload.alert_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except DuplicateAttachmentError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    return APIResponse(data=alert_summary, meta=_build_metadata(request))


@router.delete(
    "/{incident_identifier}/alerts/{alert_id}",
    response_model=APIResponse[dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Detach Alert from Incident",
)
async def detach_alert_endpoint(
    request: Request,
    incident_identifier: str,
    alert_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict[str, str]]:
    """Remove an alert from an incident case. Requires incidents.update."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        await detach_alert_from_incident(
            db=db,
            incident=incident,
            alert_id=alert_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except AlertNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    return APIResponse(
        data={"message": f"Alert {alert_id} detached from incident {incident.incident_id}"},
        meta=_build_metadata(request),
    )


# ==============================================================================
# 4. Forensic Event Evidence Endpoints
# ==============================================================================


@router.post(
    "/{incident_identifier}/events",
    response_model=APIResponse[IncidentEventSummaryResponse],
    status_code=status.HTTP_200_OK,
    summary="Attach Security Event Evidence to Incident",
)
async def attach_event_endpoint(
    request: Request,
    incident_identifier: str,
    payload: IncidentEventAttachRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentEventSummaryResponse]:
    """Link a security event as forensic evidence. Raw payload remains immutable."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        event_summary = await attach_event_to_incident(
            db=db,
            incident=incident,
            event_id=payload.event_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except EventNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except DuplicateAttachmentError as err:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(err)) from err

    return APIResponse(data=event_summary, meta=_build_metadata(request))


@router.delete(
    "/{incident_identifier}/events/{event_id}",
    response_model=APIResponse[dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Detach Event Evidence from Incident",
)
async def detach_event_endpoint(
    request: Request,
    incident_identifier: str,
    event_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict[str, str]]:
    """Remove an event evidence association from an incident. Requires incidents.update."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        await detach_event_from_incident(
            db=db,
            incident=incident,
            event_id=event_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except EventNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    msg = f"Event evidence {event_id} detached from incident {incident.incident_id}"
    return APIResponse(
        data={"message": msg},
        meta=_build_metadata(request),
    )


# ==============================================================================
# 5. Investigation Notes Endpoints
# ==============================================================================


@router.post(
    "/{incident_identifier}/notes",
    response_model=APIResponse[IncidentNoteResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Add Investigation Note",
)
async def create_note_endpoint(
    request: Request,
    incident_identifier: str,
    payload: IncidentNoteCreateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IncidentNoteResponse]:
    """Add an investigation note with author derived from session. Requires incidents.update."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
        note = await create_incident_note(
            db=db,
            incident=incident,
            content=payload.content,
            author_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except IncidentValidationError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err

    note_author = _user_summary(note.author)
    if not note_author:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve note author information",
        )

    note_resp = IncidentNoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        author=note_author,
        content=note.content,
        created_at=_ensure_utc(note.created_at),
        updated_at=_ensure_utc(note.updated_at),
    )
    return APIResponse(data=note_resp, meta=_build_metadata(request))


@router.get(
    "/{incident_identifier}/notes",
    response_model=APIResponse[list[IncidentNoteResponse]],
    status_code=status.HTTP_200_OK,
    summary="List Investigation Notes",
)
async def list_notes_endpoint(
    request: Request,
    incident_identifier: str,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[IncidentNoteResponse]]:
    """Retrieve chronological investigation notes for an incident. Requires incidents.read."""
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    data = format_incident_detail(incident).notes
    return APIResponse(data=data, meta=_build_metadata(request))


# ==============================================================================
# 6. Unified Timeline Endpoint
# ==============================================================================


@router.get(
    "/{incident_identifier}/timeline",
    response_model=APIResponse[IncidentTimelineResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Unified Investigation Timeline",
)
async def get_timeline_endpoint(
    request: Request,
    incident_identifier: str,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INCIDENTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500, description="Max timeline entries to return"),
) -> APIResponse[IncidentTimelineResponse]:
    """Retrieve chronological investigation timeline. Requires incidents.read."""
    try:
        incident = await get_incident_by_identifier(db, incident_identifier)
    except IncidentNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err

    entries = await build_incident_timeline(db, incident, limit=limit)
    resp = IncidentTimelineResponse(
        incident_id=incident.incident_id,
        total_entries=len(entries),
        entries=entries,
    )
    return APIResponse(data=resp, meta=_build_metadata(request))


@router.get(
    "/{incident_identifier}/indicators",
    response_model=APIResponse[list[IndicatorEnrichmentDetail]],
    status_code=status.HTTP_200_OK,
    summary="Get Indicators Associated with Incident",
)
async def get_incident_indicators_endpoint(
    incident_identifier: str,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[IndicatorEnrichmentDetail]]:
    """Retrieve indicators linked to an incident across direct and alert evidence."""
    try:
        indicators = await get_incident_indicators(db=db, incident_identifier=incident_identifier)
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

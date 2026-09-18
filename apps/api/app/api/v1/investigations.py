"""Investigation Analytics and Correlation API Endpoints (Phase 8).

Provides:
- GET /api/v1/investigations/context: Unified 360-degree investigation view
- GET /api/v1/investigations/summary: Deterministic aggregate investigation summary metrics
- GET /api/v1/investigations/events: Bounded correlated events
- GET /api/v1/investigations/alerts: Bounded correlated alerts
- GET /api/v1/investigations/incidents: Bounded correlated incidents
- GET /api/v1/investigations/indicators: Bounded correlated indicators with threat intel
- GET /api/v1/investigations/timeline: Deterministic unified multi-entity investigation timeline
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import PERMISSION_INVESTIGATIONS_READ
from app.db.session import get_db
from app.models import User
from app.schemas.investigation import (
    InvestigationAnchor,
    InvestigationAnchorType,
    InvestigationContextResponse,
    InvestigationSummary,
    InvestigationTimelineResponse,
    PaginatedInvestigationAlerts,
    PaginatedInvestigationEvents,
    PaginatedInvestigationIncidents,
    PaginatedInvestigationIndicators,
)
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.investigation import (
    InvestigationTargetNotFoundError,
    InvestigationValidationError,
    get_correlated_alerts,
    get_correlated_events,
    get_correlated_incidents,
    get_correlated_indicators,
    get_investigation_context,
    get_investigation_summary,
    get_investigation_timeline,
    resolve_investigation_anchor,
)

router = APIRouter(prefix="/investigations", tags=["Investigations"])


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
    "/context",
    response_model=APIResponse[InvestigationContextResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Comprehensive Investigation Context",
)
async def get_investigation_context_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[InvestigationContextResponse]:
    """Retrieve an integrated, 360-degree investigation view anchored on an entity."""
    try:
        anchor = InvestigationAnchor(
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        data = await get_investigation_context(db=db, anchor=anchor)
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    return APIResponse[InvestigationContextResponse](
        data=data,
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/summary",
    response_model=APIResponse[InvestigationSummary],
    status_code=status.HTTP_200_OK,
    summary="Get Investigation Aggregate Summary",
)
async def get_investigation_summary_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[InvestigationSummary]:
    """Retrieve factual summary metrics describing correlated investigation evidence."""
    try:
        anchor, resolved_context = await resolve_investigation_anchor(
            db=db,
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        data = await get_investigation_summary(
            db=db, anchor=anchor, resolved_context=resolved_context
        )
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    return APIResponse[InvestigationSummary](
        data=data,
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/events",
    response_model=APIResponse[PaginatedInvestigationEvents],
    status_code=status.HTTP_200_OK,
    summary="Get Correlated Events",
)
async def get_investigation_events_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=500, description="Page size")] = 50,
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[PaginatedInvestigationEvents]:
    """Retrieve bounded, paginated security events correlated with the anchor."""
    try:
        anchor, resolved_context = await resolve_investigation_anchor(
            db=db,
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        items, total = await get_correlated_events(
            db=db,
            anchor=anchor,
            resolved_context=resolved_context,
            page=page,
            limit=limit,
        )
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    payload = PaginatedInvestigationEvents(
        anchor=anchor,
        total=total,
        page=page,
        limit=limit,
        items=items,
    )
    return APIResponse[PaginatedInvestigationEvents](
        data=payload,
        meta=_build_metadata(request, page=page, limit=limit, total=total),
        error=None,
    )


@router.get(
    "/alerts",
    response_model=APIResponse[PaginatedInvestigationAlerts],
    status_code=status.HTTP_200_OK,
    summary="Get Correlated Alerts",
)
async def get_investigation_alerts_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=500, description="Page size")] = 50,
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[PaginatedInvestigationAlerts]:
    """Retrieve bounded, paginated detection alerts correlated with the anchor."""
    try:
        anchor, resolved_context = await resolve_investigation_anchor(
            db=db,
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        items, total = await get_correlated_alerts(
            db=db,
            anchor=anchor,
            resolved_context=resolved_context,
            page=page,
            limit=limit,
        )
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    payload = PaginatedInvestigationAlerts(
        anchor=anchor,
        total=total,
        page=page,
        limit=limit,
        items=items,
    )
    return APIResponse[PaginatedInvestigationAlerts](
        data=payload,
        meta=_build_metadata(request, page=page, limit=limit, total=total),
        error=None,
    )


@router.get(
    "/incidents",
    response_model=APIResponse[PaginatedInvestigationIncidents],
    status_code=status.HTTP_200_OK,
    summary="Get Correlated Incidents",
)
async def get_investigation_incidents_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=500, description="Page size")] = 50,
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[PaginatedInvestigationIncidents]:
    """Retrieve bounded, paginated incident cases correlated with the anchor."""
    try:
        anchor, resolved_context = await resolve_investigation_anchor(
            db=db,
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        items, total = await get_correlated_incidents(
            db=db,
            anchor=anchor,
            resolved_context=resolved_context,
            page=page,
            limit=limit,
        )
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    payload = PaginatedInvestigationIncidents(
        anchor=anchor,
        total=total,
        page=page,
        limit=limit,
        items=items,
    )
    return APIResponse[PaginatedInvestigationIncidents](
        data=payload,
        meta=_build_metadata(request, page=page, limit=limit, total=total),
        error=None,
    )


@router.get(
    "/indicators",
    response_model=APIResponse[PaginatedInvestigationIndicators],
    status_code=status.HTTP_200_OK,
    summary="Get Correlated Indicators",
)
async def get_investigation_indicators_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=500, description="Page size")] = 50,
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[PaginatedInvestigationIndicators]:
    """Retrieve bounded, paginated threat indicators correlated with the anchor."""
    try:
        anchor, resolved_context = await resolve_investigation_anchor(
            db=db,
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        items, total = await get_correlated_indicators(
            db=db,
            anchor=anchor,
            resolved_context=resolved_context,
            page=page,
            limit=limit,
        )
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    payload = PaginatedInvestigationIndicators(
        anchor=anchor,
        total=total,
        page=page,
        limit=limit,
        items=items,
    )
    return APIResponse[PaginatedInvestigationIndicators](
        data=payload,
        meta=_build_metadata(request, page=page, limit=limit, total=total),
        error=None,
    )


@router.get(
    "/timeline",
    response_model=APIResponse[InvestigationTimelineResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Unified Investigation Timeline",
)
async def get_investigation_timeline_endpoint(
    request: Request,
    anchor_type: Annotated[
        InvestigationAnchorType, Query(description="Anchor entity type for investigation")
    ],
    anchor_value: Annotated[
        str, Query(min_length=1, max_length=256, description="Anchor identifier or entity value")
    ],
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INVESTIGATIONS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: Annotated[int, Query(ge=1, description="Page number")] = 1,
    limit: Annotated[int, Query(ge=1, le=500, description="Page size")] = 50,
    start_time: Annotated[
        datetime | None, Query(description="Optional UTC start time boundary")
    ] = None,
    end_time: Annotated[
        datetime | None, Query(description="Optional UTC end time boundary")
    ] = None,
    window_seconds: Annotated[
        int | None, Query(ge=1, le=2592000, description="Optional time window in seconds")
    ] = None,
) -> APIResponse[InvestigationTimelineResponse]:
    """Retrieve a unified, chronologically ordered multi-entity investigation timeline."""
    try:
        anchor, resolved_context = await resolve_investigation_anchor(
            db=db,
            anchor_type=anchor_type,
            anchor_value=anchor_value,
            start_time=start_time,
            end_time=end_time,
            window_seconds=window_seconds,
        )
        data = await get_investigation_timeline(
            db=db,
            anchor=anchor,
            resolved_context=resolved_context,
            page=page,
            limit=limit,
        )
    except InvestigationTargetNotFoundError as err:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(err)) from err
    except (InvestigationValidationError, ValueError) as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(err)
        ) from err

    return APIResponse[InvestigationTimelineResponse](
        data=data,
        meta=_build_metadata(request, page=page, limit=limit, total=data.total_entries),
        error=None,
    )

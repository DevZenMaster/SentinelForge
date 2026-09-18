"""Threat Intelligence and Indicator Management API Endpoints.

Provides:
- GET /api/v1/indicators: Paginated search and filtering of indicators
- POST /api/v1/indicators: Register or create an indicator
- GET /api/v1/indicators/{indicator_id}: Detailed indicator view with intel and events
- PATCH /api/v1/indicators/{indicator_id}: Update indicator lifecycle status or notes
- POST /api/v1/indicators/{indicator_id}/intelligence: Attach threat intelligence record
- PATCH /api/v1/indicators/intelligence/{intel_id}: Update threat intelligence record
- DELETE /api/v1/indicators/intelligence/{intel_id}: Remove threat intelligence record
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import (
    PERMISSION_INTELLIGENCE_CREATE,
    PERMISSION_INTELLIGENCE_DELETE,
    PERMISSION_INTELLIGENCE_READ,
    PERMISSION_INTELLIGENCE_UPDATE,
)
from app.db.session import get_db
from app.models import User
from app.models.indicator import IndicatorStatus, IndicatorType
from app.schemas.indicator import (
    IndicatorCreateRequest,
    IndicatorDetailResponse,
    IndicatorListResponse,
    IndicatorResponse,
    IndicatorUpdateRequest,
    ThreatIntelligenceCreateRequest,
    ThreatIntelligenceResponse,
    ThreatIntelligenceUpdateRequest,
)
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.intelligence import (
    IndicatorNotFoundError,
    ThreatIntelligenceConflictError,
    ThreatIntelligenceNotFoundError,
    add_threat_intelligence,
    create_or_get_indicator,
    delete_threat_intelligence,
    get_indicator_by_id,
    list_indicators,
    update_indicator_status,
    update_threat_intelligence,
)
from app.services.ioc_normalizer import IOCValidationError

router = APIRouter(prefix="/indicators", tags=["Threat Intelligence"])


def _client_context(request: Request) -> tuple[str | None, str | None, str | None]:
    request_id = getattr(request.state, "request_id", None)
    source_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return request_id, source_ip, user_agent


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
    "",
    response_model=APIResponse[IndicatorListResponse],
    status_code=status.HTTP_200_OK,
    summary="List and Filter Threat Indicators",
)
async def list_indicators_endpoint(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    type: IndicatorType | None = Query(default=None, description="Filter by indicator type"),
    status_filter: IndicatorStatus | None = Query(
        default=None, alias="status", description="Filter by lifecycle status"
    ),
    search: str | None = Query(
        default=None, max_length=256, description="Search indicator values and notes"
    ),
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=200, description="Items per page"),
) -> APIResponse[IndicatorListResponse]:
    """Retrieve paginated threat indicators with optional type, status, and search filters."""
    items, total = await list_indicators(
        db=db,
        type=type,
        status=status_filter,
        search=search,
        page=page,
        limit=limit,
    )
    return APIResponse[IndicatorListResponse](
        data=IndicatorListResponse(
            items=items,
            total=total,
            page=page,
            limit=limit,
        ),
        meta=_build_metadata(request, page=page, limit=limit, total=total),
        error=None,
    )


@router.post(
    "",
    response_model=APIResponse[IndicatorResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register Threat Indicator",
)
async def create_indicator_endpoint(
    request: Request,
    payload: IndicatorCreateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IndicatorResponse]:
    """Register or look up an indicator, optionally attaching initial threat intelligence."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        indicator, was_created = await create_or_get_indicator(
            db=db,
            type=payload.type,
            value=payload.value,
            description=payload.description,
            status=payload.status,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IOCValidationError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid indicator format: {err}",
        ) from err

    if payload.threat_intel is not None:
        try:
            await add_threat_intelligence(
                db=db,
                indicator_id=indicator.id,
                payload=payload.threat_intel,
                actor_user_id=current_user.id,
                request_id=request_id,
                source_ip=source_ip,
                user_agent=user_agent,
            )
        except ThreatIntelligenceConflictError as err:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(err),
            ) from err

    # Reload full indicator response
    detail = await get_indicator_by_id(db=db, indicator_id=indicator.id)
    return APIResponse[IndicatorResponse](
        data=detail,
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/{indicator_id}",
    response_model=APIResponse[IndicatorDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Indicator Details",
)
async def get_indicator_endpoint(
    indicator_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IndicatorDetailResponse]:
    """Retrieve detailed threat indicator record with attached intel and linked events."""
    try:
        indicator = await get_indicator_by_id(db=db, indicator_id=indicator_id)
    except IndicatorNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err

    return APIResponse[IndicatorDetailResponse](
        data=indicator,
        meta=_build_metadata(request),
        error=None,
    )


@router.patch(
    "/{indicator_id}",
    response_model=APIResponse[IndicatorResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Indicator Status or Notes",
)
async def update_indicator_endpoint(
    indicator_id: uuid.UUID,
    payload: IndicatorUpdateRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[IndicatorResponse]:
    """Update lifecycle status (e.g. ACTIVE, FALSE_POSITIVE) or description for an indicator."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        updated = await update_indicator_status(
            db=db,
            indicator_id=indicator_id,
            new_status=payload.status,
            new_description=payload.description,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IndicatorNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err

    return APIResponse[IndicatorResponse](
        data=updated,
        meta=_build_metadata(request),
        error=None,
    )


@router.post(
    "/{indicator_id}/intelligence",
    response_model=APIResponse[ThreatIntelligenceResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Attach Threat Intelligence Record",
)
async def add_intelligence_endpoint(
    indicator_id: uuid.UUID,
    payload: ThreatIntelligenceCreateRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ThreatIntelligenceResponse]:
    """Attach source-attributed threat intelligence record to an indicator."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        intel = await add_threat_intelligence(
            db=db,
            indicator_id=indicator_id,
            payload=payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except IndicatorNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err
    except ThreatIntelligenceConflictError as err:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(err),
        ) from err

    return APIResponse[ThreatIntelligenceResponse](
        data=intel,
        meta=_build_metadata(request),
        error=None,
    )


@router.patch(
    "/intelligence/{intel_id}",
    response_model=APIResponse[ThreatIntelligenceResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Threat Intelligence Record",
)
async def update_intelligence_endpoint(
    intel_id: uuid.UUID,
    payload: ThreatIntelligenceUpdateRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[ThreatIntelligenceResponse]:
    """Update existing threat intelligence attribution, severity, confidence, or TTL."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        intel = await update_threat_intelligence(
            db=db,
            intel_id=intel_id,
            payload=payload,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except ThreatIntelligenceNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err

    return APIResponse[ThreatIntelligenceResponse](
        data=intel,
        meta=_build_metadata(request),
        error=None,
    )


@router.delete(
    "/intelligence/{intel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Threat Intelligence Record",
)
async def delete_intelligence_endpoint(
    intel_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_INTELLIGENCE_DELETE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Delete a threat intelligence record. Requires intelligence.delete permission."""
    request_id, source_ip, user_agent = _client_context(request)
    try:
        await delete_threat_intelligence(
            db=db,
            intel_id=intel_id,
            actor_user_id=current_user.id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    except ThreatIntelligenceNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(err),
        ) from err

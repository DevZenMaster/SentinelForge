"""Event Ingestion API Endpoints for SentinelForge.

Provides:
- POST /api/v1/events: Authenticated, rate-limited, idempotent ingestion pipeline
- GET /api/v1/events/{event_id}: Retrieve normalized security event record by UUID
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rate_limit import enforce_event_ingest_rate_limit
from app.core.rbac import (
    PERMISSION_EVENTS_CREATE,
    PERMISSION_EVENTS_NORMALIZE,
    PERMISSION_EVENTS_READ,
)
from app.db.session import get_db
from app.models import User
from app.schemas.event import EventCreateRequest, EventIngestData, EventResponse
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.event import (
    get_event_by_id,
    ingest_security_event,
    reprocess_event_normalization,
)

router = APIRouter(prefix="/events", tags=["Events"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


@router.post(
    "",
    response_model=APIResponse[EventIngestData],
    status_code=status.HTTP_201_CREATED,
    summary="Ingest Security Telemetry Event",
)
async def ingest_event(
    payload: EventCreateRequest,
    request: Request,
    response: Response,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_EVENTS_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
) -> APIResponse[EventIngestData]:
    """Ingest a single security event with strict schema validation and idempotency handling.

    - Authenticated via session cookie or Bearer token (requires `events.create` permission).
    - Rate-limited per client IP and user account.
    - Idempotent: Subsequent submissions with the same `external_event_id` or `Idempotency-Key`
      return 200 OK with `status: "duplicate"` instead of 201 Created.
    - Preserves `raw_payload` verbatim without mutation for evidentiary audit integrity.
    """
    # 1. Enforce event ingestion rate limiting
    enforce_event_ingest_rate_limit(request, current_user.id)

    # 2. Reconcile Idempotency-Key header with payload.external_event_id
    if idempotency_key:
        clean_key = idempotency_key.strip()
        if payload.external_event_id and payload.external_event_id != clean_key:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Mismatched external_event_id in payload and Idempotency-Key header.",
            )
        if not payload.external_event_id:
            payload.external_event_id = clean_key

    # 3. Extract request context
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    # 4. Ingest event via transactional service
    event, is_duplicate = await ingest_security_event(
        db=db,
        event_in=payload,
        request_id=request_id,
        client_ip=client_ip,
        user_agent=user_agent,
        actor_user_id=current_user.id,
    )

    # 5. Set status code: 200 OK for duplicate replay, 201 Created for new event
    if is_duplicate:
        response.status_code = status.HTTP_200_OK
    else:
        response.status_code = status.HTTP_201_CREATED

    ingested_at = event.ingested_at
    if ingested_at.tzinfo is None:
        ingested_at = ingested_at.replace(tzinfo=UTC)

    timestamp = event.timestamp
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    ingest_data = EventIngestData(
        event_id=event.id,
        external_event_id=event.external_event_id,
        status="duplicate" if is_duplicate else "ingested",
        ingested_at=ingested_at,
        timestamp=timestamp,
    )

    return APIResponse[EventIngestData](
        data=ingest_data,
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/{event_id}",
    response_model=APIResponse[EventResponse],
    summary="Retrieve Normalized Security Event by ID",
)
async def get_event(
    event_id: uuid.UUID,
    request: Request,
    _current_user: Annotated[User, Depends(require_permission(PERMISSION_EVENTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EventResponse]:
    """Fetch an ingested security event by its internal UUID."""
    event = await get_event_by_id(db, event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID '{event_id}' not found.",
        )

    if event.ingested_at.tzinfo is None:
        event.ingested_at = event.ingested_at.replace(tzinfo=UTC)
    if event.timestamp.tzinfo is None:
        event.timestamp = event.timestamp.replace(tzinfo=UTC)
    if event.normalized_at and event.normalized_at.tzinfo is None:
        event.normalized_at = event.normalized_at.replace(tzinfo=UTC)

    return APIResponse[EventResponse](
        data=EventResponse.model_validate(event),
        meta=_build_metadata(request),
        error=None,
    )


@router.post(
    "/{event_id}/normalize",
    response_model=APIResponse[EventResponse],
    status_code=status.HTTP_200_OK,
    summary="Reprocess Event Normalization",
)
async def reprocess_event(
    event_id: uuid.UUID,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_EVENTS_NORMALIZE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[EventResponse]:
    """Reprocess normalization for a single security event.

    Re-evaluates the preserved raw_payload against the parser registry,
    updates canonical fields, logs an audit entry, and returns the updated event.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    event = await reprocess_event_normalization(
        db=db,
        event_id=event_id,
        actor_user_id=current_user.id,
        request_id=request_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event with ID '{event_id}' not found.",
        )

    if event.ingested_at.tzinfo is None:
        event.ingested_at = event.ingested_at.replace(tzinfo=UTC)
    if event.timestamp.tzinfo is None:
        event.timestamp = event.timestamp.replace(tzinfo=UTC)
    if event.normalized_at and event.normalized_at.tzinfo is None:
        event.normalized_at = event.normalized_at.replace(tzinfo=UTC)

    return APIResponse[EventResponse](
        data=EventResponse.model_validate(event),
        meta=_build_metadata(request),
        error=None,
    )

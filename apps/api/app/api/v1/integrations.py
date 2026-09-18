"""External Notification Integrations API Router (Phase 13).

Provides endpoints for managing external notification destinations (Webhooks, Email)
with server-authoritative RBAC, secret masking, SSRF validation, and diagnostic testing.
"""

import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rate_limit import enforce_notification_rate_limit
from app.core.rbac import (
    PERMISSION_INTEGRATIONS_CREATE,
    PERMISSION_INTEGRATIONS_DELETE,
    PERMISSION_INTEGRATIONS_DISABLE,
    PERMISSION_INTEGRATIONS_ENABLE,
    PERMISSION_INTEGRATIONS_READ,
    PERMISSION_INTEGRATIONS_UPDATE,
)
from app.db.base import utc_now
from app.db.session import get_db
from app.models.auth import User
from app.models.notification import Integration
from app.schemas.notification import (
    DestinationType,
    IntegrationCreate,
    IntegrationResponse,
    IntegrationUpdate,
    NotificationTestRequest,
    NotificationTestResponse,
    mask_secret,
)
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.auth import record_audit_log
from app.services.notifications.providers.base import NotificationProvider
from app.services.notifications.providers.email import EmailProvider
from app.services.notifications.providers.webhook import WebhookProvider

router = APIRouter(prefix="/integrations", tags=["Integrations"])

_webhook_provider = WebhookProvider()
_email_provider = EmailProvider()


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def _to_response(intg: Integration) -> IntegrationResponse:
    has_secret, secret_prev = mask_secret(intg.secret_token)
    return IntegrationResponse(
        id=intg.id,
        name=intg.name,
        type=intg.type,
        enabled=intg.enabled,
        endpoint_url=intg.endpoint_url,
        email_recipients=intg.email_recipients,
        is_secret_configured=has_secret,
        secret_preview=secret_prev,
        created_by_user_id=intg.created_by_user_id,
        updated_by_user_id=intg.updated_by_user_id,
        last_delivery_at=intg.last_delivery_at,
        last_successful_delivery_at=intg.last_successful_delivery_at,
        last_failed_delivery_at=intg.last_failed_delivery_at,
        version=intg.version,
        created_at=intg.created_at,
        updated_at=intg.updated_at,
    )


@router.get("", response_model=APIResponse[list[IntegrationResponse]])
async def list_integrations(
    request: Request,
    type: DestinationType | None = None,
    enabled: bool | None = None,
    skip: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_READ)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[list[IntegrationResponse]]:
    """List configured external notification destinations."""
    stmt = select(Integration)
    if type is not None:
        stmt = stmt.where(Integration.type == type.value)
    if enabled is not None:
        stmt = stmt.where(Integration.enabled.is_(enabled))

    stmt = stmt.order_by(Integration.name.asc()).offset(skip).limit(limit)
    res = await db.execute(stmt)
    integrations = res.scalars().all()

    return APIResponse(
        data=[_to_response(i) for i in integrations],
        meta=_build_metadata(request),
    )


@router.post(
    "",
    response_model=APIResponse[IntegrationResponse],
    status_code=status.HTTP_201_CREATED,
)
async def create_integration(
    request: Request,
    payload: IntegrationCreate,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_CREATE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[IntegrationResponse]:
    """Register a new external notification destination."""
    enforce_notification_rate_limit(request, action="create_integration", user_id=current_user.id)

    # If secret_token is omitted for webhook, auto-generate a cryptographically random secret
    secret = payload.secret_token
    if payload.type == DestinationType.WEBHOOK and not secret:
        secret = secrets.token_hex(32)

    integration = Integration(
        id=uuid.uuid4(),
        name=payload.name.strip(),
        type=payload.type.value,
        enabled=payload.enabled,
        endpoint_url=payload.endpoint_url.strip() if payload.endpoint_url else None,
        email_recipients=payload.email_recipients,
        secret_token=secret,
        created_by_user_id=current_user.id,
        updated_by_user_id=current_user.id,
        version=1,
    )

    try:
        db.add(integration)
        await db.commit()
        await db.refresh(integration)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Integration destination with name '{payload.name}' already exists.",
        ) from exc

    await record_audit_log(
        db=db,
        action="INTEGRATION_CREATED",
        actor_user_id=current_user.id,
        resource_type="integration",
        resource_id=str(integration.id),
        new_value={
            "name": integration.name,
            "type": integration.type,
            "enabled": integration.enabled,
            "endpoint_url": integration.endpoint_url,
        },
    )

    return APIResponse(data=_to_response(integration), meta=_build_metadata(request))


@router.get("/{id}", response_model=APIResponse[IntegrationResponse])
async def get_integration(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_READ)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[IntegrationResponse]:
    """Get details of a specific integration destination with secrets masked."""
    stmt = select(Integration).where(Integration.id == id)
    res = await db.execute(stmt)
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{id}' not found.",
        )

    return APIResponse(data=_to_response(integration), meta=_build_metadata(request))


@router.patch("/{id}", response_model=APIResponse[IntegrationResponse])
async def update_integration(
    id: uuid.UUID,
    payload: IntegrationUpdate,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[IntegrationResponse]:
    """Update destination configuration with optimistic concurrency checking."""
    stmt = select(Integration).where(Integration.id == id).with_for_update()
    res = await db.execute(stmt)
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{id}' not found.",
        )

    if integration.version != payload.version:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Conflict: Destination was modified by another operator. Please reload.",
        )

    old_state = {
        "name": integration.name,
        "enabled": integration.enabled,
        "endpoint_url": integration.endpoint_url,
    }

    if payload.name is not None:
        integration.name = payload.name.strip()
    if payload.endpoint_url is not None:
        integration.endpoint_url = payload.endpoint_url.strip()
    if payload.email_recipients is not None:
        integration.email_recipients = payload.email_recipients
    if payload.secret_token is not None:
        integration.secret_token = payload.secret_token
    if payload.enabled is not None:
        integration.enabled = payload.enabled

    integration.updated_by_user_id = current_user.id
    integration.version += 1
    integration.updated_at = utc_now()

    try:
        await db.commit()
        await db.refresh(integration)
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An integration with this name already exists.",
        ) from exc

    await record_audit_log(
        db=db,
        action="INTEGRATION_UPDATED",
        actor_user_id=current_user.id,
        resource_type="integration",
        resource_id=str(integration.id),
        old_value=old_state,
        new_value={
            "name": integration.name,
            "enabled": integration.enabled,
            "endpoint_url": integration.endpoint_url,
            "version": integration.version,
        },
    )

    return APIResponse(data=_to_response(integration), meta=_build_metadata(request))


@router.post("/{id}/enable", response_model=APIResponse[IntegrationResponse])
async def enable_integration(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_ENABLE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[IntegrationResponse]:
    """Enable an external destination."""
    stmt = select(Integration).where(Integration.id == id).with_for_update()
    integration = (await db.execute(stmt)).scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{id}' not found.",
        )

    integration.enabled = True
    integration.updated_by_user_id = current_user.id
    integration.version += 1
    integration.updated_at = utc_now()
    await db.commit()
    await db.refresh(integration)

    await record_audit_log(
        db=db,
        action="INTEGRATION_ENABLED",
        actor_user_id=current_user.id,
        resource_type="integration",
        resource_id=str(integration.id),
    )

    return APIResponse(data=_to_response(integration), meta=_build_metadata(request))


@router.post("/{id}/disable", response_model=APIResponse[IntegrationResponse])
async def disable_integration(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_DISABLE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[IntegrationResponse]:
    """Disable an external destination."""
    stmt = select(Integration).where(Integration.id == id).with_for_update()
    integration = (await db.execute(stmt)).scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{id}' not found.",
        )

    integration.enabled = False
    integration.updated_by_user_id = current_user.id
    integration.version += 1
    integration.updated_at = utc_now()
    await db.commit()
    await db.refresh(integration)

    await record_audit_log(
        db=db,
        action="INTEGRATION_DISABLED",
        actor_user_id=current_user.id,
        resource_type="integration",
        resource_id=str(integration.id),
    )

    return APIResponse(data=_to_response(integration), meta=_build_metadata(request))


@router.delete("/{id}", response_model=APIResponse[dict[str, str]])
async def delete_integration(
    id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_DELETE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[dict[str, str]]:
    """Delete an integration destination."""
    stmt = select(Integration).where(Integration.id == id)
    integration = (await db.execute(stmt)).scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{id}' not found.",
        )

    name = integration.name
    await db.delete(integration)
    await db.commit()

    await record_audit_log(
        db=db,
        action="INTEGRATION_DELETED",
        actor_user_id=current_user.id,
        resource_type="integration",
        resource_id=str(id),
        old_value={"name": name},
    )

    return APIResponse(
        data={"message": f"Integration '{name}' successfully deleted."},
        meta=_build_metadata(request),
    )


@router.post("/{id}/test", response_model=APIResponse[NotificationTestResponse])
async def test_integration(
    id: uuid.UUID,
    request: Request,
    test_req: NotificationTestRequest | None = None,
    current_user: User = Depends(require_permission(PERMISSION_INTEGRATIONS_UPDATE)),
    db: AsyncSession = Depends(get_db),
) -> APIResponse[NotificationTestResponse]:
    """Test external destination connectivity with a synthetic test probe."""
    enforce_notification_rate_limit(
        request, action="test_integration", user_id=current_user.id, max_requests=10
    )

    stmt = select(Integration).where(Integration.id == id)
    integration = (await db.execute(stmt)).scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration '{id}' not found.",
        )

    dest_config = {
        "id": str(integration.id),
        "endpoint_url": integration.endpoint_url,
        "email_recipients": integration.email_recipients,
    }

    custom_msg = test_req.custom_message if test_req else None

    provider: NotificationProvider
    if integration.type == DestinationType.WEBHOOK.value:
        provider = _webhook_provider
    elif integration.type == DestinationType.EMAIL.value:
        provider = _email_provider
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported integration type: '{integration.type}'",
        )

    result = await provider.test_connection(
        destination_config=dest_config,
        secret_token=integration.secret_token,
        custom_message=custom_msg,
    )

    status_str = "SUCCESS" if result.status.value == "DELIVERED" else "FAILED"
    message = (
        "Connectivity test succeeded."
        if status_str == "SUCCESS"
        else f"Connectivity test failed: {result.failure_reason}"
    )

    await record_audit_log(
        db=db,
        action="INTEGRATION_TEST_DISPATCHED",
        actor_user_id=current_user.id,
        resource_type="integration",
        resource_id=str(integration.id),
        new_value={
            "status": status_str,
            "http_status": result.http_status,
            "latency_ms": result.latency_ms,
        },
    )

    resp_data = NotificationTestResponse(
        destination_id=integration.id,
        destination_name=integration.name,
        destination_type=integration.type,
        status=status_str,
        http_status=result.http_status,
        message=message,
        latency_ms=result.latency_ms,
    )

    return APIResponse(data=resp_data, meta=_build_metadata(request))

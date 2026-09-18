"""Health check endpoint handlers.

Provides liveness and readiness health probes without leaking internal credentials,
stack traces, or sensitive infrastructure paths.
"""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Request, Response, status

from app.api.deps import require_permission
from app.core.config import settings
from app.core.metrics import system_metrics
from app.db.session import check_database_readiness, get_pool_status
from app.models.auth import User
from app.schemas.health import ServiceHealth
from app.schemas.response import APIResponse, ResponseMetadata

router = APIRouter(tags=["Health"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


@router.get(
    "/health",
    response_model=APIResponse[ServiceHealth],
    summary="Application Health Status",
)
async def health(request: Request) -> APIResponse[ServiceHealth]:
    """Provide overall application health and readiness summary."""
    db_ready = await check_database_readiness()
    overall_status = "healthy" if db_ready else "degraded"
    db_status = "ready" if db_ready else "unreachable"

    return APIResponse[ServiceHealth](
        data=ServiceHealth(
            status=overall_status,
            version=settings.APP_VERSION,
            environment=settings.ENVIRONMENT,
            database=db_status,
        ),
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/health/live",
    response_model=APIResponse[dict[str, str]],
    summary="Liveness Probe",
)
async def liveness_probe(request: Request) -> APIResponse[dict[str, str]]:
    """Determine whether the application server process is running and accepting requests."""
    return APIResponse[dict[str, str]](
        data={"status": "live"},
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/health/ready",
    response_model=APIResponse[dict[str, str]],
    summary="Readiness Probe",
)
async def readiness_probe(request: Request, response: Response) -> APIResponse[dict[str, str]]:
    """Determine whether the database dependency is reachable to serve production traffic."""
    db_ready = await check_database_readiness()
    if not db_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return APIResponse[dict[str, str]](
            data={"status": "not_ready", "database": "unreachable"},
            meta=_build_metadata(request),
            error=None,
        )

    return APIResponse[dict[str, str]](
        data={"status": "ready", "database": "connected"},
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/metrics",
    response_model=APIResponse[dict[str, Any]],
    summary="Operational Telemetry Metrics",
)
async def get_metrics(
    request: Request,
    _current_user: User = Depends(require_permission("audit.read")),
) -> APIResponse[dict[str, Any]]:
    """Expose controlled operational metrics to authorized SOC auditors/administrators.

    Strictly protects against high cardinality and credential/payload leakage.
    """
    snapshot = system_metrics.get_snapshot()
    snapshot["database_pool"] = get_pool_status()
    snapshot["environment"] = settings.ENVIRONMENT
    snapshot["version"] = settings.APP_VERSION

    return APIResponse[dict[str, Any]](
        data=snapshot,
        meta=_build_metadata(request),
        error=None,
    )

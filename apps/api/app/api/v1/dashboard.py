"""SOC Security Dashboard Telemetry API Endpoints (Phase 11).

Provides deterministic aggregate metrics, alert counters, and operational health
derived directly from authoritative persisted database state.
"""

from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.deps import require_permission
from app.core.rbac import PERMISSION_ALERTS_READ
from app.db.session import get_db
from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.detection import DetectionRule
from app.models.incident import Incident
from app.models.indicator import Indicator
from app.schemas.alert import AlertStatus
from app.schemas.dashboard import SOCDashboardMetricsResponse
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.alert import format_alert_response

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


@router.get(
    "/metrics",
    response_model=APIResponse[SOCDashboardMetricsResponse],
    status_code=status.HTTP_200_OK,
    summary="Get SOC Operational Dashboard Metrics",
)
async def get_dashboard_metrics(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_ALERTS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[SOCDashboardMetricsResponse]:
    """Retrieve aggregate security operations metrics computed from authoritative data.

    Requires `alerts.read` permission.
    """
    now = datetime.now(UTC)
    active_statuses = [AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.IN_PROGRESS]
    sla_threshold = now - timedelta(hours=24)

    # 1. Alert Aggregates
    open_alerts = (
        await db.execute(select(func.count(Alert.id)).where(Alert.status.in_(active_statuses)))
    ).scalar_one() or 0

    critical_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_(active_statuses),
                Alert.severity == "CRITICAL",
            )
        )
    ).scalar_one() or 0

    high_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_(active_statuses),
                Alert.severity == "HIGH",
            )
        )
    ).scalar_one() or 0

    unack_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status == AlertStatus.OPEN,
                Alert.acknowledged_at.is_(None),
            )
        )
    ).scalar_one() or 0

    unassigned_alerts = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_(active_statuses),
                Alert.assignee_id.is_(None),
            )
        )
    ).scalar_one() or 0

    sla_breached = (
        await db.execute(
            select(func.count(Alert.id)).where(
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED]),
                Alert.severity.in_(["CRITICAL", "HIGH"]),
                Alert.created_at < sla_threshold,
            )
        )
    ).scalar_one() or 0

    # 2. Incident Aggregates
    open_incidents = (
        await db.execute(
            select(func.count(Incident.id)).where(Incident.status.in_(["OPEN", "IN_PROGRESS"]))
        )
    ).scalar_one() or 0

    # 3. Detection Rule Aggregates
    active_rules = (
        await db.execute(
            select(func.count(DetectionRule.id)).where(
                DetectionRule.status == "ACTIVE",
                DetectionRule.enabled.is_(True),
            )
        )
    ).scalar_one() or 0

    # 4. Threat Intel Aggregates
    total_indicators = (await db.execute(select(func.count(Indicator.id)))).scalar_one() or 0

    # 5. Bounded Recent High-Priority Alerts (5 items)
    recent_alerts_stmt = (
        select(Alert)
        .options(
            selectinload(Alert.assignee),
            selectinload(Alert.acknowledged_by),
            selectinload(Alert.resolved_by),
            selectinload(Alert.closed_by),
            selectinload(Alert.suppressed_by),
        )
        .where(Alert.status.in_(active_statuses))
        .order_by(Alert.last_seen.desc())
        .limit(5)
    )
    recent_alert_rows = (await db.execute(recent_alerts_stmt)).scalars().all()
    recent_alerts = [format_alert_response(a) for a in recent_alert_rows]

    # 6. Bounded Recent Operational Audit Activity (10 items)
    audit_stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10)
    audit_rows = (await db.execute(audit_stmt)).scalars().all()
    recent_activity: list[dict[str, Any]] = [
        {
            "id": str(log.id),
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "actor_user_id": str(log.actor_user_id) if log.actor_user_id else None,
            "timestamp": log.timestamp.isoformat(),
            "request_id": log.request_id,
        }
        for log in audit_rows
    ]

    metrics = SOCDashboardMetricsResponse(
        open_alerts_count=open_alerts,
        critical_alerts_count=critical_alerts,
        high_alerts_count=high_alerts,
        unacknowledged_alerts_count=unack_alerts,
        unassigned_alerts_count=unassigned_alerts,
        sla_breached_alerts_count=sla_breached,
        open_incidents_count=open_incidents,
        active_rules_count=active_rules,
        total_indicators_count=total_indicators,
        recent_alerts=recent_alerts,
        recent_activity=recent_activity,
    )

    return APIResponse(data=metrics, meta=_build_metadata(request))

"""Security Audit Log Aggregate Reporting Service."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.schemas.reports import ReportingTimeRange, SecurityAuditReport


async def get_security_audit_report(
    db: AsyncSession, time_range: ReportingTimeRange
) -> SecurityAuditReport:
    """Aggregate immutable audit logging metrics and authentication telemetry."""
    # 1. Action distribution
    action_stmt = (
        select(AuditLog.action, func.count(AuditLog.id))
        .where(
            AuditLog.timestamp >= time_range.start_time,
            AuditLog.timestamp <= time_range.end_time,
        )
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc())
    )
    action_rows = (await db.execute(action_stmt)).all()
    action_distribution = {row[0]: row[1] for row in action_rows}

    # 2. Resource type breakdown
    res_stmt = (
        select(AuditLog.resource_type, func.count(AuditLog.id))
        .where(
            AuditLog.timestamp >= time_range.start_time,
            AuditLog.timestamp <= time_range.end_time,
        )
        .group_by(AuditLog.resource_type)
        .order_by(func.count(AuditLog.id).desc())
    )
    res_rows = (await db.execute(res_stmt)).all()
    resource_type_breakdown = {row[0]: row[1] for row in res_rows}

    # 3. Authentication telemetry
    login_success = action_distribution.get("LOGIN_SUCCESS", 0)
    login_failure = action_distribution.get("LOGIN_FAILURE", 0)
    total_events = sum(action_distribution.values())

    return SecurityAuditReport(
        time_range=time_range,
        total_audit_events=total_events,
        action_distribution=action_distribution,
        resource_type_breakdown=resource_type_breakdown,
        login_success_count=login_success,
        login_failure_count=login_failure,
        generated_at=datetime.now(UTC),
    )

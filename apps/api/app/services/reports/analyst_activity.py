"""Analyst Operations and Recorded Activity Reporting Service."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.auth import User
from app.schemas.reports import (
    AnalystActivityItem,
    AnalystActivityReport,
    ReportingTimeRange,
)


async def get_analyst_activity_report(
    db: AsyncSession, time_range: ReportingTimeRange
) -> AnalystActivityReport:
    """Compile auditable log of recorded analyst operations within the window.

    Explicitly non-evaluative: captures system actions for capacity and audit
    purposes only; strictly disclaims productivity scoring.
    """
    stmt = (
        select(
            AuditLog.actor_user_id,
            User.username,
            func.count().filter(AuditLog.action == "ALERT_ACKNOWLEDGED").label("ack_count"),
            func.count().filter(AuditLog.action == "ALERT_ASSIGNED").label("assign_count"),
            func.count().filter(AuditLog.action == "ALERT_RESOLVED").label("resolve_count"),
            func.count().filter(AuditLog.action == "ALERT_NOTE_CREATED").label("notes_count"),
            func.count().filter(AuditLog.action.like("INCIDENT_%")).label("incident_count"),
            func.count(AuditLog.id).label("total_actions"),
        )
        .join(User, AuditLog.actor_user_id == User.id)
        .where(
            AuditLog.timestamp >= time_range.start_time,
            AuditLog.timestamp <= time_range.end_time,
            AuditLog.actor_user_id.is_not(None),
        )
        .group_by(AuditLog.actor_user_id, User.username)
        .order_by(func.count(AuditLog.id).desc())
    )
    rows = (await db.execute(stmt)).all()

    items: list[AnalystActivityItem] = [
        AnalystActivityItem(
            user_id=str(row.actor_user_id),
            username=row.username,
            alerts_acknowledged=row.ack_count,
            alerts_assigned=row.assign_count,
            alerts_resolved=row.resolve_count,
            triage_notes_created=row.notes_count,
            incidents_updated=row.incident_count,
            total_recorded_actions=row.total_actions,
        )
        for row in rows
    ]

    return AnalystActivityReport(
        time_range=time_range,
        disclaimer=(
            "Recorded operational activity metrics only. "
            "Not intended for individual productivity scoring, competence evaluation, "
            "or automated performance ranking."
        ),
        analysts=items,
        generated_at=datetime.now(UTC),
    )

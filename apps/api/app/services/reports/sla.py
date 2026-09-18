"""SLA Performance Reporting Service with Authoritative Population Denominators."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alert import Alert
from app.schemas.reports import ReportingTimeRange, SLABreachItem, SLAReport

SLA_THRESHOLD_SECONDS = 86400  # 24 hours


async def get_sla_report(db: AsyncSession, time_range: ReportingTimeRange) -> SLAReport:
    """Calculate SLA breach metrics for Critical and High severity alerts.

    Adheres strictly to the authoritative Phase 10 definition:
    Only CRITICAL and HIGH severity alerts are evaluated against the 24-hour triage SLA.
    The denominator (applicable_alerts) is explicitly exposed to avoid statistical distortion.
    """
    stmt = (
        select(Alert)
        .options(selectinload(Alert.assignee))
        .where(
            Alert.created_at >= time_range.start_time,
            Alert.created_at <= time_range.end_time,
            Alert.severity.in_(["CRITICAL", "HIGH"]),
        )
        .order_by(Alert.created_at.desc())
    )
    alerts = (await db.execute(stmt)).scalars().all()
    applicable_alerts = len(alerts)

    now = datetime.now(UTC)
    breached_items: list[SLABreachItem] = []
    severity_distribution: dict[str, int] = {"CRITICAL": 0, "HIGH": 0}

    for alert in alerts:
        created_at = (
            alert.created_at
            if alert.created_at.tzinfo is not None
            else alert.created_at.replace(tzinfo=UTC)
        )
        ack_at = (
            alert.acknowledged_at
            if (alert.acknowledged_at is None or alert.acknowledged_at.tzinfo is not None)
            else alert.acknowledged_at.replace(tzinfo=UTC)
        )

        # Calculate triage delay
        if ack_at is not None:
            delay = (ack_at - created_at).total_seconds()
        else:
            delay = (now - created_at).total_seconds()

        if delay > SLA_THRESHOLD_SECONDS:
            sev = alert.severity.upper() if alert.severity else "HIGH"
            severity_distribution[sev] = severity_distribution.get(sev, 0) + 1

            assigned_user = alert.assignee.username if alert.assignee else None
            breached_items.append(
                SLABreachItem(
                    alert_id=str(alert.id),
                    title=alert.title,
                    severity=sev,
                    created_at=created_at,
                    acknowledged_at=ack_at,
                    triage_delay_seconds=round(max(0.0, delay), 2),
                    assigned_to=assigned_user,
                )
            )

    sla_breached_count = len(breached_items)
    breach_rate = (
        round((sla_breached_count / applicable_alerts) * 100.0, 2) if applicable_alerts > 0 else 0.0
    )

    return SLAReport(
        time_range=time_range,
        sla_breached_count=sla_breached_count,
        applicable_alerts=applicable_alerts,
        breach_rate_percentage=breach_rate,
        severity_distribution=severity_distribution,
        breached_alerts=breached_items,
        generated_at=now,
    )

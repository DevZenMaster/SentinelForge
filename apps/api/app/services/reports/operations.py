"""Security Operations Summary and Alert Performance Reporting Services."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.detection import DetectionRule
from app.models.incident import Incident
from app.models.indicator import Indicator, IndicatorStatus
from app.schemas.reports import (
    AlertLifecycleMetrics,
    AlertPerformanceReport,
    OperationsSummaryReport,
    ReportingTimeRange,
)
from app.services.reports.base import calculate_duration_metric, to_utc

SEVERITY_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
STATUS_KEYS = ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS", "SUPPRESSED", "RESOLVED", "CLOSED"]


async def get_operations_summary(
    db: AsyncSession, time_range: ReportingTimeRange
) -> OperationsSummaryReport:
    """Generate high-level operational summary KPIs for the specified window."""
    # 1. Alert Aggregations
    alert_query = select(
        func.count(Alert.id).label("total"),
        func.count().filter(Alert.acknowledged_at.is_not(None)).label("acknowledged"),
        func.count().filter(Alert.acknowledged_at.is_(None)).label("unacknowledged"),
        func.count().filter(Alert.assignee_id.is_not(None)).label("assigned"),
        func.count().filter(Alert.assignee_id.is_(None)).label("unassigned"),
        func.count().filter(Alert.suppressed_at.is_not(None)).label("suppressed"),
        func.count().filter(Alert.resolved_at.is_not(None)).label("resolved"),
        func.count().filter(Alert.closed_at.is_not(None)).label("closed"),
    ).where(
        Alert.created_at >= time_range.start_time,
        Alert.created_at <= time_range.end_time,
    )
    alert_res = (await db.execute(alert_query)).one()

    # Severity distribution
    sev_query = (
        select(Alert.severity, func.count(Alert.id))
        .where(
            Alert.created_at >= time_range.start_time,
            Alert.created_at <= time_range.end_time,
        )
        .group_by(Alert.severity)
    )
    sev_counts: dict[str, int] = {
        str(row[0]): int(row[1]) for row in (await db.execute(sev_query)).all()
    }
    alerts_by_severity = {k: sev_counts.get(k, 0) for k in SEVERITY_KEYS}

    # Status distribution
    stat_query = (
        select(Alert.status, func.count(Alert.id))
        .where(
            Alert.created_at >= time_range.start_time,
            Alert.created_at <= time_range.end_time,
        )
        .group_by(Alert.status)
    )
    stat_counts: dict[str, int] = {
        str(row[0]): int(row[1]) for row in (await db.execute(stat_query)).all()
    }
    alerts_by_status = {k: stat_counts.get(k, 0) for k in STATUS_KEYS}

    # 2. Open Incident Cases
    inc_query = select(func.count(Incident.id)).where(
        Incident.status.in_(["OPEN", "IN_PROGRESS", "REOPENED"])
    )
    open_incidents = (await db.execute(inc_query)).scalar_one()

    # 3. Active Detection Rules
    rule_query = select(func.count(DetectionRule.id)).where(DetectionRule.status == "ACTIVE")
    active_rules = (await db.execute(rule_query)).scalar_one()

    # 4. Active Threat Indicators
    ioc_query = select(func.count(Indicator.id)).where(Indicator.status == IndicatorStatus.ACTIVE)
    active_indicators = (await db.execute(ioc_query)).scalar_one()

    return OperationsSummaryReport(
        time_range=time_range,
        total_alerts=alert_res.total,
        alerts_by_severity=alerts_by_severity,
        alerts_by_status=alerts_by_status,
        acknowledged_count=alert_res.acknowledged,
        unacknowledged_count=alert_res.unacknowledged,
        assigned_count=alert_res.assigned,
        unassigned_count=alert_res.unassigned,
        suppressed_count=alert_res.suppressed,
        resolved_count=alert_res.resolved,
        closed_count=alert_res.closed,
        open_incident_cases=open_incidents,
        total_active_rules=active_rules,
        total_active_indicators=active_indicators,
        generated_at=datetime.now(UTC),
    )


async def get_alert_performance(
    db: AsyncSession, time_range: ReportingTimeRange
) -> AlertPerformanceReport:
    """Generate detailed alert performance and lifecycle duration metrics."""
    # Query all alert lifecycle timestamps within the window
    stmt = select(
        Alert.id,
        Alert.severity,
        Alert.status,
        Alert.created_at,
        Alert.acknowledged_at,
        Alert.assigned_at,
        Alert.resolved_at,
        Alert.closed_at,
    ).where(
        Alert.created_at >= time_range.start_time,
        Alert.created_at <= time_range.end_time,
    )
    rows = (await db.execute(stmt)).all()

    alerts_by_severity = {k: 0 for k in SEVERITY_KEYS}
    alerts_by_status = {k: 0 for k in STATUS_KEYS}

    ack_durations: list[float] = []
    assign_durations: list[float] = []
    resolve_durations: list[float] = []
    close_durations: list[float] = []

    unack_count = 0
    unassign_count = 0
    unres_count = 0
    unclosed_count = 0

    for row in rows:
        # Severity and status frequency
        sev = row.severity.upper() if row.severity else "INFO"
        if sev in alerts_by_severity:
            alerts_by_severity[sev] += 1

        stat = row.status.upper() if row.status else "OPEN"
        if stat in alerts_by_status:
            alerts_by_status[stat] += 1

        c_at = to_utc(row.created_at)
        if c_at is None:
            continue

        # Time to Acknowledge
        if row.acknowledged_at is not None:
            ack_at = to_utc(row.acknowledged_at)
            if ack_at is not None:
                delta = (ack_at - c_at).total_seconds()
                ack_durations.append(max(0.0, delta))
            else:
                unack_count += 1
        else:
            unack_count += 1

        # Time to Assign
        if row.assigned_at is not None:
            assign_at = to_utc(row.assigned_at)
            if assign_at is not None:
                delta = (assign_at - c_at).total_seconds()
                assign_durations.append(max(0.0, delta))
            else:
                unassign_count += 1
        else:
            unassign_count += 1

        # Time to Resolve
        if row.resolved_at is not None:
            res_at = to_utc(row.resolved_at)
            if res_at is not None:
                delta = (res_at - c_at).total_seconds()
                resolve_durations.append(max(0.0, delta))
            else:
                unres_count += 1
        else:
            unres_count += 1

        # Time to Close
        if row.closed_at is not None:
            cl_at = to_utc(row.closed_at)
            if cl_at is not None:
                delta = (cl_at - c_at).total_seconds()
                close_durations.append(max(0.0, delta))
            else:
                unclosed_count += 1
        else:
            unclosed_count += 1

    lifecycle = AlertLifecycleMetrics(
        time_to_acknowledge=calculate_duration_metric(ack_durations),
        time_to_assign=calculate_duration_metric(assign_durations),
        time_to_resolve=calculate_duration_metric(resolve_durations),
        time_to_close=calculate_duration_metric(close_durations),
        unacknowledged_count=unack_count,
        unassigned_count=unassign_count,
        unresolved_count=unres_count,
        unclosed_count=unclosed_count,
    )

    return AlertPerformanceReport(
        time_range=time_range,
        total_alerts=len(rows),
        alerts_by_severity=alerts_by_severity,
        alerts_by_status=alerts_by_status,
        lifecycle=lifecycle,
        generated_at=datetime.now(UTC),
    )

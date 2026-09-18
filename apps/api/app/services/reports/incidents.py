"""Incident Response Operations and Case Management Reporting Service."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.incident import Incident, IncidentAlert
from app.schemas.reports import IncidentReport, ReportingTimeRange
from app.services.reports.base import calculate_duration_metric, to_utc

INCIDENT_SEVERITY_KEYS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
INCIDENT_STATUS_KEYS = ["OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED", "REOPENED"]
STANDARD_RESOLUTION_CATEGORIES = [
    "TRUE_POSITIVE_MALICIOUS",
    "TRUE_POSITIVE_BENIGN",
    "FALSE_POSITIVE",
    "DUPLICATE",
    "OTHER",
]


async def get_incident_report(db: AsyncSession, time_range: ReportingTimeRange) -> IncidentReport:
    """Generate metrics for security incidents and resolution performance."""
    # 1. Fetch incident rows in the time window
    stmt = select(
        Incident.id,
        Incident.severity,
        Incident.status,
        Incident.resolution_category,
        Incident.created_at,
        Incident.resolved_at,
    ).where(
        Incident.created_at >= time_range.start_time,
        Incident.created_at <= time_range.end_time,
    )
    rows = (await db.execute(stmt)).all()

    incidents_by_severity = {k: 0 for k in INCIDENT_SEVERITY_KEYS}
    incidents_by_status = {k: 0 for k in INCIDENT_STATUS_KEYS}
    resolution_breakdown = {k: 0 for k in STANDARD_RESOLUTION_CATEGORIES}
    resolved_durations: list[float] = []

    for row in rows:
        sev = row.severity.upper() if row.severity else "MEDIUM"
        if sev in incidents_by_severity:
            incidents_by_severity[sev] += 1
        else:
            incidents_by_severity[sev] = 1

        stat = row.status.upper() if row.status else "OPEN"
        if stat in incidents_by_status:
            incidents_by_status[stat] += 1
        else:
            incidents_by_status[stat] = 1

        if row.resolution_category:
            cat = row.resolution_category.upper()
            resolution_breakdown[cat] = resolution_breakdown.get(cat, 0) + 1

        if row.resolved_at is not None:
            c_at = to_utc(row.created_at)
            res_at = to_utc(row.resolved_at)
            if c_at is not None and res_at is not None:
                delta = (res_at - c_at).total_seconds()
                resolved_durations.append(max(0.0, delta))

    # 2. Count linked alerts for incidents created in this window
    linked_alerts_query = (
        select(func.count(IncidentAlert.id))
        .join(Incident, IncidentAlert.incident_id == Incident.id)
        .where(
            Incident.created_at >= time_range.start_time,
            Incident.created_at <= time_range.end_time,
        )
    )
    linked_alerts_count = (await db.execute(linked_alerts_query)).scalar_one()

    return IncidentReport(
        time_range=time_range,
        total_incidents=len(rows),
        incidents_by_severity=incidents_by_severity,
        incidents_by_status=incidents_by_status,
        resolution_breakdown=resolution_breakdown,
        duration_metrics=calculate_duration_metric(resolved_durations),
        linked_alerts_count=linked_alerts_count,
        generated_at=datetime.now(UTC),
    )

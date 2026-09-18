"""Threat Intelligence and Indicator Telemetry Reporting Service."""

from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.indicator import Indicator, IndicatorEvent, IndicatorStatus, IndicatorType
from app.schemas.reports import ReportingTimeRange, ThreatIntelReport

ALL_IOC_TYPES = [t.value for t in IndicatorType]
ALL_IOC_STATUSES = [s.value for s in IndicatorStatus]


async def get_threat_intel_report(
    db: AsyncSession, time_range: ReportingTimeRange
) -> ThreatIntelReport:
    """Generate threat intelligence corpus volume, types, and sighting observations."""
    # 1. Type distribution
    type_query = select(Indicator.type, func.count(Indicator.id)).group_by(Indicator.type)
    type_rows: dict[str, int] = {
        str(row[0]): int(row[1]) for row in (await db.execute(type_query)).all()
    }
    indicators_by_type = {t: type_rows.get(t, 0) for t in ALL_IOC_TYPES}

    # 2. Status distribution
    status_query = select(Indicator.status, func.count(Indicator.id)).group_by(Indicator.status)
    status_rows: dict[str, int] = {
        str(row[0]): int(row[1]) for row in (await db.execute(status_query)).all()
    }
    indicators_by_status = {s: status_rows.get(s, 0) for s in ALL_IOC_STATUSES}

    # Total indicators
    total_indicators = sum(indicators_by_status.values())

    # 3. Sightings in the reporting period
    sightings_query = select(func.count(IndicatorEvent.id)).where(
        IndicatorEvent.created_at >= time_range.start_time,
        IndicatorEvent.created_at <= time_range.end_time,
    )
    total_sightings = (await db.execute(sightings_query)).scalar_one()

    return ThreatIntelReport(
        time_range=time_range,
        indicators_by_type=indicators_by_type,
        indicators_by_status=indicators_by_status,
        total_indicators=total_indicators,
        total_sightings_in_period=total_sightings,
        generated_at=datetime.now(UTC),
    )

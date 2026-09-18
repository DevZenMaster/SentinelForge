"""Investigation Analytics and Correlation Service (Phase 8).

Provides deterministic, read-only analytics correlating Events, Alerts, Incidents,
Indicators, and Threat Intelligence. Implements bounded queries, unified multi-entity
timelines, deterministic tie-breaking, and database-level aggregate summaries.
"""

import ipaddress
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alert import Alert, AlertEvent
from app.models.event import Event
from app.models.incident import Incident, IncidentAlert, IncidentEvent, IncidentNote
from app.models.indicator import (
    Indicator,
    IndicatorEvent,
    IndicatorType,
    ThreatClassification,
)
from app.schemas.investigation import (
    MAX_INVESTIGATION_WINDOW_SECONDS,
    InvestigationAlertSummary,
    InvestigationAnchor,
    InvestigationAnchorType,
    InvestigationContextResponse,
    InvestigationEventSummary,
    InvestigationIncidentSummary,
    InvestigationIndicatorSummary,
    InvestigationSummary,
    InvestigationTimelineEntry,
    InvestigationTimelineResponse,
)

logger = logging.getLogger("sentinelforge.investigation")


class InvestigationTargetNotFoundError(Exception):
    """Raised when an anchor entity (incident, alert, indicator) cannot be found."""


class InvestigationValidationError(Exception):
    """Raised when investigation parameters fail domain validation."""


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _safe_uuid(val: str) -> uuid.UUID | None:
    """Safely convert string to UUID, returning None on failure."""
    try:
        return uuid.UUID(val.strip())
    except (ValueError, AttributeError):
        return None


async def resolve_investigation_anchor(
    db: AsyncSession,
    anchor_type: InvestigationAnchorType,
    anchor_value: str,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    window_seconds: int | None = None,
) -> tuple[InvestigationAnchor, dict[str, Any]]:
    """Validate and resolve investigation anchor entity and temporal boundaries.

    Returns the validated InvestigationAnchor and a resolved context dictionary
    containing resolved ORM objects (e.g. incident, alert, indicator).
    """
    val = anchor_value.strip()
    if not val:
        raise InvestigationValidationError("Anchor value cannot be empty.")

    resolved_context: dict[str, Any] = {}
    now_utc = datetime.now(UTC)

    # 1. Temporal boundary resolution
    start_time = _ensure_utc(start_time)
    end_time = _ensure_utc(end_time)

    if window_seconds is not None:
        if window_seconds <= 0 or window_seconds > MAX_INVESTIGATION_WINDOW_SECONDS:
            raise InvestigationValidationError(
                f"window_seconds must be between 1 and {MAX_INVESTIGATION_WINDOW_SECONDS} seconds."
            )
        if end_time is None and start_time is None:
            end_time = now_utc
            start_time = end_time - timedelta(seconds=window_seconds)
        elif start_time is not None and end_time is None:
            end_time = start_time + timedelta(seconds=window_seconds)
        elif end_time is not None and start_time is None:
            start_time = end_time - timedelta(seconds=window_seconds)

    if start_time and end_time:
        if start_time > end_time:
            raise InvestigationValidationError("start_time cannot be greater than end_time.")
        if (end_time - start_time).total_seconds() > MAX_INVESTIGATION_WINDOW_SECONDS:
            raise InvestigationValidationError(
                f"Time window cannot exceed {MAX_INVESTIGATION_WINDOW_SECONDS} seconds (30 days)."
            )

    # 2. Entity resolution
    if anchor_type == InvestigationAnchorType.INCIDENT:
        incident_uuid = _safe_uuid(val)
        stmt_inc = select(Incident).where(
            or_(
                Incident.id == incident_uuid if incident_uuid else False,
                Incident.incident_id == val.upper(),
            )
        )
        res_inc = await db.execute(stmt_inc)
        incident = res_inc.scalar_one_or_none()
        if not incident:
            raise InvestigationTargetNotFoundError(f"Incident '{val}' not found.")
        resolved_context["incident"] = incident

    elif anchor_type == InvestigationAnchorType.ALERT:
        alert_uuid = _safe_uuid(val)
        if not alert_uuid:
            raise InvestigationValidationError(f"Invalid alert UUID format '{val}'.")
        stmt_alert = select(Alert).where(Alert.id == alert_uuid)
        res_alert = await db.execute(stmt_alert)
        alert = res_alert.scalar_one_or_none()
        if not alert:
            raise InvestigationTargetNotFoundError(f"Alert '{val}' not found.")
        resolved_context["alert"] = alert

    elif anchor_type == InvestigationAnchorType.INDICATOR:
        ind_uuid = _safe_uuid(val)
        stmt_ind = select(Indicator).where(
            or_(
                Indicator.id == ind_uuid if ind_uuid else False,
                Indicator.normalized_value == val,
            )
        )
        res_ind = await db.execute(stmt_ind)
        indicator = res_ind.scalar_one_or_none()
        if not indicator:
            raise InvestigationTargetNotFoundError(f"Indicator '{val}' not found.")
        resolved_context["indicator"] = indicator

    elif anchor_type in (InvestigationAnchorType.SOURCE_IP, InvestigationAnchorType.DESTINATION_IP):
        try:
            ipaddress.ip_address(val)
        except ValueError as err:
            raise InvestigationValidationError(f"Invalid IP address format: '{val}'.") from err

    elif anchor_type == InvestigationAnchorType.USERNAME:
        if len(val) > 128:
            raise InvestigationValidationError("Username exceeds maximum length of 128 characters.")

    anchor = InvestigationAnchor(
        anchor_type=anchor_type,
        anchor_value=val,
        start_time=start_time,
        end_time=end_time,
        window_seconds=window_seconds,
    )
    return anchor, resolved_context


# ==============================================================================
# Correlated Events Query Engine
# ==============================================================================


async def get_correlated_events(
    db: AsyncSession,
    anchor: InvestigationAnchor,
    resolved_context: dict[str, Any] | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[InvestigationEventSummary], int]:
    """Retrieve bounded, paginated canonical event summaries correlated with the anchor."""
    limit = max(1, min(limit, 500))
    offset = max(0, (page - 1) * limit)

    if resolved_context is None:
        _, resolved_context = await resolve_investigation_anchor(
            db,
            anchor.anchor_type,
            anchor.anchor_value,
            anchor.start_time,
            anchor.end_time,
            anchor.window_seconds,
        )

    stmt = select(Event)
    count_stmt = select(func.count(func.distinct(Event.id)))

    if anchor.anchor_type == InvestigationAnchorType.INCIDENT:
        incident: Incident = resolved_context["incident"]
        direct_event_subquery = select(IncidentEvent.event_id).where(
            IncidentEvent.incident_id == incident.id
        )
        indirect_event_subquery = (
            select(AlertEvent.event_id)
            .join(IncidentAlert, IncidentAlert.alert_id == AlertEvent.alert_id)
            .where(IncidentAlert.incident_id == incident.id)
        )
        combined_events = direct_event_subquery.union(indirect_event_subquery).subquery()
        stmt = stmt.join(combined_events, Event.id == combined_events.c.event_id)
        count_stmt = count_stmt.join(combined_events, Event.id == combined_events.c.event_id)

    elif anchor.anchor_type == InvestigationAnchorType.ALERT:
        alert: Alert = resolved_context["alert"]
        stmt = stmt.join(AlertEvent, AlertEvent.event_id == Event.id).where(
            AlertEvent.alert_id == alert.id
        )
        count_stmt = count_stmt.join(AlertEvent, AlertEvent.event_id == Event.id).where(
            AlertEvent.alert_id == alert.id
        )

    elif anchor.anchor_type == InvestigationAnchorType.INDICATOR:
        indicator: Indicator = resolved_context["indicator"]
        stmt = stmt.join(IndicatorEvent, IndicatorEvent.event_id == Event.id).where(
            IndicatorEvent.indicator_id == indicator.id
        )
        count_stmt = count_stmt.join(IndicatorEvent, IndicatorEvent.event_id == Event.id).where(
            IndicatorEvent.indicator_id == indicator.id
        )

    elif anchor.anchor_type == InvestigationAnchorType.SOURCE_IP:
        stmt = stmt.where(Event.source_ip == anchor.anchor_value)
        count_stmt = count_stmt.where(Event.source_ip == anchor.anchor_value)

    elif anchor.anchor_type == InvestigationAnchorType.DESTINATION_IP:
        stmt = stmt.where(Event.destination_ip == anchor.anchor_value)
        count_stmt = count_stmt.where(Event.destination_ip == anchor.anchor_value)

    elif anchor.anchor_type == InvestigationAnchorType.USERNAME:
        stmt = stmt.where(Event.username == anchor.anchor_value)
        count_stmt = count_stmt.where(Event.username == anchor.anchor_value)

    # Apply temporal window constraints
    if anchor.start_time:
        stmt = stmt.where(Event.timestamp >= anchor.start_time)
        count_stmt = count_stmt.where(Event.timestamp >= anchor.start_time)
    if anchor.end_time:
        stmt = stmt.where(Event.timestamp <= anchor.end_time)
        count_stmt = count_stmt.where(Event.timestamp <= anchor.end_time)

    # Total count
    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one() or 0

    # Deterministic ordering: primary timestamp descending, secondary UUID descending
    stmt = stmt.order_by(Event.timestamp.desc(), Event.id.desc()).offset(offset).limit(limit)
    res = await db.execute(stmt)
    events = res.scalars().all()

    items = [
        InvestigationEventSummary(
            id=e.id,
            timestamp=_ensure_utc(e.timestamp) or datetime.now(UTC),
            source=e.source,
            source_type=e.source_type,
            source_ip=e.source_ip,
            destination_ip=e.destination_ip,
            source_port=e.source_port,
            destination_port=e.destination_port,
            event_type=e.event_type,
            action=e.action,
            outcome=e.outcome,
            username=e.username,
            severity=e.severity,
            message=e.message,
        )
        for e in events
    ]
    return items, total


# ==============================================================================
# Correlated Alerts Query Engine
# ==============================================================================


async def get_correlated_alerts(
    db: AsyncSession,
    anchor: InvestigationAnchor,
    resolved_context: dict[str, Any] | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[InvestigationAlertSummary], int]:
    """Retrieve bounded, paginated alerts correlated with the investigation anchor."""
    limit = max(1, min(limit, 500))
    offset = max(0, (page - 1) * limit)

    if resolved_context is None:
        _, resolved_context = await resolve_investigation_anchor(
            db,
            anchor.anchor_type,
            anchor.anchor_value,
            anchor.start_time,
            anchor.end_time,
            anchor.window_seconds,
        )

    stmt = select(Alert)
    count_stmt = select(func.count(func.distinct(Alert.id)))

    if anchor.anchor_type == InvestigationAnchorType.INCIDENT:
        incident: Incident = resolved_context["incident"]
        stmt = stmt.join(IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
            IncidentAlert.incident_id == incident.id
        )
        count_stmt = count_stmt.join(IncidentAlert, IncidentAlert.alert_id == Alert.id).where(
            IncidentAlert.incident_id == incident.id
        )

    elif anchor.anchor_type == InvestigationAnchorType.ALERT:
        alert: Alert = resolved_context["alert"]
        # Include the alert itself, plus alerts matching the same correlation key or source IP
        conditions = [Alert.id == alert.id]
        if alert.correlation_key:
            conditions.append(Alert.correlation_key == alert.correlation_key)
        if alert.source_ip:
            conditions.append(Alert.source_ip == alert.source_ip)
        stmt = stmt.where(or_(*conditions))
        count_stmt = count_stmt.where(or_(*conditions))

    elif anchor.anchor_type == InvestigationAnchorType.INDICATOR:
        indicator: Indicator = resolved_context["indicator"]
        # Alerts containing events that carry this indicator
        stmt = (
            stmt.join(AlertEvent, AlertEvent.alert_id == Alert.id)
            .join(IndicatorEvent, IndicatorEvent.event_id == AlertEvent.event_id)
            .where(IndicatorEvent.indicator_id == indicator.id)
        )
        count_stmt = (
            count_stmt.join(AlertEvent, AlertEvent.alert_id == Alert.id)
            .join(IndicatorEvent, IndicatorEvent.event_id == AlertEvent.event_id)
            .where(IndicatorEvent.indicator_id == indicator.id)
        )

    elif anchor.anchor_type == InvestigationAnchorType.SOURCE_IP:
        # Match alerts by source_ip or by underlying events
        event_match = (
            select(AlertEvent.alert_id)
            .join(Event, Event.id == AlertEvent.event_id)
            .where(Event.source_ip == anchor.anchor_value)
        )
        condition = or_(Alert.source_ip == anchor.anchor_value, Alert.id.in_(event_match))
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    elif anchor.anchor_type == InvestigationAnchorType.DESTINATION_IP:
        # Match alerts whose constituent events contain destination_ip
        event_match = (
            select(AlertEvent.alert_id)
            .join(Event, Event.id == AlertEvent.event_id)
            .where(Event.destination_ip == anchor.anchor_value)
        )
        stmt = stmt.where(Alert.id.in_(event_match))
        count_stmt = count_stmt.where(Alert.id.in_(event_match))

    elif anchor.anchor_type == InvestigationAnchorType.USERNAME:
        # Match alerts by username or by constituent events
        event_match = (
            select(AlertEvent.alert_id)
            .join(Event, Event.id == AlertEvent.event_id)
            .where(Event.username == anchor.anchor_value)
        )
        condition = or_(Alert.username == anchor.anchor_value, Alert.id.in_(event_match))
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    # Temporal bounds on alert creation / detection
    if anchor.start_time:
        stmt = stmt.where(Alert.created_at >= anchor.start_time)
        count_stmt = count_stmt.where(Alert.created_at >= anchor.start_time)
    if anchor.end_time:
        stmt = stmt.where(Alert.created_at <= anchor.end_time)
        count_stmt = count_stmt.where(Alert.created_at <= anchor.end_time)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one() or 0

    # Deterministic ordering: primary created_at descending, secondary UUID descending
    stmt = (
        stmt.distinct()
        .order_by(Alert.created_at.desc(), Alert.id.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    alerts = res.scalars().all()

    items = [
        InvestigationAlertSummary(
            id=a.id,
            rule_id=a.rule_id,
            rule_version=a.rule_version,
            title=a.title,
            description=a.description,
            severity=a.severity,
            status=a.status,
            source_ip=a.source_ip,
            username=a.username,
            correlation_key=a.correlation_key,
            observed_count=a.observed_count,
            first_seen=_ensure_utc(a.first_seen) or datetime.now(UTC),
            last_seen=_ensure_utc(a.last_seen) or datetime.now(UTC),
            created_at=_ensure_utc(a.created_at) or datetime.now(UTC),
        )
        for a in alerts
    ]
    return items, total


# ==============================================================================
# Correlated Incidents Query Engine
# ==============================================================================


async def get_correlated_incidents(
    db: AsyncSession,
    anchor: InvestigationAnchor,
    resolved_context: dict[str, Any] | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[InvestigationIncidentSummary], int]:
    """Retrieve bounded, paginated incidents correlated with the investigation anchor."""
    limit = max(1, min(limit, 500))
    offset = max(0, (page - 1) * limit)

    if resolved_context is None:
        _, resolved_context = await resolve_investigation_anchor(
            db,
            anchor.anchor_type,
            anchor.anchor_value,
            anchor.start_time,
            anchor.end_time,
            anchor.window_seconds,
        )

    stmt = select(Incident)
    count_stmt = select(func.count(func.distinct(Incident.id)))

    if anchor.anchor_type == InvestigationAnchorType.INCIDENT:
        incident: Incident = resolved_context["incident"]
        stmt = stmt.where(Incident.id == incident.id)
        count_stmt = count_stmt.where(Incident.id == incident.id)

    elif anchor.anchor_type == InvestigationAnchorType.ALERT:
        alert: Alert = resolved_context["alert"]
        stmt = stmt.join(IncidentAlert, IncidentAlert.incident_id == Incident.id).where(
            IncidentAlert.alert_id == alert.id
        )
        count_stmt = count_stmt.join(IncidentAlert, IncidentAlert.incident_id == Incident.id).where(
            IncidentAlert.alert_id == alert.id
        )

    elif anchor.anchor_type == InvestigationAnchorType.INDICATOR:
        indicator: Indicator = resolved_context["indicator"]
        direct_incidents = (
            select(IncidentEvent.incident_id)
            .join(IndicatorEvent, IndicatorEvent.event_id == IncidentEvent.event_id)
            .where(IndicatorEvent.indicator_id == indicator.id)
        )
        indirect_incidents = (
            select(IncidentAlert.incident_id)
            .join(AlertEvent, AlertEvent.alert_id == IncidentAlert.alert_id)
            .join(IndicatorEvent, IndicatorEvent.event_id == AlertEvent.event_id)
            .where(IndicatorEvent.indicator_id == indicator.id)
        )
        union_incidents = direct_incidents.union(indirect_incidents).subquery()
        stmt = stmt.join(union_incidents, Incident.id == union_incidents.c.incident_id)
        count_stmt = count_stmt.join(union_incidents, Incident.id == union_incidents.c.incident_id)

    elif anchor.anchor_type == InvestigationAnchorType.SOURCE_IP:
        direct_incidents = (
            select(IncidentEvent.incident_id)
            .join(Event, Event.id == IncidentEvent.event_id)
            .where(Event.source_ip == anchor.anchor_value)
        )
        alert_incidents = (
            select(IncidentAlert.incident_id)
            .join(Alert, Alert.id == IncidentAlert.alert_id)
            .where(Alert.source_ip == anchor.anchor_value)
        )
        union_inc = direct_incidents.union(alert_incidents).subquery()
        stmt = stmt.join(union_inc, Incident.id == union_inc.c.incident_id)
        count_stmt = count_stmt.join(union_inc, Incident.id == union_inc.c.incident_id)

    elif anchor.anchor_type == InvestigationAnchorType.DESTINATION_IP:
        event_inc = (
            select(IncidentEvent.incident_id)
            .join(Event, Event.id == IncidentEvent.event_id)
            .where(Event.destination_ip == anchor.anchor_value)
        )
        stmt = stmt.where(Incident.id.in_(event_inc))
        count_stmt = count_stmt.where(Incident.id.in_(event_inc))

    elif anchor.anchor_type == InvestigationAnchorType.USERNAME:
        direct_inc = (
            select(IncidentEvent.incident_id)
            .join(Event, Event.id == IncidentEvent.event_id)
            .where(Event.username == anchor.anchor_value)
        )
        alert_inc = (
            select(IncidentAlert.incident_id)
            .join(Alert, Alert.id == IncidentAlert.alert_id)
            .where(Alert.username == anchor.anchor_value)
        )
        union_inc = direct_inc.union(alert_inc).subquery()
        stmt = stmt.join(union_inc, Incident.id == union_inc.c.incident_id)
        count_stmt = count_stmt.join(union_inc, Incident.id == union_inc.c.incident_id)

    if anchor.start_time:
        stmt = stmt.where(Incident.created_at >= anchor.start_time)
        count_stmt = count_stmt.where(Incident.created_at >= anchor.start_time)
    if anchor.end_time:
        stmt = stmt.where(Incident.created_at <= anchor.end_time)
        count_stmt = count_stmt.where(Incident.created_at <= anchor.end_time)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one() or 0

    stmt = (
        stmt.distinct()
        .order_by(Incident.created_at.desc(), Incident.id.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    incidents = res.scalars().all()

    items = [
        InvestigationIncidentSummary(
            id=i.id,
            incident_id=i.incident_id,
            title=i.title,
            description=i.description,
            severity=i.severity,
            priority=i.priority,
            status=i.status,
            created_at=_ensure_utc(i.created_at) or datetime.now(UTC),
        )
        for i in incidents
    ]
    return items, total


# ==============================================================================
# Correlated Indicators Query Engine
# ==============================================================================


async def get_correlated_indicators(
    db: AsyncSession,
    anchor: InvestigationAnchor,
    resolved_context: dict[str, Any] | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[InvestigationIndicatorSummary], int]:
    """Retrieve bounded, paginated indicators correlated with the investigation anchor."""
    limit = max(1, min(limit, 500))
    offset = max(0, (page - 1) * limit)

    if resolved_context is None:
        _, resolved_context = await resolve_investigation_anchor(
            db,
            anchor.anchor_type,
            anchor.anchor_value,
            anchor.start_time,
            anchor.end_time,
            anchor.window_seconds,
        )

    stmt = select(Indicator).options(selectinload(Indicator.threat_intelligences))
    count_stmt = select(func.count(func.distinct(Indicator.id)))

    if anchor.anchor_type == InvestigationAnchorType.INCIDENT:
        incident: Incident = resolved_context["incident"]
        direct_ind = (
            select(IndicatorEvent.indicator_id)
            .join(IncidentEvent, IncidentEvent.event_id == IndicatorEvent.event_id)
            .where(IncidentEvent.incident_id == incident.id)
        )
        indirect_ind = (
            select(IndicatorEvent.indicator_id)
            .join(AlertEvent, AlertEvent.event_id == IndicatorEvent.event_id)
            .join(IncidentAlert, IncidentAlert.alert_id == AlertEvent.alert_id)
            .where(IncidentAlert.incident_id == incident.id)
        )
        union_ind = direct_ind.union(indirect_ind).subquery()
        stmt = stmt.join(union_ind, Indicator.id == union_ind.c.indicator_id)
        count_stmt = count_stmt.join(union_ind, Indicator.id == union_ind.c.indicator_id)

    elif anchor.anchor_type == InvestigationAnchorType.ALERT:
        alert: Alert = resolved_context["alert"]
        ind_subquery = (
            select(IndicatorEvent.indicator_id)
            .join(AlertEvent, AlertEvent.event_id == IndicatorEvent.event_id)
            .where(AlertEvent.alert_id == alert.id)
        )
        stmt = stmt.where(Indicator.id.in_(ind_subquery))
        count_stmt = count_stmt.where(Indicator.id.in_(ind_subquery))

    elif anchor.anchor_type == InvestigationAnchorType.INDICATOR:
        indicator: Indicator = resolved_context["indicator"]
        stmt = stmt.where(Indicator.id == indicator.id)
        count_stmt = count_stmt.where(Indicator.id == indicator.id)

    elif anchor.anchor_type in (
        InvestigationAnchorType.SOURCE_IP,
        InvestigationAnchorType.DESTINATION_IP,
    ):
        ip_val = anchor.anchor_value
        event_filter = (
            Event.source_ip == ip_val
            if anchor.anchor_type == InvestigationAnchorType.SOURCE_IP
            else Event.destination_ip == ip_val
        )
        ind_from_events = (
            select(IndicatorEvent.indicator_id)
            .join(Event, Event.id == IndicatorEvent.event_id)
            .where(event_filter)
        )
        direct_ip_ind = select(Indicator.id).where(
            Indicator.type == IndicatorType.IP.value,
            Indicator.normalized_value == ip_val,
        )
        union_ip_ind = ind_from_events.union(direct_ip_ind).subquery()
        stmt = stmt.join(union_ip_ind, Indicator.id == union_ip_ind.c.indicator_id)
        count_stmt = count_stmt.join(union_ip_ind, Indicator.id == union_ip_ind.c.indicator_id)

    elif anchor.anchor_type == InvestigationAnchorType.USERNAME:
        username_val = anchor.anchor_value
        ind_from_events = (
            select(IndicatorEvent.indicator_id)
            .join(Event, Event.id == IndicatorEvent.event_id)
            .where(Event.username == username_val)
        )
        direct_user_ind = select(Indicator.id).where(
            Indicator.type == IndicatorType.EMAIL.value,
            Indicator.normalized_value == username_val.lower(),
        )
        union_u_ind = ind_from_events.union(direct_user_ind).subquery()
        stmt = stmt.join(union_u_ind, Indicator.id == union_u_ind.c.indicator_id)
        count_stmt = count_stmt.join(union_u_ind, Indicator.id == union_u_ind.c.indicator_id)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one() or 0

    stmt = (
        stmt.distinct()
        .order_by(Indicator.last_seen_at.desc(), Indicator.id.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(stmt)
    indicators = res.scalars().all()

    now_utc = datetime.now(UTC)
    severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

    items: list[InvestigationIndicatorSummary] = []
    for ind in indicators:
        threat_sources: list[str] = []
        is_threat = False
        highest_sev: str | None = None
        highest_sev_rank = 0

        for intel in ind.threat_intelligences:
            intel_exp = _ensure_utc(intel.expires_at)
            is_expired = intel_exp is not None and intel_exp < now_utc
            threat_sources.append(intel.source)

            if not is_expired and intel.threat_classification in (
                ThreatClassification.MALICIOUS,
                ThreatClassification.SUSPICIOUS,
                ThreatClassification.MALICIOUS.value,
                ThreatClassification.SUSPICIOUS.value,
            ):
                is_threat = True
                raw_sev = (
                    intel.severity.value if hasattr(intel.severity, "value") else intel.severity
                )
                sev_str = str(raw_sev).upper()
                rank = severity_order.get(sev_str, 0)
                if rank > highest_sev_rank:
                    highest_sev_rank = rank
                    highest_sev = sev_str

        items.append(
            InvestigationIndicatorSummary(
                id=ind.id,
                type=str(ind.type.value if hasattr(ind.type, "value") else ind.type),
                normalized_value=ind.normalized_value,
                status=str(ind.status.value if hasattr(ind.status, "value") else ind.status),
                sightings_count=ind.sightings_count,
                first_seen_at=_ensure_utc(ind.first_seen_at) or now_utc,
                last_seen_at=_ensure_utc(ind.last_seen_at) or now_utc,
                is_threat=is_threat,
                threat_sources=sorted(list(set(threat_sources))),
                highest_severity=highest_sev,
            )
        )

    return items, total


# ==============================================================================
# Investigation Summary Aggregate Engine
# ==============================================================================


async def get_investigation_summary(
    db: AsyncSession,
    anchor: InvestigationAnchor,
    resolved_context: dict[str, Any] | None = None,
) -> InvestigationSummary:
    """Compute deterministic, database-level aggregate investigation summary metrics.

    Does NOT calculate risk scores or threat scores. Reflects factual database counts.
    """
    if resolved_context is None:
        _, resolved_context = await resolve_investigation_anchor(
            db,
            anchor.anchor_type,
            anchor.anchor_value,
            anchor.start_time,
            anchor.end_time,
            anchor.window_seconds,
        )

    # 1. Total counts across entities
    _, event_count = await get_correlated_events(db, anchor, resolved_context, page=1, limit=1)
    _, alert_count = await get_correlated_alerts(db, anchor, resolved_context, page=1, limit=1)
    _, incident_count = await get_correlated_incidents(
        db, anchor, resolved_context, page=1, limit=1
    )
    _, indicator_count = await get_correlated_indicators(
        db, anchor, resolved_context, page=1, limit=1
    )

    # 2. Distinct entity counts from correlated events
    # We construct a base query for events matching the anchor
    event_subquery_stmt = select(Event)
    if anchor.anchor_type == InvestigationAnchorType.INCIDENT:
        inc: Incident = resolved_context["incident"]
        direct = select(IncidentEvent.event_id).where(IncidentEvent.incident_id == inc.id)
        indirect = (
            select(AlertEvent.event_id)
            .join(IncidentAlert, IncidentAlert.alert_id == AlertEvent.alert_id)
            .where(IncidentAlert.incident_id == inc.id)
        )
        combined = direct.union(indirect).subquery()
        event_subquery_stmt = event_subquery_stmt.join(combined, Event.id == combined.c.event_id)
    elif anchor.anchor_type == InvestigationAnchorType.ALERT:
        al: Alert = resolved_context["alert"]
        event_subquery_stmt = event_subquery_stmt.join(
            AlertEvent, AlertEvent.event_id == Event.id
        ).where(AlertEvent.alert_id == al.id)
    elif anchor.anchor_type == InvestigationAnchorType.INDICATOR:
        ind: Indicator = resolved_context["indicator"]
        event_subquery_stmt = event_subquery_stmt.join(
            IndicatorEvent, IndicatorEvent.event_id == Event.id
        ).where(IndicatorEvent.indicator_id == ind.id)
    elif anchor.anchor_type == InvestigationAnchorType.SOURCE_IP:
        event_subquery_stmt = event_subquery_stmt.where(Event.source_ip == anchor.anchor_value)
    elif anchor.anchor_type == InvestigationAnchorType.DESTINATION_IP:
        event_subquery_stmt = event_subquery_stmt.where(Event.destination_ip == anchor.anchor_value)
    elif anchor.anchor_type == InvestigationAnchorType.USERNAME:
        event_subquery_stmt = event_subquery_stmt.where(Event.username == anchor.anchor_value)

    if anchor.start_time:
        event_subquery_stmt = event_subquery_stmt.where(Event.timestamp >= anchor.start_time)
    if anchor.end_time:
        event_subquery_stmt = event_subquery_stmt.where(Event.timestamp <= anchor.end_time)

    matched_events = event_subquery_stmt.subquery()

    agg_stmt = select(
        func.min(matched_events.c.timestamp),
        func.max(matched_events.c.timestamp),
        func.count(func.distinct(matched_events.c.source_ip)),
        func.count(func.distinct(matched_events.c.destination_ip)),
        func.count(func.distinct(matched_events.c.username)),
    )
    agg_res = await db.execute(agg_stmt)
    first_ev_ts, last_ev_ts, uniq_src, uniq_dst, uniq_users = agg_res.one()

    # Determine earliest and latest timestamps across all observed entities
    timestamps: list[datetime] = []
    if first_ev_ts:
        timestamps.append(_ensure_utc(first_ev_ts) or datetime.now(UTC))
    if last_ev_ts:
        timestamps.append(_ensure_utc(last_ev_ts) or datetime.now(UTC))

    if anchor.anchor_type == InvestigationAnchorType.INCIDENT:
        inc_obj: Incident = resolved_context["incident"]
        if inc_obj.created_at:
            timestamps.append(_ensure_utc(inc_obj.created_at) or datetime.now(UTC))
    elif anchor.anchor_type == InvestigationAnchorType.ALERT:
        al_obj: Alert = resolved_context["alert"]
        if al_obj.first_seen:
            timestamps.append(_ensure_utc(al_obj.first_seen) or datetime.now(UTC))
        if al_obj.last_seen:
            timestamps.append(_ensure_utc(al_obj.last_seen) or datetime.now(UTC))
    elif anchor.anchor_type == InvestigationAnchorType.INDICATOR:
        ind_obj: Indicator = resolved_context["indicator"]
        if ind_obj.first_seen_at:
            timestamps.append(_ensure_utc(ind_obj.first_seen_at) or datetime.now(UTC))
        if ind_obj.last_seen_at:
            timestamps.append(_ensure_utc(ind_obj.last_seen_at) or datetime.now(UTC))

    earliest = min(timestamps) if timestamps else None
    latest = max(timestamps) if timestamps else None

    return InvestigationSummary(
        event_count=event_count,
        alert_count=alert_count,
        incident_count=incident_count,
        indicator_count=indicator_count,
        first_seen=earliest,
        last_seen=latest,
        unique_source_ips=uniq_src or 0,
        unique_destination_ips=uniq_dst or 0,
        unique_usernames=uniq_users or 0,
    )


# ==============================================================================
# Unified Investigation Timeline Engine
# ==============================================================================


async def get_investigation_timeline(
    db: AsyncSession,
    anchor: InvestigationAnchor,
    resolved_context: dict[str, Any] | None = None,
    page: int = 1,
    limit: int = 50,
) -> InvestigationTimelineResponse:
    """Generate a deterministic, unified multi-entity investigation timeline.

    Aggregates events, alerts, incidents, notes, indicators, and threat intelligence
    with deterministic secondary and tertiary tie-breaking on identical timestamps.
    """
    limit = max(1, min(limit, 500))
    offset = max(0, (page - 1) * limit)

    if resolved_context is None:
        _, resolved_context = await resolve_investigation_anchor(
            db,
            anchor.anchor_type,
            anchor.anchor_value,
            anchor.start_time,
            anchor.end_time,
            anchor.window_seconds,
        )

    entries: list[InvestigationTimelineEntry] = []

    # 1. Fetch Events (bounded up to 500 for timeline compilation)
    events, _ = await get_correlated_events(db, anchor, resolved_context, page=1, limit=500)
    for e in events:
        entries.append(
            InvestigationTimelineEntry(
                id=f"event:{e.id}",
                entity_type="EVENT",
                entity_id=str(e.id),
                timestamp=e.timestamp,
                occurred_at=e.timestamp,
                action_at=None,
                title=f"Event: {e.event_type} ({e.action})",
                severity=e.severity,
                details={
                    "source": e.source,
                    "source_ip": e.source_ip,
                    "destination_ip": e.destination_ip,
                    "username": e.username,
                    "outcome": e.outcome,
                },
            )
        )

    # 2. Fetch Alerts (bounded up to 200)
    alerts, _ = await get_correlated_alerts(db, anchor, resolved_context, page=1, limit=200)
    for a in alerts:
        entries.append(
            InvestigationTimelineEntry(
                id=f"alert:{a.id}",
                entity_type="ALERT",
                entity_id=str(a.id),
                timestamp=a.created_at,
                occurred_at=a.first_seen,
                action_at=a.created_at,
                title=f"Alert: {a.title}",
                severity=a.severity,
                details={
                    "rule_id": a.rule_id,
                    "status": a.status,
                    "correlation_key": a.correlation_key,
                    "observed_count": a.observed_count,
                },
            )
        )

    # 3. Fetch Incidents (bounded up to 100)
    incidents, _ = await get_correlated_incidents(db, anchor, resolved_context, page=1, limit=100)
    for i in incidents:
        entries.append(
            InvestigationTimelineEntry(
                id=f"incident:{i.id}",
                entity_type="INCIDENT",
                entity_id=str(i.id),
                timestamp=i.created_at,
                occurred_at=None,
                action_at=i.created_at,
                title=f"Incident: {i.title} ({i.incident_id})",
                severity=i.severity,
                details={
                    "incident_id": i.incident_id,
                    "status": i.status,
                    "priority": i.priority,
                },
            )
        )

        # Also include incident investigation notes if this incident is resolved in context
        notes_res = await db.execute(
            select(IncidentNote)
            .options(selectinload(IncidentNote.author))
            .where(IncidentNote.incident_id == i.id)
            .order_by(IncidentNote.created_at.asc())
        )
        notes = notes_res.scalars().all()
        for n in notes:
            n_ts = _ensure_utc(n.created_at) or datetime.now(UTC)
            author_name = n.author.username if n.author else "SYSTEM"
            entries.append(
                InvestigationTimelineEntry(
                    id=f"note:{n.id}",
                    entity_type="NOTE",
                    entity_id=str(n.id),
                    timestamp=n_ts,
                    occurred_at=None,
                    action_at=n_ts,
                    title=f"Investigation Note by {author_name}",
                    severity=None,
                    details={
                        "incident_id": i.incident_id,
                        "author": author_name,
                        "content": n.content,
                    },
                )
            )

    # 4. Fetch Indicators (bounded up to 200)
    indicators, _ = await get_correlated_indicators(db, anchor, resolved_context, page=1, limit=200)
    for ind in indicators:
        entries.append(
            InvestigationTimelineEntry(
                id=f"indicator:{ind.id}",
                entity_type="INDICATOR",
                entity_id=str(ind.id),
                timestamp=ind.first_seen_at,
                occurred_at=ind.first_seen_at,
                action_at=ind.last_seen_at,
                title=f"Indicator Observed: {ind.type} {ind.normalized_value}",
                severity=ind.highest_severity,
                details={
                    "type": ind.type,
                    "status": ind.status,
                    "sightings_count": ind.sightings_count,
                    "is_threat": ind.is_threat,
                    "threat_sources": ind.threat_sources,
                },
            )
        )

    # 5. Deterministic sorting:
    # Primary: timestamp descending
    # Secondary: entity_type ascending
    # Tertiary: entity_id ascending
    entries.sort(
        key=lambda entry: (
            entry.timestamp,
            entry.entity_type,
            entry.entity_id,
        ),
        reverse=True,
    )

    total_entries = len(entries)
    paginated_entries = entries[offset : offset + limit]

    return InvestigationTimelineResponse(
        anchor=anchor,
        total_entries=total_entries,
        page=page,
        limit=limit,
        entries=paginated_entries,
    )


# ==============================================================================
# Comprehensive Investigation Context
# ==============================================================================


async def get_investigation_context(
    db: AsyncSession,
    anchor: InvestigationAnchor,
) -> InvestigationContextResponse:
    """Generate a comprehensive 360-degree investigation view for an anchor entity."""
    anchor, resolved_context = await resolve_investigation_anchor(
        db,
        anchor.anchor_type,
        anchor.anchor_value,
        anchor.start_time,
        anchor.end_time,
        anchor.window_seconds,
    )

    summary = await get_investigation_summary(db, anchor, resolved_context)
    incidents, _ = await get_correlated_incidents(db, anchor, resolved_context, page=1, limit=20)
    alerts, _ = await get_correlated_alerts(db, anchor, resolved_context, page=1, limit=20)
    events, _ = await get_correlated_events(db, anchor, resolved_context, page=1, limit=50)
    indicators, _ = await get_correlated_indicators(db, anchor, resolved_context, page=1, limit=50)
    timeline = await get_investigation_timeline(db, anchor, resolved_context, page=1, limit=20)

    return InvestigationContextResponse(
        anchor=anchor,
        summary=summary,
        correlated_incidents=incidents,
        correlated_alerts=alerts,
        correlated_events=events,
        correlated_indicators=indicators,
        recent_timeline=timeline.entries,
    )

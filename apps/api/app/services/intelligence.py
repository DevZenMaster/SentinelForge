"""Threat Intelligence and Indicator of Compromise (IOC) Enrichment Service.

Coordinates indicator normalization, persistent threat intelligence correlation,
evidence association, and deterministic event enrichment with auditability.
"""

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alert import Alert, AlertEvent
from app.models.event import Event
from app.models.incident import Incident, IncidentAlert, IncidentEvent
from app.models.indicator import (
    Indicator,
    IndicatorEvent,
    IndicatorStatus,
    IndicatorType,
    ThreatClassification,
    ThreatIntelligence,
)
from app.schemas.indicator import (
    EventEnrichmentResponse,
    IndicatorDetailResponse,
    IndicatorEnrichmentDetail,
    IndicatorEventResponse,
    IndicatorResponse,
    ThreatIntelligenceCreateRequest,
    ThreatIntelligenceResponse,
    ThreatIntelligenceUpdateRequest,
)
from app.services.auth import record_audit_log
from app.services.ioc_normalizer import (
    ExtractedIOC,
    extract_iocs_from_event,
    normalize_ioc,
)


class IndicatorNotFoundError(Exception):
    """Raised when an indicator cannot be found."""


class IndicatorConflictError(Exception):
    """Raised when an indicator with identical type and normalized value already exists."""


class ThreatIntelligenceNotFoundError(Exception):
    """Raised when a threat intelligence record cannot be found."""


class ThreatIntelligenceConflictError(Exception):
    """Raised when a threat intelligence record for the same source and reference exists."""


class IntelligenceValidationError(Exception):
    """Raised when intelligence parameters or relationships fail validation."""


class TargetNotFoundError(Exception):
    """Raised when an event, alert, or incident target cannot be found."""


def _str_val(val: Any) -> str:
    if hasattr(val, "value"):
        return str(val.value)
    return str(val)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def is_threat_intel_expired(intel: ThreatIntelligence, now: datetime | None = None) -> bool:
    """Check if threat intelligence record has passed its TTL expiration timestamp."""
    if intel.expires_at is None:
        return False
    current_time = now or datetime.now(UTC)
    expiry = _ensure_utc(intel.expires_at)
    if expiry is None:
        return False
    return expiry <= current_time


def format_threat_intelligence_response(
    intel: ThreatIntelligence, now: datetime | None = None
) -> ThreatIntelligenceResponse:
    """Format ORM ThreatIntelligence instance to Pydantic response model."""
    current_time = now or datetime.now(UTC)
    expired = is_threat_intel_expired(intel, current_time)
    return ThreatIntelligenceResponse(
        id=intel.id,
        indicator_id=intel.indicator_id,
        source=intel.source,
        threat_classification=intel.threat_classification,
        severity=intel.severity,
        confidence=intel.confidence,
        source_reference=intel.source_reference,
        description=intel.description,
        mitre_tactics=intel.mitre_tactics,
        mitre_techniques=intel.mitre_techniques,
        tags=intel.tags,
        threat_actor=intel.threat_actor,
        campaign=intel.campaign,
        raw_data=intel.raw_data,
        first_seen=_ensure_utc(intel.first_seen) or current_time,
        last_seen=_ensure_utc(intel.last_seen) or current_time,
        expires_at=_ensure_utc(intel.expires_at),
        is_expired=expired,
        created_at=_ensure_utc(intel.created_at) or current_time,
        updated_at=_ensure_utc(intel.updated_at) or current_time,
    )


def format_indicator_response(
    indicator: Indicator, now: datetime | None = None
) -> IndicatorResponse:
    """Format ORM Indicator to standard response."""
    current_time = now or datetime.now(UTC)
    intel_responses = [
        format_threat_intelligence_response(ti, current_time)
        for ti in (indicator.threat_intelligences or [])
    ]
    return IndicatorResponse(
        id=indicator.id,
        type=indicator.type,
        value=indicator.value,
        normalized_value=indicator.normalized_value,
        status=indicator.status,
        description=indicator.description,
        first_seen_at=_ensure_utc(indicator.first_seen_at) or current_time,
        last_seen_at=_ensure_utc(indicator.last_seen_at) or current_time,
        sightings_count=indicator.sightings_count,
        created_at=_ensure_utc(indicator.created_at) or current_time,
        updated_at=_ensure_utc(indicator.updated_at) or current_time,
        threat_intelligences=intel_responses,
    )


def format_indicator_detail_response(
    indicator: Indicator, now: datetime | None = None
) -> IndicatorDetailResponse:
    """Format ORM Indicator to detailed response including linked events."""
    current_time = now or datetime.now(UTC)
    intel_responses = [
        format_threat_intelligence_response(ti, current_time)
        for ti in (indicator.threat_intelligences or [])
    ]
    event_links = [
        IndicatorEventResponse(
            id=ie.id,
            indicator_id=ie.indicator_id,
            event_id=ie.event_id,
            extracted_from_field=ie.extracted_from_field,
            raw_value=ie.raw_value,
            created_at=_ensure_utc(ie.created_at) or current_time,
        )
        for ie in (indicator.indicator_events or [])
    ]
    return IndicatorDetailResponse(
        id=indicator.id,
        type=indicator.type,
        value=indicator.value,
        normalized_value=indicator.normalized_value,
        status=indicator.status,
        description=indicator.description,
        first_seen_at=_ensure_utc(indicator.first_seen_at) or current_time,
        last_seen_at=_ensure_utc(indicator.last_seen_at) or current_time,
        sightings_count=indicator.sightings_count,
        created_at=_ensure_utc(indicator.created_at) or current_time,
        updated_at=_ensure_utc(indicator.updated_at) or current_time,
        threat_intelligences=intel_responses,
        events=event_links,
    )


async def create_or_get_indicator(
    db: AsyncSession,
    type: IndicatorType,
    value: str,
    description: str | None = None,
    status: IndicatorStatus = IndicatorStatus.ACTIVE,
    actor_user_id: uuid.UUID | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[Indicator, bool]:
    """Retrieve existing indicator or create new one in a concurrency-safe manner.

    Returns tuple (Indicator, was_created).
    """
    norm_val = normalize_ioc(type, value)

    # Check existing
    result = await db.execute(
        select(Indicator)
        .options(selectinload(Indicator.threat_intelligences))
        .where(Indicator.type == type, Indicator.normalized_value == norm_val)
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        return existing, False

    now = datetime.now(UTC)
    indicator = Indicator(
        type=type,
        value=value,
        normalized_value=norm_val,
        status=status,
        description=description,
        first_seen_at=now,
        last_seen_at=now,
        sightings_count=0,
    )

    try:
        async with db.begin_nested():
            db.add(indicator)
            await db.flush()
    except IntegrityError:
        # Concurrent insert won race; query existing row
        for _ in range(10):
            res = await db.execute(
                select(Indicator)
                .options(selectinload(Indicator.threat_intelligences))
                .where(Indicator.type == type, Indicator.normalized_value == norm_val)
            )
            existing = res.scalar_one_or_none()
            if existing is not None:
                return existing, False
            await asyncio.sleep(0.05)
        # Fallback if still not visible
        res = await db.execute(
            select(Indicator)
            .options(selectinload(Indicator.threat_intelligences))
            .where(Indicator.type == type, Indicator.normalized_value == norm_val)
        )
        return res.scalar_one(), False

    # Record audit log for manual or system registration
    await record_audit_log(
        db=db,
        action="INDICATOR_CREATED",
        actor_user_id=actor_user_id,
        resource_type="indicator",
        resource_id=str(indicator.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={
            "type": _str_val(indicator.type),
            "value": indicator.value,
            "normalized_value": indicator.normalized_value,
            "status": _str_val(indicator.status),
        },
    )

    return indicator, True


async def get_indicator_by_id(db: AsyncSession, indicator_id: uuid.UUID) -> IndicatorDetailResponse:
    """Retrieve single indicator with all threat intelligence and event links."""
    result = await db.execute(
        select(Indicator)
        .options(
            selectinload(Indicator.threat_intelligences),
            selectinload(Indicator.indicator_events),
        )
        .where(Indicator.id == indicator_id)
    )
    indicator = result.scalar_one_or_none()
    if not indicator:
        raise IndicatorNotFoundError(f"Indicator '{indicator_id}' not found")
    return format_indicator_detail_response(indicator)


async def list_indicators(
    db: AsyncSession,
    type: IndicatorType | None = None,
    status: IndicatorStatus | None = None,
    search: str | None = None,
    page: int = 1,
    limit: int = 50,
) -> tuple[list[IndicatorResponse], int]:
    """List paginated indicators with optional filtering."""
    query = select(Indicator).options(selectinload(Indicator.threat_intelligences))
    count_query = select(func.count(Indicator.id))

    filters = []
    if type is not None:
        filters.append(Indicator.type == type)
    if status is not None:
        filters.append(Indicator.status == status)
    if search:
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                Indicator.value.ilike(pattern),
                Indicator.normalized_value.ilike(pattern),
                Indicator.description.ilike(pattern),
            )
        )

    if filters:
        query = query.where(*filters)
        count_query = count_query.where(*filters)

    total_res = await db.execute(count_query)
    total = total_res.scalar_one()

    offset = (page - 1) * limit
    query = query.order_by(Indicator.last_seen_at.desc()).offset(offset).limit(limit)
    rows = await db.execute(query)
    indicators = rows.scalars().all()

    items = [format_indicator_response(ind) for ind in indicators]
    return items, total


async def update_indicator_status(
    db: AsyncSession,
    indicator_id: uuid.UUID,
    new_status: IndicatorStatus | None = None,
    new_description: str | None = None,
    actor_user_id: uuid.UUID | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> IndicatorResponse:
    """Update lifecycle status or description of an indicator."""
    result = await db.execute(
        select(Indicator)
        .options(selectinload(Indicator.threat_intelligences))
        .where(Indicator.id == indicator_id)
    )
    indicator = result.scalar_one_or_none()
    if not indicator:
        raise IndicatorNotFoundError(f"Indicator '{indicator_id}' not found")

    old_val = {"status": _str_val(indicator.status), "description": indicator.description}
    if new_status is not None:
        indicator.status = new_status
    if new_description is not None:
        indicator.description = new_description

    new_val = {"status": _str_val(indicator.status), "description": indicator.description}

    await db.flush()

    await record_audit_log(
        db=db,
        action="INDICATOR_UPDATED",
        actor_user_id=actor_user_id,
        resource_type="indicator",
        resource_id=str(indicator.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_val,
        new_value=new_val,
    )

    return format_indicator_response(indicator)


async def add_threat_intelligence(
    db: AsyncSession,
    indicator_id: uuid.UUID,
    payload: ThreatIntelligenceCreateRequest,
    actor_user_id: uuid.UUID | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> ThreatIntelligenceResponse:
    """Attach threat intelligence provenance to an indicator."""
    result = await db.execute(select(Indicator).where(Indicator.id == indicator_id))
    indicator = result.scalar_one_or_none()
    if not indicator:
        raise IndicatorNotFoundError(f"Indicator '{indicator_id}' not found")

    # Check for duplicate source reference on this indicator
    if payload.source_reference is not None:
        dup_res = await db.execute(
            select(ThreatIntelligence).where(
                ThreatIntelligence.indicator_id == indicator_id,
                ThreatIntelligence.source == payload.source,
                ThreatIntelligence.source_reference == payload.source_reference,
            )
        )
        if dup_res.scalar_one_or_none() is not None:
            raise ThreatIntelligenceConflictError(
                f"Threat intelligence record for source '{payload.source}' "
                f"and reference '{payload.source_reference}' already exists for this indicator"
            )

    now = datetime.now(UTC)
    intel = ThreatIntelligence(
        indicator_id=indicator_id,
        source=payload.source,
        threat_classification=payload.threat_classification,
        severity=payload.severity,
        confidence=payload.confidence,
        source_reference=payload.source_reference,
        description=payload.description,
        mitre_tactics=payload.mitre_tactics,
        mitre_techniques=payload.mitre_techniques,
        tags=payload.tags,
        threat_actor=payload.threat_actor,
        campaign=payload.campaign,
        raw_data=payload.raw_data,
        first_seen=now,
        last_seen=now,
        expires_at=payload.expires_at,
    )

    try:
        async with db.begin_nested():
            db.add(intel)
            await db.flush()
    except IntegrityError as err:
        raise ThreatIntelligenceConflictError(
            f"Failed to persist threat intelligence: duplicate record for source reference: {err}"
        ) from err

    await record_audit_log(
        db=db,
        action="INTELLIGENCE_CREATED",
        actor_user_id=actor_user_id,
        resource_type="threat_intelligence",
        resource_id=str(intel.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={
            "indicator_id": str(indicator_id),
            "source": intel.source,
            "threat_classification": _str_val(intel.threat_classification),
            "severity": _str_val(intel.severity),
            "confidence": intel.confidence,
            "source_reference": intel.source_reference,
        },
    )

    return format_threat_intelligence_response(intel)


async def update_threat_intelligence(
    db: AsyncSession,
    intel_id: uuid.UUID,
    payload: ThreatIntelligenceUpdateRequest,
    actor_user_id: uuid.UUID | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> ThreatIntelligenceResponse:
    """Update existing threat intelligence record."""
    result = await db.execute(select(ThreatIntelligence).where(ThreatIntelligence.id == intel_id))
    intel = result.scalar_one_or_none()
    if not intel:
        raise ThreatIntelligenceNotFoundError(f"Threat intelligence '{intel_id}' not found")

    old_val = {
        "threat_classification": _str_val(intel.threat_classification),
        "severity": _str_val(intel.severity),
        "confidence": intel.confidence,
        "source_reference": intel.source_reference,
    }

    if payload.threat_classification is not None:
        intel.threat_classification = payload.threat_classification
    if payload.severity is not None:
        intel.severity = payload.severity
    if payload.confidence is not None:
        intel.confidence = payload.confidence
    if payload.source_reference is not None:
        intel.source_reference = payload.source_reference
    if payload.description is not None:
        intel.description = payload.description
    if payload.mitre_tactics is not None:
        intel.mitre_tactics = payload.mitre_tactics
    if payload.mitre_techniques is not None:
        intel.mitre_techniques = payload.mitre_techniques
    if payload.tags is not None:
        intel.tags = payload.tags
    if payload.threat_actor is not None:
        intel.threat_actor = payload.threat_actor
    if payload.campaign is not None:
        intel.campaign = payload.campaign
    if payload.raw_data is not None:
        intel.raw_data = payload.raw_data
    if payload.expires_at is not None:
        intel.expires_at = payload.expires_at

    intel.last_seen = datetime.now(UTC)
    await db.flush()

    new_val = {
        "threat_classification": _str_val(intel.threat_classification),
        "severity": _str_val(intel.severity),
        "confidence": intel.confidence,
        "source_reference": intel.source_reference,
    }

    await record_audit_log(
        db=db,
        action="INTELLIGENCE_UPDATED",
        actor_user_id=actor_user_id,
        resource_type="threat_intelligence",
        resource_id=str(intel.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_val,
        new_value=new_val,
    )

    return format_threat_intelligence_response(intel)


async def delete_threat_intelligence(
    db: AsyncSession,
    intel_id: uuid.UUID,
    actor_user_id: uuid.UUID | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Delete a threat intelligence record."""
    result = await db.execute(select(ThreatIntelligence).where(ThreatIntelligence.id == intel_id))
    intel = result.scalar_one_or_none()
    if not intel:
        raise ThreatIntelligenceNotFoundError(f"Threat intelligence '{intel_id}' not found")

    old_val = {
        "indicator_id": str(intel.indicator_id),
        "source": intel.source,
        "source_reference": intel.source_reference,
    }

    await db.delete(intel)
    await db.flush()

    await record_audit_log(
        db=db,
        action="INTELLIGENCE_DELETED",
        actor_user_id=actor_user_id,
        resource_type="threat_intelligence",
        resource_id=str(intel_id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_val,
    )


async def enrich_event(
    db: AsyncSession,
    event_id: uuid.UUID,
    actor_user_id: uuid.UUID | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> EventEnrichmentResponse:
    """Extract IOCs from event, associate evidence, correlate threat intel, and emit audit record.

    Guarantees:
    - Raw event payload, timestamp, and source fields are 100% unmutated.
    - Idempotent: multiple runs do not generate duplicate links or inflate sightings erroneously.
    - Concurrency-safe indicator creation.
    """
    event_res = await db.execute(select(Event).where(Event.id == event_id))
    event = event_res.scalar_one_or_none()
    if not event:
        raise TargetNotFoundError(f"Event '{event_id}' not found")

    extracted_iocs: list[ExtractedIOC] = extract_iocs_from_event(event)
    now = datetime.now(UTC)

    enrichment_details: list[IndicatorEnrichmentDetail] = []
    threat_count = 0
    sighted_in_this_run: set[uuid.UUID] = set()

    for extracted in extracted_iocs:
        # Create or fetch indicator
        indicator, was_created = await create_or_get_indicator(
            db=db,
            type=extracted.type,
            value=extracted.raw_value,
            actor_user_id=actor_user_id,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )

        # Check if already linked to this event for this specific field
        link_query = select(IndicatorEvent).where(
            IndicatorEvent.indicator_id == indicator.id,
            IndicatorEvent.event_id == event.id,
            IndicatorEvent.extracted_from_field == extracted.extracted_from_field,
        )
        existing_link = (await db.execute(link_query)).scalar_one_or_none()

        # Check if indicator was already sighted in this event across any field
        existing_sighting_query = (
            select(IndicatorEvent.id)
            .where(
                IndicatorEvent.indicator_id == indicator.id,
                IndicatorEvent.event_id == event.id,
            )
            .limit(1)
        )
        already_sighted = (
            await db.execute(existing_sighting_query)
        ).scalar_one_or_none() is not None

        if existing_link is None:
            # Create link
            link = IndicatorEvent(
                indicator_id=indicator.id,
                event_id=event.id,
                extracted_from_field=extracted.extracted_from_field,
                raw_value=extracted.raw_value,
            )
            try:
                async with db.begin_nested():
                    db.add(link)
                    await db.flush()
                # Update sighting metadata on indicator once per event
                if not already_sighted and indicator.id not in sighted_in_this_run:
                    indicator.sightings_count += 1
                    sighted_in_this_run.add(indicator.id)
                ev_time = _ensure_utc(event.timestamp) or now
                ind_time = _ensure_utc(indicator.last_seen_at) or now
                if ev_time > ind_time:
                    indicator.last_seen_at = ev_time
            except IntegrityError:
                # Concurrent link insert won race
                pass

        # Load fresh threat intelligence records for indicator
        intel_res = await db.execute(
            select(ThreatIntelligence).where(ThreatIntelligence.indicator_id == indicator.id)
        )
        intel_records = intel_res.scalars().all()

        # Format intel records and determine if active threat
        formatted_intel = [format_threat_intelligence_response(ti, now) for ti in intel_records]
        active_threats = [
            ti
            for ti in formatted_intel
            if not ti.is_expired
            and ti.threat_classification
            in {ThreatClassification.MALICIOUS, ThreatClassification.SUSPICIOUS}
        ]
        is_threat = len(active_threats) > 0 and indicator.status in {
            IndicatorStatus.ACTIVE,
            IndicatorStatus.WATCHLIST,
        }

        if is_threat:
            threat_count += 1

        enrichment_details.append(
            IndicatorEnrichmentDetail(
                indicator_id=indicator.id,
                type=indicator.type,
                value=indicator.value,
                normalized_value=indicator.normalized_value,
                status=indicator.status,
                extracted_from_field=extracted.extracted_from_field,
                raw_value=extracted.raw_value,
                is_threat=is_threat,
                threat_intelligences=formatted_intel,
            )
        )

    await db.flush()

    # Record audit log for enrichment event
    await record_audit_log(
        db=db,
        action="EVENT_ENRICHED",
        actor_user_id=actor_user_id,
        resource_type="event",
        resource_id=str(event_id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={
            "total_indicators": len(enrichment_details),
            "threat_count": threat_count,
        },
    )

    return EventEnrichmentResponse(
        event_id=event.id,
        total_indicators=len(enrichment_details),
        threat_count=threat_count,
        enriched_at=now,
        indicators=enrichment_details,
    )


async def get_event_indicators(
    db: AsyncSession, event_id: uuid.UUID
) -> list[IndicatorEnrichmentDetail]:
    """Retrieve all indicators linked to an event with their threat intelligence."""
    event_res = await db.execute(select(Event).where(Event.id == event_id))
    if not event_res.scalar_one_or_none():
        raise TargetNotFoundError(f"Event '{event_id}' not found")

    links_res = await db.execute(
        select(IndicatorEvent)
        .options(
            selectinload(IndicatorEvent.indicator).selectinload(Indicator.threat_intelligences)
        )
        .where(IndicatorEvent.event_id == event_id)
        .order_by(IndicatorEvent.created_at.asc())
    )
    links = links_res.scalars().all()

    now = datetime.now(UTC)
    results: list[IndicatorEnrichmentDetail] = []
    for link in links:
        ind = link.indicator
        formatted_intel = [
            format_threat_intelligence_response(ti, now) for ti in ind.threat_intelligences
        ]
        active_threats = [
            ti
            for ti in formatted_intel
            if not ti.is_expired
            and ti.threat_classification
            in {ThreatClassification.MALICIOUS, ThreatClassification.SUSPICIOUS}
        ]
        is_threat = len(active_threats) > 0 and ind.status in {
            IndicatorStatus.ACTIVE,
            IndicatorStatus.WATCHLIST,
        }
        results.append(
            IndicatorEnrichmentDetail(
                indicator_id=ind.id,
                type=ind.type,
                value=ind.value,
                normalized_value=ind.normalized_value,
                status=ind.status,
                extracted_from_field=link.extracted_from_field,
                raw_value=link.raw_value,
                is_threat=is_threat,
                threat_intelligences=formatted_intel,
            )
        )
    return results


async def get_alert_indicators(
    db: AsyncSession, alert_id: uuid.UUID
) -> list[IndicatorEnrichmentDetail]:
    """Retrieve all indicators associated with an alert via its evidence events."""
    alert_res = await db.execute(select(Alert).where(Alert.id == alert_id))
    if not alert_res.scalar_one_or_none():
        raise TargetNotFoundError(f"Alert '{alert_id}' not found")

    # Get event IDs for this alert
    event_ids_res = await db.execute(
        select(AlertEvent.event_id).where(AlertEvent.alert_id == alert_id)
    )
    event_ids = event_ids_res.scalars().all()
    if not event_ids:
        return []

    # Get all indicator links for these events
    links_res = await db.execute(
        select(IndicatorEvent)
        .options(
            selectinload(IndicatorEvent.indicator).selectinload(Indicator.threat_intelligences)
        )
        .where(IndicatorEvent.event_id.in_(event_ids))
        .order_by(IndicatorEvent.created_at.asc())
    )
    links = links_res.scalars().all()

    now = datetime.now(UTC)
    results: list[IndicatorEnrichmentDetail] = []
    seen_keys: set[tuple[uuid.UUID, str]] = set()

    for link in links:
        key = (link.indicator_id, link.extracted_from_field)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        ind = link.indicator
        formatted_intel = [
            format_threat_intelligence_response(ti, now) for ti in ind.threat_intelligences
        ]
        active_threats = [
            ti
            for ti in formatted_intel
            if not ti.is_expired
            and ti.threat_classification
            in {ThreatClassification.MALICIOUS, ThreatClassification.SUSPICIOUS}
        ]
        is_threat = len(active_threats) > 0 and ind.status in {
            IndicatorStatus.ACTIVE,
            IndicatorStatus.WATCHLIST,
        }
        results.append(
            IndicatorEnrichmentDetail(
                indicator_id=ind.id,
                type=ind.type,
                value=ind.value,
                normalized_value=ind.normalized_value,
                status=ind.status,
                extracted_from_field=link.extracted_from_field,
                raw_value=link.raw_value,
                is_threat=is_threat,
                threat_intelligences=formatted_intel,
            )
        )
    return results


async def get_incident_indicators(
    db: AsyncSession, incident_identifier: str
) -> list[IndicatorEnrichmentDetail]:
    """Retrieve all indicators linked to an incident across direct events and alert events."""
    # Lookup incident by UUID or human-readable incident_id (INC-YYYYMMDD-XXXX)
    incident_query = select(Incident)
    try:
        inc_uuid = uuid.UUID(incident_identifier)
        incident_query = incident_query.where(Incident.id == inc_uuid)
    except ValueError:
        incident_query = incident_query.where(Incident.incident_id == incident_identifier)

    incident_res = await db.execute(incident_query)
    incident = incident_res.scalar_one_or_none()
    if not incident:
        raise TargetNotFoundError(f"Incident '{incident_identifier}' not found")

    # 1. Direct event IDs from IncidentEvent
    direct_event_ids_res = await db.execute(
        select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
    )
    direct_event_ids = set(direct_event_ids_res.scalars().all())

    # 2. Alert-associated event IDs from IncidentAlert -> AlertEvent
    alert_ids_res = await db.execute(
        select(IncidentAlert.alert_id).where(IncidentAlert.incident_id == incident.id)
    )
    alert_ids = alert_ids_res.scalars().all()

    alert_event_ids: set[uuid.UUID] = set()
    if alert_ids:
        alert_events_res = await db.execute(
            select(AlertEvent.event_id).where(AlertEvent.alert_id.in_(alert_ids))
        )
        alert_event_ids = set(alert_events_res.scalars().all())

    all_event_ids = direct_event_ids.union(alert_event_ids)
    if not all_event_ids:
        return []

    # Get all indicator links for these events
    links_res = await db.execute(
        select(IndicatorEvent)
        .options(
            selectinload(IndicatorEvent.indicator).selectinload(Indicator.threat_intelligences)
        )
        .where(IndicatorEvent.event_id.in_(all_event_ids))
        .order_by(IndicatorEvent.created_at.asc())
    )
    links = links_res.scalars().all()

    now = datetime.now(UTC)
    results: list[IndicatorEnrichmentDetail] = []
    seen_keys: set[tuple[uuid.UUID, str]] = set()

    for link in links:
        key = (link.indicator_id, link.extracted_from_field)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        ind = link.indicator
        formatted_intel = [
            format_threat_intelligence_response(ti, now) for ti in ind.threat_intelligences
        ]
        active_threats = [
            ti
            for ti in formatted_intel
            if not ti.is_expired
            and ti.threat_classification
            in {ThreatClassification.MALICIOUS, ThreatClassification.SUSPICIOUS}
        ]
        is_threat = len(active_threats) > 0 and ind.status in {
            IndicatorStatus.ACTIVE,
            IndicatorStatus.WATCHLIST,
        }
        results.append(
            IndicatorEnrichmentDetail(
                indicator_id=ind.id,
                type=ind.type,
                value=ind.value,
                normalized_value=ind.normalized_value,
                status=ind.status,
                extracted_from_field=link.extracted_from_field,
                raw_value=link.raw_value,
                is_threat=is_threat,
                threat_intelligences=formatted_intel,
            )
        )
    return results

"""Incident Management and Investigation Service (Phase 6).

Implements case management, strict lifecycle state transitions, analyst assignment,
alert correlation, direct forensic event evidence linkage, notes management,
and unified chronological timeline aggregation.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.event import Event
from app.models.incident import Incident, IncidentAlert, IncidentEvent, IncidentNote
from app.schemas.incident import (
    IncidentAlertSummaryResponse,
    IncidentCreateRequest,
    IncidentDetailResponse,
    IncidentEventSummaryResponse,
    IncidentNoteResponse,
    IncidentPriority,
    IncidentResolutionCategory,
    IncidentResponse,
    IncidentSeverity,
    IncidentStatus,
    IncidentStatusTransitionRequest,
    IncidentTimelineEntry,
    IncidentUpdateRequest,
    TimelineEntryType,
    UserSummaryResponse,
)
from app.services.auth import record_audit_log
from app.services.notifications import emit_notification_event

logger = logging.getLogger("sentinelforge.incident")
_incident_create_lock = asyncio.Lock()


async def _safe_notify_incident(
    db: AsyncSession,
    incident: Incident,
    event_type: str,
) -> None:
    """Safely emit incident notification event without impacting core transaction."""
    try:
        await emit_notification_event(
            db=db,
            event_type=event_type,
            source_resource_type="incident",
            source_resource_id=str(incident.id),
            payload_data={
                "id": str(incident.id),
                "incident_id": incident.incident_id,
                "title": incident.title,
                "severity": incident.severity,
                "priority": incident.priority,
                "status": incident.status,
            },
        )
    except Exception:
        logger.warning(f"Failed to emit notification for {event_type}", exc_info=True)


# ==============================================================================
# Domain Exceptions
# ==============================================================================


class IncidentNotFoundError(Exception):
    """Raised when an incident case is not found by ID."""


class AlertNotFoundError(Exception):
    """Raised when an alert to be linked/unlinked is not found."""


class EventNotFoundError(Exception):
    """Raised when an event to be linked/unlinked is not found."""


class UserNotFoundError(Exception):
    """Raised when an analyst assignment targets a non-existent or inactive user."""


class DuplicateAttachmentError(Exception):
    """Raised when an alert or event is already linked to an incident."""


class InvalidStatusTransitionError(Exception):
    """Raised when an incident status change violates the lifecycle state machine."""


class IncidentValidationError(Exception):
    """Raised when incident parameters fail domain validation."""


# ==============================================================================
# State Machine Definitions
# ==============================================================================

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "OPEN": {"IN_PROGRESS"},
    "IN_PROGRESS": {"RESOLVED", "OPEN"},
    "RESOLVED": {"CLOSED", "REOPENED"},
    "CLOSED": {"REOPENED"},
    "REOPENED": {"IN_PROGRESS", "RESOLVED"},
    # Legacy alias support
    "INVESTIGATING": {"IN_PROGRESS", "RESOLVED"},
}


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _require_utc(dt: datetime) -> datetime:
    """Ensure non-null datetime is timezone-aware UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _user_summary(user: User | None) -> UserSummaryResponse | None:
    """Helper converting User ORM model to UserSummaryResponse."""
    if not user:
        return None
    return UserSummaryResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
    )


# ==============================================================================
# Identifier Generation
# ==============================================================================


async def generate_incident_id(db: AsyncSession, year: int | None = None) -> str:
    """Generate sequential, human-readable incident ticket ID (e.g. INC-2026-000001).

    In PostgreSQL, serializes generation per year via transactional advisory locking.
    Extracts the highest existing numeric sequence suffix, ignoring non-numeric fallback IDs.
    """
    if year is None:
        year = datetime.now(UTC).year
    prefix = f"INC-{year}-"

    # In PostgreSQL, acquire transaction advisory lock to serialize generation per year
    if db.bind and db.bind.dialect.name == "postgresql":
        await db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": f"incident_seq_{year}"},
        )

    stmt = (
        select(Incident.incident_id)
        .where(Incident.incident_id.like(f"{prefix}%"))
        .order_by(Incident.incident_id.desc())
    )
    result = await db.execute(stmt)
    existing_ids = result.scalars().all()

    max_num = 0
    for inc_id in existing_ids:
        if inc_id.startswith(prefix):
            suffix = inc_id[len(prefix) :]
            if suffix.isdigit():
                val = int(suffix)
                if val > max_num:
                    max_num = val

    seq_num = max_num + 1
    return f"{prefix}{seq_num:06d}"


# ==============================================================================
# Incident Operations
# ==============================================================================


async def create_incident(
    db: AsyncSession,
    payload: IncidentCreateRequest,
    created_by_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Incident:
    """Create a new incident case file with optional initial alerts, events, and note."""
    # 1. Validate assigned user if provided
    if payload.assigned_to_user_id:
        user_stmt = select(User).where(
            User.id == payload.assigned_to_user_id, User.is_active.is_(True)
        )
        assigned_user = (await db.execute(user_stmt)).scalar_one_or_none()
        if not assigned_user:
            raise UserNotFoundError(
                f"Assigned user {payload.assigned_to_user_id} not found or inactive"
            )

    # 2. Validate alerts existence if provided
    if payload.alert_ids:
        for alert_id in payload.alert_ids:
            a_stmt = select(Alert).where(Alert.id == alert_id)
            if not (await db.execute(a_stmt)).scalar_one_or_none():
                raise AlertNotFoundError(f"Alert {alert_id} not found")

    # 3. Validate events existence if provided
    if payload.event_ids:
        for event_id in payload.event_ids:
            e_stmt = select(Event).where(Event.id == event_id)
            if not (await db.execute(e_stmt)).scalar_one_or_none():
                raise EventNotFoundError(f"Event {event_id} not found")

    # 4. Generate incident_id with retry on race condition using savepoint
    max_retries = 5
    async with _incident_create_lock:
        for attempt in range(max_retries):
            incident_id = await generate_incident_id(db)
            incident = Incident(
                incident_id=incident_id,
                title=payload.title.strip(),
                description=payload.description.strip(),
                severity=payload.severity.value,
                priority=payload.priority.value,
                status=IncidentStatus.OPEN.value,
                created_by_user_id=created_by_user_id,
                assigned_to_user_id=payload.assigned_to_user_id,
                notes=[],
            )
            try:
                db.add(incident)
                await db.commit()
                break
            except IntegrityError:
                await db.rollback()
                if attempt == max_retries - 1:
                    raise IncidentValidationError(
                        "Failed to generate unique incident ID due to concurrent inserts"
                    ) from None

    # 5. Attach initial alerts
    if payload.alert_ids:
        for alert_id in set(payload.alert_ids):
            db.add(
                IncidentAlert(
                    incident_id=incident.id,
                    alert_id=alert_id,
                    added_by_user_id=created_by_user_id,
                )
            )

    # 6. Attach initial events as evidence
    if payload.event_ids:
        for event_id in set(payload.event_ids):
            db.add(
                IncidentEvent(
                    incident_id=incident.id,
                    event_id=event_id,
                    added_by_user_id=created_by_user_id,
                )
            )

    # 7. Add opening investigation note if provided
    if payload.initial_note:
        db.add(
            IncidentNote(
                incident_id=incident.id,
                author_user_id=created_by_user_id,
                content=payload.initial_note.strip(),
            )
        )

    await db.commit()

    # 8. Audit logging
    assignee_str = str(incident.assigned_to_user_id) if incident.assigned_to_user_id else None
    await record_audit_log(
        db=db,
        action="INCIDENT_CREATED",
        actor_user_id=created_by_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        new_value={
            "incident_id": incident.incident_id,
            "title": incident.title,
            "severity": incident.severity,
            "priority": incident.priority,
            "status": incident.status,
            "assigned_to_user_id": assignee_str,
        },
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    if payload.alert_ids:
        for alert_id in set(payload.alert_ids):
            await record_audit_log(
                db=db,
                action="INCIDENT_ALERT_ATTACHED",
                actor_user_id=created_by_user_id,
                resource_type="incident",
                resource_id=str(incident.id),
                new_value={"alert_id": str(alert_id)},
                request_id=request_id,
                source_ip=source_ip,
                user_agent=user_agent,
            )

    if payload.event_ids:
        for event_id in set(payload.event_ids):
            await record_audit_log(
                db=db,
                action="INCIDENT_EVENT_ATTACHED",
                actor_user_id=created_by_user_id,
                resource_type="incident",
                resource_id=str(incident.id),
                new_value={"event_id": str(event_id)},
                request_id=request_id,
                source_ip=source_ip,
                user_agent=user_agent,
            )

    if payload.initial_note:
        await record_audit_log(
            db=db,
            action="INCIDENT_NOTE_CREATED",
            actor_user_id=created_by_user_id,
            resource_type="incident",
            resource_id=str(incident.id),
            new_value={"content_length": len(payload.initial_note.strip())},
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )

    await _safe_notify_incident(db, incident, "INCIDENT_CREATED")

    return await get_incident_by_identifier(db, str(incident.id))


async def get_incident_by_identifier(
    db: AsyncSession, identifier: str, for_update: bool = False
) -> Incident:
    """Retrieve an incident by either internal UUID or human-readable ticket ID."""
    stmt = select(Incident).options(
        selectinload(Incident.assigned_to_user),
        selectinload(Incident.created_by_user),
        selectinload(Incident.resolved_by_user),
        selectinload(Incident.closed_by_user),
        selectinload(Incident.incident_alerts).selectinload(IncidentAlert.alert),
        selectinload(Incident.incident_alerts).selectinload(IncidentAlert.added_by_user),
        selectinload(Incident.incident_events).selectinload(IncidentEvent.event),
        selectinload(Incident.incident_events).selectinload(IncidentEvent.added_by_user),
        selectinload(Incident.incident_notes).selectinload(IncidentNote.author),
    )

    if for_update:
        stmt = stmt.with_for_update()

    try:
        val_uuid = uuid.UUID(identifier)
        stmt = stmt.where(or_(Incident.id == val_uuid, Incident.incident_id == identifier))
    except ValueError:
        stmt = stmt.where(Incident.incident_id == identifier)

    result = await db.execute(stmt)
    incident = result.scalar_one_or_none()
    if not incident:
        raise IncidentNotFoundError(f"Incident '{identifier}' not found")
    return incident


async def list_incidents(
    db: AsyncSession,
    page: int = 1,
    limit: int = 50,
    status: IncidentStatus | str | None = None,
    severity: IncidentSeverity | str | None = None,
    priority: IncidentPriority | str | None = None,
    assigned_to_user_id: uuid.UUID | None = None,
    created_by_user_id: uuid.UUID | None = None,
    search: str | None = None,
) -> tuple[list[IncidentResponse], int]:
    """Retrieve paginated incidents with filtering and count aggregates."""
    stmt = (
        select(
            Incident,
            func.count(func.distinct(IncidentAlert.id)).label("alerts_count"),
            func.count(func.distinct(IncidentEvent.id)).label("events_count"),
            func.count(func.distinct(IncidentNote.id)).label("notes_count"),
        )
        .outerjoin(IncidentAlert, IncidentAlert.incident_id == Incident.id)
        .outerjoin(IncidentEvent, IncidentEvent.incident_id == Incident.id)
        .outerjoin(IncidentNote, IncidentNote.incident_id == Incident.id)
        .options(
            selectinload(Incident.assigned_to_user),
            selectinload(Incident.created_by_user),
            selectinload(Incident.resolved_by_user),
            selectinload(Incident.closed_by_user),
        )
        .group_by(Incident.id)
    )

    count_stmt = select(func.count(Incident.id))

    status_str = status.value if isinstance(status, IncidentStatus) else status
    severity_str = severity.value if isinstance(severity, IncidentSeverity) else severity
    priority_str = priority.value if isinstance(priority, IncidentPriority) else priority

    if status_str:
        stmt = stmt.where(Incident.status == status_str.upper())
        count_stmt = count_stmt.where(Incident.status == status_str.upper())
    if severity_str:
        stmt = stmt.where(Incident.severity == severity_str.upper())
        count_stmt = count_stmt.where(Incident.severity == severity_str.upper())
    if priority_str:
        stmt = stmt.where(Incident.priority == priority_str.upper())
        count_stmt = count_stmt.where(Incident.priority == priority_str.upper())
    if assigned_to_user_id:
        stmt = stmt.where(Incident.assigned_to_user_id == assigned_to_user_id)
        count_stmt = count_stmt.where(Incident.assigned_to_user_id == assigned_to_user_id)
    if created_by_user_id:
        stmt = stmt.where(Incident.created_by_user_id == created_by_user_id)
        count_stmt = count_stmt.where(Incident.created_by_user_id == created_by_user_id)
    if search:
        search_pattern = f"%{search.strip()}%"
        condition = or_(
            Incident.title.ilike(search_pattern),
            Incident.description.ilike(search_pattern),
            Incident.incident_id.ilike(search_pattern),
        )
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total_res = await db.execute(count_stmt)
    total = total_res.scalar_one()

    offset = (page - 1) * limit
    stmt = stmt.order_by(Incident.created_at.desc(), Incident.id.desc()).offset(offset).limit(limit)

    results = (await db.execute(stmt)).all()

    items: list[IncidentResponse] = []
    for inc, a_count, e_count, n_count in results:
        status_val = (
            IncidentStatus(inc.status)
            if inc.status in IncidentStatus._value2member_map_
            else IncidentStatus.OPEN
        )
        res_cat = (
            IncidentResolutionCategory(inc.resolution_category) if inc.resolution_category else None
        )
        items.append(
            IncidentResponse(
                id=inc.id,
                incident_id=inc.incident_id,
                title=inc.title,
                description=inc.description,
                severity=IncidentSeverity(inc.severity),
                priority=IncidentPriority(inc.priority),
                status=status_val,
                assigned_to=_user_summary(inc.assigned_to_user),
                created_by=_user_summary(inc.created_by_user),
                resolved_by=_user_summary(inc.resolved_by_user),
                closed_by=_user_summary(inc.closed_by_user),
                resolved_at=_ensure_utc(inc.resolved_at),
                resolution_category=res_cat,
                resolution_notes=inc.resolution_notes,
                closed_at=_ensure_utc(inc.closed_at),
                alerts_count=a_count,
                events_count=e_count,
                notes_count=n_count,
                created_at=_ensure_utc(inc.created_at),
                updated_at=_ensure_utc(inc.updated_at),
            )
        )

    return items, total


async def update_incident(
    db: AsyncSession,
    incident: Incident,
    payload: IncidentUpdateRequest,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Incident:
    """Update core incident properties (title, description, severity, priority)."""
    old_value = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "priority": incident.priority,
    }

    if payload.title is not None:
        incident.title = payload.title.strip()
    if payload.description is not None:
        incident.description = payload.description.strip()
    if payload.severity is not None:
        incident.severity = payload.severity.value
    if payload.priority is not None:
        incident.priority = payload.priority.value

    new_value = {
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "priority": incident.priority,
    }

    await db.commit()
    await db.refresh(incident)

    await record_audit_log(
        db=db,
        action="INCIDENT_UPDATED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        old_value=old_value,
        new_value=new_value,
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    return await get_incident_by_identifier(db, str(incident.id))


async def transition_incident_status(
    db: AsyncSession,
    incident: Incident,
    payload: IncidentStatusTransitionRequest,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Incident:
    """Validate and execute incident lifecycle state machine transition."""
    current_status = incident.status
    target_status = payload.status.value

    if target_status == current_status:
        raise InvalidStatusTransitionError(f"Incident is already in status '{current_status}'.")

    allowed = ALLOWED_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise InvalidStatusTransitionError(
            f"Cannot transition incident from status '{current_status}' to '{target_status}'. "
            f"Allowed transitions: {sorted(list(allowed))}"
        )

    old_value = {
        "status": current_status,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
    }

    now_utc = datetime.now(UTC)

    if target_status == IncidentStatus.RESOLVED.value:
        incident.status = IncidentStatus.RESOLVED.value
        res_cat_str = payload.resolution_category.value if payload.resolution_category else None
        incident.resolution_category = res_cat_str
        incident.resolution_notes = (
            payload.resolution_notes.strip() if payload.resolution_notes else None
        )
        incident.resolved_at = now_utc
        incident.resolved_by_user_id = actor_user_id

        # Automatically record system transition note
        cat_str = res_cat_str or "UNSPECIFIED"
        note_content = (
            f"[Status transitioned to RESOLVED]\n"
            f"Category: {cat_str}\n"
            f"Notes: {payload.resolution_notes.strip() if payload.resolution_notes else ''}"
        )
        if payload.comment:
            note_content += f"\nComment: {payload.comment.strip()}"
        db.add(
            IncidentNote(
                incident_id=incident.id,
                author_user_id=actor_user_id,
                content=note_content,
            )
        )

    elif target_status == IncidentStatus.CLOSED.value:
        incident.status = IncidentStatus.CLOSED.value
        incident.closed_at = now_utc
        incident.closed_by_user_id = actor_user_id
        if payload.comment:
            db.add(
                IncidentNote(
                    incident_id=incident.id,
                    author_user_id=actor_user_id,
                    content=f"[Status transitioned to CLOSED] {payload.comment.strip()}",
                )
            )

    elif target_status == IncidentStatus.REOPENED.value:
        incident.status = IncidentStatus.REOPENED.value
        incident.closed_at = None
        incident.closed_by_user_id = None
        reopen_comment = payload.comment.strip() if payload.comment else "No reason provided"
        db.add(
            IncidentNote(
                incident_id=incident.id,
                author_user_id=actor_user_id,
                content=f"[Incident REOPENED] Reason: {reopen_comment}",
            )
        )

    elif target_status == IncidentStatus.IN_PROGRESS.value:
        incident.status = IncidentStatus.IN_PROGRESS.value
        if payload.comment:
            db.add(
                IncidentNote(
                    incident_id=incident.id,
                    author_user_id=actor_user_id,
                    content=f"[Status transitioned to IN_PROGRESS] {payload.comment.strip()}",
                )
            )

    elif target_status == IncidentStatus.OPEN.value:
        incident.status = IncidentStatus.OPEN.value
        if payload.comment:
            db.add(
                IncidentNote(
                    incident_id=incident.id,
                    author_user_id=actor_user_id,
                    content=f"[Status transitioned to OPEN] {payload.comment.strip()}",
                )
            )

    await db.flush()

    new_value = {
        "status": incident.status,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
        "resolution_category": incident.resolution_category,
    }

    # Record specific lifecycle audit action
    specific_action = f"INCIDENT_{target_status}"
    if target_status in ("RESOLVED", "CLOSED", "REOPENED"):
        await record_audit_log(
            db=db,
            action=specific_action,
            actor_user_id=actor_user_id,
            resource_type="incident",
            resource_id=str(incident.id),
            old_value=old_value,
            new_value=new_value,
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )

    await record_audit_log(
        db=db,
        action="INCIDENT_STATUS_CHANGED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        old_value=old_value,
        new_value=new_value,
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    notif_event_type = (
        "INCIDENT_RESOLVED"
        if target_status == IncidentStatus.RESOLVED.value
        else "INCIDENT_STATE_CHANGED"
    )
    await _safe_notify_incident(db, incident, notif_event_type)

    return await get_incident_by_identifier(db, str(incident.id))


async def assign_incident(
    db: AsyncSession,
    incident: Incident,
    assigned_to_user_id: uuid.UUID | None,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Incident:
    """Assign or reassign an analyst to the incident case."""
    old_assignee = str(incident.assigned_to_user_id) if incident.assigned_to_user_id else None
    old_status = incident.status
    target_user: User | None = None

    if assigned_to_user_id is not None:
        user_stmt = select(User).where(User.id == assigned_to_user_id, User.is_active.is_(True))
        target_user = (await db.execute(user_stmt)).scalar_one_or_none()
        if not target_user:
            raise UserNotFoundError(f"User {assigned_to_user_id} not found or inactive")

    incident.assigned_to_user = target_user
    incident.assigned_to_user_id = assigned_to_user_id

    # If assigning an OPEN incident, automatically move it to IN_PROGRESS
    status_changed = False
    if incident.status == IncidentStatus.OPEN.value and assigned_to_user_id is not None:
        incident.status = IncidentStatus.IN_PROGRESS.value
        status_changed = True
        assignee_name = target_user.username if target_user else str(assigned_to_user_id)
        db.add(
            IncidentNote(
                incident_id=incident.id,
                author_user_id=actor_user_id,
                content=(
                    f"[Status auto-transitioned from OPEN to IN_PROGRESS "
                    f"upon assignment to {assignee_name}]"
                ),
            )
        )

    await db.flush()

    new_assignee = str(incident.assigned_to_user_id) if incident.assigned_to_user_id else None

    await record_audit_log(
        db=db,
        action="INCIDENT_ASSIGNED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        old_value={"assigned_to_user_id": old_assignee},
        new_value={"assigned_to_user_id": new_assignee, "status": incident.status},
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    if status_changed:
        await record_audit_log(
            db=db,
            action="INCIDENT_STATUS_CHANGED",
            actor_user_id=actor_user_id,
            resource_type="incident",
            resource_id=str(incident.id),
            old_value={"status": old_status},
            new_value={"status": incident.status, "reason": "auto_assignment"},
            request_id=request_id,
            source_ip=source_ip,
            user_agent=user_agent,
        )

    return await get_incident_by_identifier(db, str(incident.id))


async def attach_alert_to_incident(
    db: AsyncSession,
    incident: Incident,
    alert_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> IncidentAlertSummaryResponse:
    """Attach an alert to an incident case, ensuring uniqueness and race safety."""
    alert_stmt = select(Alert).where(Alert.id == alert_id)
    alert = (await db.execute(alert_stmt)).scalar_one_or_none()
    if not alert:
        raise AlertNotFoundError(f"Alert {alert_id} not found")

    existing_stmt = select(IncidentAlert).where(
        IncidentAlert.incident_id == incident.id, IncidentAlert.alert_id == alert_id
    )
    if (await db.execute(existing_stmt)).scalar_one_or_none():
        raise DuplicateAttachmentError(
            f"Alert {alert_id} is already linked to incident {incident.incident_id}"
        )

    incident_id_str = incident.incident_id
    inc_alert = IncidentAlert(
        incident_id=incident.id,
        alert_id=alert_id,
        added_by_user_id=actor_user_id,
    )
    db.add(inc_alert)

    try:
        await db.flush()
    except IntegrityError as err:
        await db.rollback()
        raise DuplicateAttachmentError(
            f"Alert {alert_id} is already linked to incident {incident_id_str}"
        ) from err

    await record_audit_log(
        db=db,
        action="INCIDENT_ALERT_ATTACHED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        new_value={"alert_id": str(alert_id), "rule_id": alert.rule_id},
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    added_at_val = _require_utc(inc_alert.added_at)
    return IncidentAlertSummaryResponse(
        alert_id=alert.id,
        rule_id=alert.rule_id,
        title=alert.title,
        severity=alert.severity,
        status=alert.status,
        added_at=added_at_val,
        added_by_user_id=inc_alert.added_by_user_id,
    )


async def detach_alert_from_incident(
    db: AsyncSession,
    incident: Incident,
    alert_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Detach an alert from an incident case."""
    existing_stmt = select(IncidentAlert).where(
        IncidentAlert.incident_id == incident.id, IncidentAlert.alert_id == alert_id
    )
    inc_alert = (await db.execute(existing_stmt)).scalar_one_or_none()
    if not inc_alert:
        raise AlertNotFoundError(
            f"Alert {alert_id} is not linked to incident {incident.incident_id}"
        )

    await db.delete(inc_alert)
    await db.flush()

    await record_audit_log(
        db=db,
        action="INCIDENT_ALERT_DETACHED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        old_value={"alert_id": str(alert_id)},
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )


async def attach_event_to_incident(
    db: AsyncSession,
    incident: Incident,
    event_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> IncidentEventSummaryResponse:
    """Attach a raw security event as forensic evidence, preserving payload immutability."""
    event_stmt = select(Event).where(Event.id == event_id)
    event = (await db.execute(event_stmt)).scalar_one_or_none()
    if not event:
        raise EventNotFoundError(f"Security event {event_id} not found")

    existing_stmt = select(IncidentEvent).where(
        IncidentEvent.incident_id == incident.id, IncidentEvent.event_id == event_id
    )
    if (await db.execute(existing_stmt)).scalar_one_or_none():
        raise DuplicateAttachmentError(
            f"Event {event_id} is already linked as evidence to incident {incident.incident_id}"
        )

    incident_id_str = incident.incident_id
    inc_event = IncidentEvent(
        incident_id=incident.id,
        event_id=event_id,
        added_by_user_id=actor_user_id,
    )
    db.add(inc_event)

    try:
        await db.flush()
    except IntegrityError as err:
        await db.rollback()
        raise DuplicateAttachmentError(
            f"Event {event_id} is already linked as evidence to incident {incident_id_str}"
        ) from err

    await record_audit_log(
        db=db,
        action="INCIDENT_EVENT_ATTACHED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        new_value={"event_id": str(event_id), "event_type": event.event_type},
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    added_at_val = _require_utc(inc_event.added_at)
    event_ts_val = _require_utc(event.timestamp)
    return IncidentEventSummaryResponse(
        event_id=event.id,
        timestamp=event_ts_val,
        event_type=event.event_type,
        action=event.action,
        source=event.source,
        source_ip=event.source_ip,
        username=event.username,
        severity=event.severity,
        added_at=added_at_val,
        added_by_user_id=inc_event.added_by_user_id,
    )


async def detach_event_from_incident(
    db: AsyncSession,
    incident: Incident,
    event_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    """Detach a forensic event evidence link from an incident case."""
    existing_stmt = select(IncidentEvent).where(
        IncidentEvent.incident_id == incident.id, IncidentEvent.event_id == event_id
    )
    inc_event = (await db.execute(existing_stmt)).scalar_one_or_none()
    if not inc_event:
        raise EventNotFoundError(
            f"Event {event_id} is not linked to incident {incident.incident_id}"
        )

    await db.delete(inc_event)
    await db.flush()

    await record_audit_log(
        db=db,
        action="INCIDENT_EVENT_DETACHED",
        actor_user_id=actor_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        old_value={"event_id": str(event_id)},
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )


async def create_incident_note(
    db: AsyncSession,
    incident: Incident,
    content: str,
    author_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> IncidentNote:
    """Add an investigation note with author strictly derived from session."""
    clean_content = content.strip()
    if not clean_content:
        raise IncidentValidationError("Note content cannot be empty")
    if len(clean_content) > 10000:
        raise IncidentValidationError("Note content cannot exceed 10,000 characters")

    note = IncidentNote(
        incident_id=incident.id,
        author_user_id=author_user_id,
        content=clean_content,
    )
    db.add(note)
    await db.flush()

    # Never log full note content in audit log for data confidentiality
    await record_audit_log(
        db=db,
        action="INCIDENT_NOTE_CREATED",
        actor_user_id=author_user_id,
        resource_type="incident",
        resource_id=str(incident.id),
        new_value={"note_id": str(note.id), "content_length": len(clean_content)},
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
    )

    # Re-fetch note with author loaded
    stmt = (
        select(IncidentNote)
        .options(selectinload(IncidentNote.author))
        .where(IncidentNote.id == note.id)
    )
    return (await db.execute(stmt)).scalar_one()


async def build_incident_timeline(
    db: AsyncSession, incident: Incident, limit: int = 500
) -> list[IncidentTimelineEntry]:
    """Aggregate chronological timeline distinguishing event timestamps from action timestamps."""
    timeline_entries: list[IncidentTimelineEntry] = []

    # 1. Incident Creation Entry
    timeline_entries.append(
        IncidentTimelineEntry(
            id=f"create-{incident.id}",
            entry_type=TimelineEntryType.INCIDENT_CREATED,
            timestamp=_ensure_utc(incident.created_at),
            event_timestamp=None,
            actor=_user_summary(incident.created_by_user),
            title=f"Incident Opened: {incident.incident_id}",
            details={
                "title": incident.title,
                "severity": incident.severity,
                "priority": incident.priority,
                "status": incident.status,
            },
            reference_id=incident.incident_id,
        )
    )

    # 2. Audit Trail Events (Status changes, assignment modifications)
    audit_stmt = (
        select(AuditLog)
        .options(selectinload(AuditLog.actor))
        .where(
            AuditLog.resource_type == "incident",
            AuditLog.resource_id == str(incident.id),
        )
        .order_by(AuditLog.timestamp.asc())
        .limit(500)
    )
    audit_logs = (await db.execute(audit_stmt)).scalars().all()

    for log in audit_logs:
        if log.action in (
            "INCIDENT_STATUS_CHANGED",
            "INCIDENT_RESOLVED",
            "INCIDENT_CLOSED",
            "INCIDENT_REOPENED",
        ):
            st = log.new_value.get("status") if log.new_value else "UNKNOWN"
            timeline_entries.append(
                IncidentTimelineEntry(
                    id=f"status-{log.id}",
                    entry_type=TimelineEntryType.STATUS_CHANGED,
                    timestamp=_ensure_utc(log.timestamp),
                    event_timestamp=None,
                    actor=_user_summary(log.actor),
                    title=f"Lifecycle Status Changed to {st}",
                    details=log.new_value or {},
                    reference_id=str(log.id),
                )
            )
        elif log.action == "INCIDENT_ASSIGNED":
            assigned_id = log.new_value.get("assigned_to_user_id") if log.new_value else None
            timeline_entries.append(
                IncidentTimelineEntry(
                    id=f"assign-{log.id}",
                    entry_type=TimelineEntryType.ASSIGNMENT_CHANGED,
                    timestamp=_ensure_utc(log.timestamp),
                    event_timestamp=None,
                    actor=_user_summary(log.actor),
                    title=f"Analyst Assigned: {assigned_id or 'Unassigned'}",
                    details=log.new_value or {},
                    reference_id=str(log.id),
                )
            )

    # 3. Attached Alerts (cleanly differentiating telemetry first_seen from added_at)
    for inc_alert in incident.incident_alerts:
        alert = inc_alert.alert
        if alert:
            timeline_entries.append(
                IncidentTimelineEntry(
                    id=f"alert-{inc_alert.id}",
                    entry_type=TimelineEntryType.ALERT_ATTACHED,
                    timestamp=_ensure_utc(inc_alert.added_at),
                    event_timestamp=_ensure_utc(alert.first_seen),
                    actor=_user_summary(inc_alert.added_by_user),
                    title=f"Alert Linked: [{alert.rule_id}] {alert.title}",
                    details={
                        "alert_id": str(alert.id),
                        "rule_id": alert.rule_id,
                        "severity": alert.severity,
                        "observed_count": alert.observed_count,
                        "source_ip": alert.source_ip,
                        "username": alert.username,
                    },
                    reference_id=str(alert.id),
                )
            )

    # 4. Attached Events (cleanly differentiating telemetry timestamp from added_at)
    for inc_event in incident.incident_events:
        event = inc_event.event
        if event:
            timeline_entries.append(
                IncidentTimelineEntry(
                    id=f"evidence-{inc_event.id}",
                    entry_type=TimelineEntryType.EVIDENCE_ATTACHED,
                    timestamp=_ensure_utc(inc_event.added_at),
                    event_timestamp=_ensure_utc(event.timestamp),
                    actor=_user_summary(inc_event.added_by_user),
                    title=f"Evidence Attached: {event.event_type} / {event.action}",
                    details={
                        "event_id": str(event.id),
                        "event_type": event.event_type,
                        "action": event.action,
                        "outcome": event.outcome,
                        "source_ip": event.source_ip,
                        "destination_ip": event.destination_ip,
                        "username": event.username,
                        "severity": event.severity,
                    },
                    reference_id=str(event.id),
                )
            )

    # 5. Notes
    for note in incident.incident_notes:
        timeline_entries.append(
            IncidentTimelineEntry(
                id=f"note-{note.id}",
                entry_type=TimelineEntryType.NOTE_ADDED,
                timestamp=_ensure_utc(note.created_at),
                event_timestamp=None,
                actor=_user_summary(note.author),
                title="Investigation Note Added",
                details={"content": note.content},
                reference_id=str(note.id),
            )
        )

    # Sort strictly chronologically with deterministic tie-breaking on unique id
    timeline_entries.sort(key=lambda x: (x.timestamp, x.id))
    return timeline_entries[:limit]


def format_incident_detail(incident: Incident) -> IncidentDetailResponse:
    """Convert an Incident ORM model into a complete IncidentDetailResponse."""
    alerts_list: list[IncidentAlertSummaryResponse] = []
    for ia in incident.incident_alerts:
        if ia.alert:
            alerts_list.append(
                IncidentAlertSummaryResponse(
                    alert_id=ia.alert.id,
                    rule_id=ia.alert.rule_id,
                    title=ia.alert.title,
                    severity=ia.alert.severity,
                    status=ia.alert.status,
                    added_at=_ensure_utc(ia.added_at),
                    added_by_user_id=ia.added_by_user_id,
                )
            )

    events_list: list[IncidentEventSummaryResponse] = []
    for ie in incident.incident_events:
        if ie.event:
            events_list.append(
                IncidentEventSummaryResponse(
                    event_id=ie.event.id,
                    timestamp=_ensure_utc(ie.event.timestamp),
                    event_type=ie.event.event_type,
                    action=ie.event.action,
                    source=ie.event.source,
                    source_ip=ie.event.source_ip,
                    username=ie.event.username,
                    severity=ie.event.severity,
                    added_at=_ensure_utc(ie.added_at),
                    added_by_user_id=ie.added_by_user_id,
                )
            )

    notes_list: list[IncidentNoteResponse] = []
    for note in incident.incident_notes:
        notes_list.append(
            IncidentNoteResponse(
                id=note.id,
                incident_id=note.incident_id,
                author=_user_summary(note.author),
                content=note.content,
                created_at=_ensure_utc(note.created_at),
                updated_at=_ensure_utc(note.updated_at),
            )
        )

    status_val = (
        IncidentStatus(incident.status)
        if incident.status in IncidentStatus._value2member_map_
        else IncidentStatus.OPEN
    )
    res_cat = (
        IncidentResolutionCategory(incident.resolution_category)
        if incident.resolution_category
        else None
    )

    return IncidentDetailResponse(
        id=incident.id,
        incident_id=incident.incident_id,
        title=incident.title,
        description=incident.description,
        severity=IncidentSeverity(incident.severity),
        priority=IncidentPriority(incident.priority),
        status=status_val,
        assigned_to=_user_summary(incident.assigned_to_user),
        created_by=_user_summary(incident.created_by_user),
        resolved_by=_user_summary(incident.resolved_by_user),
        closed_by=_user_summary(incident.closed_by_user),
        resolved_at=_ensure_utc(incident.resolved_at),
        resolution_category=res_cat,
        resolution_notes=incident.resolution_notes,
        closed_at=_ensure_utc(incident.closed_at),
        alerts_count=len(alerts_list),
        events_count=len(events_list),
        notes_count=len(notes_list),
        alerts=alerts_list,
        events=events_list,
        notes=notes_list,
        created_at=_ensure_utc(incident.created_at),
        updated_at=_ensure_utc(incident.updated_at),
    )

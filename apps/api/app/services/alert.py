"""Alert Operations, Lifecycle Management, and Security Monitoring Service (Phase 10).

Provides:
- Deterministic alert lifecycle state machine enforcement
  (OPEN -> ACKNOWLEDGED -> IN_PROGRESS -> RESOLVED -> CLOSED)
- Secure analyst assignment, reassignment, and unassignment
- Bounded alert suppression with expiration bounds and auditability
- Append-only analyst triage notes
- Deterministic, explainable operational prioritization metadata
- Concurrency protection via row-level locking (with_for_update) and optimistic version control
- Incident case correlation and Phase 8 investigation linkage
- Complete audit logging and notification-ready event emission
"""

import html
import logging
import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.alert import Alert, AlertNote
from app.models.auth import User
from app.models.incident import Incident, IncidentAlert
from app.schemas.alert import (
    AlertCloseRequest,
    AlertIncidentSummary,
    AlertInvestigationLink,
    AlertNoteListResponse,
    AlertNoteResponse,
    AlertPrioritizationMetadata,
    AlertResolveRequest,
    AlertResponse,
    AlertStatus,
    AlertSuppressRequest,
)
from app.schemas.incident import UserSummaryResponse
from app.services.auth import record_audit_log
from app.services.notifications import emit_notification_event

logger = logging.getLogger("sentinelforge.alerts")


# ==============================================================================
# Domain Exceptions
# ==============================================================================


class AlertNotFoundError(Exception):
    """Raised when an alert is not found by ID."""


class InvalidAlertTransitionError(Exception):
    """Raised when a status change violates the lifecycle state machine."""


class AlertValidationError(Exception):
    """Raised when operational parameters fail domain validation."""


class AlertConflictError(Exception):
    """Raised when optimistic concurrency checks fail or concurrent mutations conflict."""


class UserNotFoundError(Exception):
    """Raised when an analyst assignment targets a non-existent or inactive user."""


class IncidentNotFoundError(Exception):
    """Raised when an incident to be linked is not found."""


class DuplicateAlertAttachmentError(Exception):
    """Raised when an alert is already linked to an incident case."""


# ==============================================================================
# Lifecycle State Machine Definition
# ==============================================================================


ALLOWED_ALERT_TRANSITIONS: dict[str, set[str]] = {
    AlertStatus.OPEN: {
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.IN_PROGRESS,
        AlertStatus.SUPPRESSED,
    },
    AlertStatus.ACKNOWLEDGED: {
        AlertStatus.IN_PROGRESS,
        AlertStatus.SUPPRESSED,
        AlertStatus.RESOLVED,
        AlertStatus.CLOSED,
    },
    AlertStatus.IN_PROGRESS: {
        AlertStatus.RESOLVED,
        AlertStatus.SUPPRESSED,
        AlertStatus.CLOSED,
        AlertStatus.ACKNOWLEDGED,
    },
    AlertStatus.SUPPRESSED: {
        AlertStatus.OPEN,
        AlertStatus.ACKNOWLEDGED,
        AlertStatus.CLOSED,
    },
    AlertStatus.RESOLVED: {
        AlertStatus.CLOSED,
        AlertStatus.OPEN,
        AlertStatus.IN_PROGRESS,
    },
    AlertStatus.CLOSED: {
        AlertStatus.OPEN,
        AlertStatus.IN_PROGRESS,
    },
}

# Supported sort fields allowlist
ALLOWED_SORT_FIELDS: dict[str, Any] = {
    "created_at": Alert.created_at,
    "updated_at": Alert.updated_at,
    "severity": Alert.severity,
    "status": Alert.status,
    "rule_id": Alert.rule_id,
    "rule_version": Alert.rule_version,
    "assigned_at": Alert.assigned_at,
    "last_seen": Alert.last_seen,
    "observed_count": Alert.observed_count,
}


# ==============================================================================
# Notification-Ready Operational Events Architecture
# ==============================================================================


@dataclass(frozen=True)
class AlertOperationalEvent:
    """Standardized operational event ready for future notification layers."""

    event_type: str
    alert_id: uuid.UUID
    actor_user_id: uuid.UUID | None
    timestamp: datetime
    metadata: dict[str, Any]


def emit_alert_event(event: AlertOperationalEvent) -> None:
    """Emit an operational alert event.

    Maintains clean service boundaries suitable for future notification subscribers
    (e.g., Slack, webhooks, or email) without introducing external broker dependencies.
    """
    logger.info(
        f"Operational alert event emitted: {event.event_type}",
        extra={
            "alert_id": str(event.alert_id),
            "event_type": event.event_type,
            "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
            "metadata": event.metadata,
        },
    )


async def _safe_notify_alert(
    db: AsyncSession,
    alert: Alert,
    event_type: str,
    extra: dict[str, Any] | None = None,
) -> None:
    """Safely emit notification event without impacting alert transaction."""
    try:
        payload: dict[str, Any] = {
            "id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "rule_id": alert.rule_id,
            "rule_version": alert.rule_version,
            "source_ip": alert.source_ip,
            "username": alert.username,
        }
        if extra:
            payload.update(extra)
        await emit_notification_event(
            db=db,
            event_type=event_type,
            source_resource_type="alert",
            source_resource_id=str(alert.id),
            payload_data=payload,
            correlation_id=alert.correlation_key,
        )
    except Exception:
        logger.warning(f"Failed to emit notification for {event_type}", exc_info=True)


# ==============================================================================
# Helper Utilities
# ==============================================================================


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt


def _user_summary(user: User | None) -> UserSummaryResponse | None:
    """Convert User ORM model to UserSummaryResponse."""
    if not user:
        return None
    return UserSummaryResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
    )


def sanitize_note_content(raw_content: str) -> str:
    """Sanitize analyst note content to prevent stored HTML/script injection."""
    stripped = raw_content.strip()
    if not stripped:
        raise AlertValidationError("Note content cannot be empty or whitespace-only.")
    if len(stripped) > 10000:
        raise AlertValidationError("Note content cannot exceed 10,000 characters.")
    return html.escape(stripped)


# ==============================================================================
# Deterministic Prioritization Calculation
# ==============================================================================


def calculate_alert_prioritization(
    alert: Alert,
    linked_incidents_count: int = 0,
    notes_count: int = 0,
    evidence_count: int = 0,
    now: datetime | None = None,
) -> AlertPrioritizationMetadata:
    """Calculate deterministic, explainable operational prioritization metadata.

    Exclusively factual rules based on severity, temporal age, assignment state,
    acknowledgement status, and incident linkage. Zero AI/ML or probabilistic scoring.
    """
    if now is None:
        now = datetime.now(UTC)

    created_at = _ensure_utc(alert.created_at) or now
    age_seconds = max(0, int((now - created_at).total_seconds()))

    severity_upper = alert.severity.upper()
    severity_weights = {
        "CRITICAL": 400,
        "HIGH": 300,
        "MEDIUM": 200,
        "LOW": 100,
        "INFO": 50,
    }
    base_score = severity_weights.get(severity_upper, 100)
    score = base_score
    factors: list[str] = [f"Base severity: {severity_upper} ({base_score} pts)"]

    is_assigned = alert.assignee_id is not None
    is_acknowledged = alert.acknowledged_at is not None
    is_suppressed = alert.status == AlertStatus.SUPPRESSED
    is_resolved = alert.status == AlertStatus.RESOLVED
    is_closed = alert.status == AlertStatus.CLOSED

    sla_breach = False
    if alert.status in (AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED):
        if not is_acknowledged:
            score += 50
            factors.append("Unacknowledged active alert (+50 pts)")
        if not is_assigned:
            score += 25
            factors.append("Unassigned ownership (+25 pts)")
        if age_seconds > 86400 and severity_upper in ("CRITICAL", "HIGH"):
            sla_breach = True
            score += 50
            factors.append("SLA breach: Critical/High alert untriaged >24h (+50 pts)")

    if linked_incidents_count > 0:
        score += 75
        factors.append(f"Linked to {linked_incidents_count} incident case(s) (+75 pts)")

    if is_suppressed:
        score = max(0, score - 150)
        factors.append("Suppressed alert (-150 pts)")

    if is_resolved or is_closed:
        score = 0
        factors.append(f"Lifecycle state is {alert.status} (score reset to 0)")

    # Assign deterministic priority tier
    if is_resolved or is_closed:
        priority_tier = "LOW"
    elif score >= 400:
        priority_tier = "CRITICAL"
    elif score >= 300:
        priority_tier = "HIGH"
    elif score >= 150:
        priority_tier = "MEDIUM"
    else:
        priority_tier = "LOW"

    return AlertPrioritizationMetadata(
        priority_tier=priority_tier,
        priority_score=score,
        sla_breach=sla_breach,
        age_seconds=age_seconds,
        is_assigned=is_assigned,
        is_acknowledged=is_acknowledged,
        is_suppressed=is_suppressed,
        is_resolved=is_resolved,
        is_closed=is_closed,
        linked_incident_count=linked_incidents_count,
        notes_count=notes_count,
        evidence_count=evidence_count,
        factors=factors,
    )


# ==============================================================================
# Alert Operations & Lifecycle Transitions
# ==============================================================================


async def get_alert_locked(db: AsyncSession, alert_id: uuid.UUID) -> Alert:
    """Retrieve an alert with row-level locking (FOR UPDATE) for concurrency safety."""
    stmt = select(Alert).where(Alert.id == alert_id).with_for_update()
    result = await db.execute(stmt)
    alert = result.scalar_one_or_none()
    if not alert:
        raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")
    return alert


async def load_alert_with_actors(db: AsyncSession, alert_id: uuid.UUID) -> Alert:
    """Reload an alert after mutation with actor relationships eagerly loaded."""
    stmt = (
        select(Alert)
        .where(Alert.id == alert_id)
        .options(
            selectinload(Alert.assignee),
            selectinload(Alert.acknowledged_by),
            selectinload(Alert.resolved_by),
            selectinload(Alert.closed_by),
            selectinload(Alert.suppressed_by),
        )
    )
    res = await db.execute(stmt)
    return res.scalar_one()


async def acknowledge_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    comment: str | None = None,
    expected_version: int | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Alert:
    """Explicitly acknowledge an alert and advance lifecycle state."""
    alert = await get_alert_locked(db, alert_id)

    if expected_version is not None and alert.version != expected_version:
        raise AlertConflictError(
            f"Alert version conflict: current version is {alert.version}, "
            f"requested update expected {expected_version}."
        )

    old_status = alert.status

    if old_status == AlertStatus.ACKNOWLEDGED:
        raise InvalidAlertTransitionError("Alert is already acknowledged.")
    if old_status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
        raise InvalidAlertTransitionError(f"Cannot acknowledge an alert in '{old_status}' state.")

    now = datetime.now(UTC)
    old_state = {
        "status": alert.status,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        "acknowledged_by_id": str(alert.acknowledged_by_id) if alert.acknowledged_by_id else None,
        "version": alert.version,
    }

    alert.status = AlertStatus.ACKNOWLEDGED
    alert.acknowledged_at = now
    alert.acknowledged_by_id = actor_user_id
    alert.version += 1

    if comment:
        note_content = sanitize_note_content(f"Acknowledgement comment: {comment}")
        note = AlertNote(
            alert_id=alert.id,
            author_user_id=actor_user_id,
            content=note_content,
            created_at=now,
            updated_at=now,
        )
        db.add(note)

    await db.commit()
    await db.refresh(alert)

    new_state = {
        "status": alert.status,
        "acknowledged_at": alert.acknowledged_at.isoformat(),
        "acknowledged_by_id": str(alert.acknowledged_by_id),
        "version": alert.version,
    }

    await record_audit_log(
        db=db,
        action="ALERT_ACKNOWLEDGED",
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_state,
        new_value=new_state,
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_ACKNOWLEDGED",
            alert_id=alert.id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={"previous_status": old_status, "new_status": alert.status},
        )
    )

    await _safe_notify_alert(db, alert, "ALERT_ACKNOWLEDGED")

    return await load_alert_with_actors(db, alert.id)


async def assign_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    assignee_user_id: uuid.UUID | None,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Alert:
    """Assign, reassign, or unassign an alert to an analyst with active-user validation."""
    alert = await get_alert_locked(db, alert_id)

    if assignee_user_id is not None:
        user_stmt = select(User).where(User.id == assignee_user_id)
        user_res = await db.execute(user_stmt)
        target_user = user_res.scalar_one_or_none()
        if not target_user:
            raise UserNotFoundError(f"User with ID '{assignee_user_id}' does not exist.")
        if not target_user.is_active:
            raise AlertValidationError(
                f"User '{target_user.username}' is inactive and cannot be assigned."
            )

    now = datetime.now(UTC)
    old_state = {
        "assignee_id": str(alert.assignee_id) if alert.assignee_id else None,
        "assigned_at": alert.assigned_at.isoformat() if alert.assigned_at else None,
        "version": alert.version,
    }

    action = "ALERT_ASSIGNED" if assignee_user_id else "ALERT_UNASSIGNED"
    alert.assignee_id = assignee_user_id
    alert.assigned_at = now if assignee_user_id else None
    alert.version += 1

    await db.commit()
    await db.refresh(alert)

    new_state = {
        "assignee_id": str(alert.assignee_id) if alert.assignee_id else None,
        "assigned_at": alert.assigned_at.isoformat() if alert.assigned_at else None,
        "version": alert.version,
    }

    await record_audit_log(
        db=db,
        action=action,
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_state,
        new_value=new_state,
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type=action,
            alert_id=alert.id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={"assignee_id": str(assignee_user_id) if assignee_user_id else None},
        )
    )

    await _safe_notify_alert(db, alert, action)

    return await load_alert_with_actors(db, alert.id)


async def transition_alert_status(
    db: AsyncSession,
    alert_id: uuid.UUID,
    target_status: AlertStatus,
    actor_user_id: uuid.UUID,
    comment: str | None = None,
    expected_version: int | None = None,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Alert:
    """Transition alert lifecycle state according to strict deterministic state machine."""
    alert = await get_alert_locked(db, alert_id)

    # Concurrency verification
    if expected_version is not None and alert.version != expected_version:
        raise AlertConflictError(
            f"Alert version conflict: current version is {alert.version}, "
            f"requested update expected {expected_version}."
        )

    current_status = alert.status
    if current_status == target_status:
        raise InvalidAlertTransitionError(f"Alert is already in state '{target_status}'.")

    allowed = ALLOWED_ALERT_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise InvalidAlertTransitionError(
            f"Invalid transition from '{current_status}' to '{target_status}'. "
            f"Allowed targets: {sorted(allowed)}"
        )

    now = datetime.now(UTC)
    old_state = {
        "status": alert.status,
        "version": alert.version,
    }

    alert.status = target_status
    alert.version += 1

    # State-specific metadata adjustments
    if current_status == AlertStatus.SUPPRESSED and target_status != AlertStatus.SUPPRESSED:
        alert.suppressed_at = None
        alert.suppressed_by_id = None
        alert.suppression_reason = None
        alert.suppressed_until = None

    if target_status == AlertStatus.ACKNOWLEDGED:
        if not alert.acknowledged_at:
            alert.acknowledged_at = now
            alert.acknowledged_by_id = actor_user_id
    elif target_status == AlertStatus.CLOSED:
        alert.closed_at = now
        alert.closed_by_id = actor_user_id

    if comment:
        note_content = sanitize_note_content(f"Status transition to {target_status}: {comment}")
        note = AlertNote(
            alert_id=alert.id,
            author_user_id=actor_user_id,
            content=note_content,
            created_at=now,
            updated_at=now,
        )
        db.add(note)

    await db.commit()

    new_state = {
        "status": alert.status,
        "version": alert.version,
    }

    await record_audit_log(
        db=db,
        action="ALERT_STATUS_TRANSITIONED",
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_state,
        new_value=new_state,
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_STATUS_TRANSITIONED",
            alert_id=alert.id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={"previous_status": current_status, "new_status": target_status},
        )
    )

    return await load_alert_with_actors(db, alert.id)


async def suppress_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    payload: AlertSuppressRequest,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Alert:
    """Suppress an alert with mandatory reason and optional bounded expiration."""
    alert = await get_alert_locked(db, alert_id)

    if alert.status == AlertStatus.SUPPRESSED:
        raise InvalidAlertTransitionError("Alert is already suppressed.")

    allowed = ALLOWED_ALERT_TRANSITIONS.get(alert.status, set())
    if AlertStatus.SUPPRESSED not in allowed:
        raise InvalidAlertTransitionError(f"Cannot suppress an alert in '{alert.status}' state.")

    now = datetime.now(UTC)
    old_state = {
        "status": alert.status,
        "suppressed_by_id": str(alert.suppressed_by_id) if alert.suppressed_by_id else None,
        "suppression_reason": alert.suppression_reason,
        "suppressed_until": alert.suppressed_until.isoformat() if alert.suppressed_until else None,
        "version": alert.version,
    }

    alert.status = AlertStatus.SUPPRESSED
    alert.suppressed_at = now
    alert.suppressed_by_id = actor_user_id
    alert.suppression_reason = payload.reason
    alert.suppressed_until = payload.suppressed_until
    alert.version += 1

    # Record suppression note
    suppress_note_text = f"Suppression Reason: {payload.reason}"
    if payload.suppressed_until:
        suppress_note_text += f" (Expires: {payload.suppressed_until.isoformat()})"
    db.add(
        AlertNote(
            alert_id=alert.id,
            author_user_id=actor_user_id,
            content=sanitize_note_content(suppress_note_text),
            created_at=now,
            updated_at=now,
        )
    )

    await db.commit()
    await db.refresh(alert)

    new_state = {
        "status": alert.status,
        "suppressed_by_id": str(alert.suppressed_by_id),
        "suppression_reason": alert.suppression_reason,
        "suppressed_until": alert.suppressed_until.isoformat() if alert.suppressed_until else None,
        "version": alert.version,
    }

    await record_audit_log(
        db=db,
        action="ALERT_SUPPRESSED",
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_state,
        new_value=new_state,
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_SUPPRESSED",
            alert_id=alert.id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={
                "reason": payload.reason,
                "suppressed_until": alert.suppressed_until.isoformat()
                if alert.suppressed_until
                else None,
            },
        )
    )

    await _safe_notify_alert(db, alert, "ALERT_SUPPRESSED", {"reason": payload.reason})

    return await load_alert_with_actors(db, alert.id)


async def resolve_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    payload: AlertResolveRequest,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Alert:
    """Resolve an alert with mandatory resolution documentation."""
    alert = await get_alert_locked(db, alert_id)

    if alert.status == AlertStatus.RESOLVED:
        raise InvalidAlertTransitionError("Alert is already resolved.")

    allowed = ALLOWED_ALERT_TRANSITIONS.get(alert.status, set())
    if AlertStatus.RESOLVED not in allowed:
        raise InvalidAlertTransitionError(
            f"Cannot resolve an alert in '{alert.status}' state. Allowed targets: {sorted(allowed)}"
        )

    now = datetime.now(UTC)
    old_state = {
        "status": alert.status,
        "resolved_by_id": str(alert.resolved_by_id) if alert.resolved_by_id else None,
        "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
        "resolution_notes": alert.resolution_notes,
        "version": alert.version,
    }

    alert.status = AlertStatus.RESOLVED
    alert.resolved_at = now
    alert.resolved_by_id = actor_user_id
    alert.resolution_notes = payload.resolution_notes
    alert.version += 1

    # Record resolution note
    db.add(
        AlertNote(
            alert_id=alert.id,
            author_user_id=actor_user_id,
            content=sanitize_note_content(f"Resolution: {payload.resolution_notes}"),
            created_at=now,
            updated_at=now,
        )
    )

    await db.commit()
    await db.refresh(alert)

    new_state = {
        "status": alert.status,
        "resolved_by_id": str(alert.resolved_by_id),
        "resolved_at": alert.resolved_at.isoformat(),
        "resolution_notes": alert.resolution_notes,
        "version": alert.version,
    }

    await record_audit_log(
        db=db,
        action="ALERT_RESOLVED",
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_state,
        new_value=new_state,
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_RESOLVED",
            alert_id=alert.id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={"resolution_notes": payload.resolution_notes},
        )
    )

    await _safe_notify_alert(
        db, alert, "ALERT_RESOLVED", {"resolution_notes": payload.resolution_notes}
    )

    return await load_alert_with_actors(db, alert.id)


async def close_alert(
    db: AsyncSession,
    alert_id: uuid.UUID,
    payload: AlertCloseRequest,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> Alert:
    """Close an alert."""
    alert = await get_alert_locked(db, alert_id)

    if alert.status == AlertStatus.CLOSED:
        raise InvalidAlertTransitionError("Alert is already closed.")

    allowed = ALLOWED_ALERT_TRANSITIONS.get(alert.status, set())
    if AlertStatus.CLOSED not in allowed:
        raise InvalidAlertTransitionError(
            f"Cannot close an alert in '{alert.status}' state. Allowed targets: {sorted(allowed)}"
        )

    now = datetime.now(UTC)
    old_state = {
        "status": alert.status,
        "closed_by_id": str(alert.closed_by_id) if alert.closed_by_id else None,
        "closed_at": alert.closed_at.isoformat() if alert.closed_at else None,
        "version": alert.version,
    }

    alert.status = AlertStatus.CLOSED
    alert.closed_at = now
    alert.closed_by_id = actor_user_id
    alert.version += 1

    if payload.notes:
        db.add(
            AlertNote(
                alert_id=alert.id,
                author_user_id=actor_user_id,
                content=sanitize_note_content(f"Closure note: {payload.notes}"),
                created_at=now,
                updated_at=now,
            )
        )

    await db.commit()

    new_state = {
        "status": alert.status,
        "closed_by_id": str(alert.closed_by_id),
        "closed_at": alert.closed_at.isoformat(),
        "version": alert.version,
    }

    await record_audit_log(
        db=db,
        action="ALERT_CLOSED",
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert.id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        old_value=old_state,
        new_value=new_state,
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_CLOSED",
            alert_id=alert.id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={"notes": payload.notes},
        )
    )

    await _safe_notify_alert(db, alert, "ALERT_CLOSED", {"notes": payload.notes})

    return await load_alert_with_actors(db, alert.id)


# ==============================================================================
# Analyst Notes Management
# ==============================================================================


async def create_alert_note(
    db: AsyncSession,
    alert_id: uuid.UUID,
    raw_content: str,
    author_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> AlertNote:
    """Append a sanitized triage note to an alert."""
    stmt = select(Alert.id).where(Alert.id == alert_id)
    exists = (await db.execute(stmt)).scalar_one_or_none()
    if not exists:
        raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")

    sanitized_content = sanitize_note_content(raw_content)
    now = datetime.now(UTC)

    note = AlertNote(
        alert_id=alert_id,
        author_user_id=author_user_id,
        content=sanitized_content,
        created_at=now,
        updated_at=now,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    # Fetch with author relationship loaded
    note_stmt = (
        select(AlertNote).options(selectinload(AlertNote.author)).where(AlertNote.id == note.id)
    )
    loaded_note = (await db.execute(note_stmt)).scalar_one()

    # Audit logging (note content omitted to protect investigation confidentiality)
    await record_audit_log(
        db=db,
        action="ALERT_NOTE_CREATED",
        actor_user_id=author_user_id,
        resource_type="alert",
        resource_id=str(alert_id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={"note_id": str(note.id), "length": len(sanitized_content)},
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_NOTE_CREATED",
            alert_id=alert_id,
            actor_user_id=author_user_id,
            timestamp=now,
            metadata={"note_id": str(note.id)},
        )
    )

    return loaded_note


async def list_alert_notes(
    db: AsyncSession,
    alert_id: uuid.UUID,
    page: int = 1,
    limit: int = 50,
) -> AlertNoteListResponse:
    """Retrieve paginated analyst triage notes for an alert in chronological order."""
    stmt_alert = select(Alert.id).where(Alert.id == alert_id)
    exists = (await db.execute(stmt_alert)).scalar_one_or_none()
    if not exists:
        raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")

    count_stmt = select(func.count(AlertNote.id)).where(AlertNote.alert_id == alert_id)
    total = (await db.execute(count_stmt)).scalar_one()

    offset = (page - 1) * limit
    notes_stmt = (
        select(AlertNote)
        .options(selectinload(AlertNote.author))
        .where(AlertNote.alert_id == alert_id)
        .order_by(AlertNote.created_at.asc(), AlertNote.id.asc())
        .offset(offset)
        .limit(limit)
    )
    notes = (await db.execute(notes_stmt)).scalars().all()

    items = [
        AlertNoteResponse(
            id=n.id,
            alert_id=n.alert_id,
            author=_user_summary(n.author)
            or UserSummaryResponse(
                id=n.author_user_id, username="system", email="system@sentinelforge.local"
            ),
            content=n.content,
            created_at=_ensure_utc(n.created_at) or datetime.now(UTC),
            updated_at=_ensure_utc(n.updated_at) or datetime.now(UTC),
        )
        for n in notes
    ]

    total_pages = math.ceil(total / limit) if total > 0 else 0
    return AlertNoteListResponse(
        items=items,
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
    )


# ==============================================================================
# Incident & Investigation Integration
# ==============================================================================


async def link_alert_to_incident(
    db: AsyncSession,
    alert_id: uuid.UUID,
    incident_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> IncidentAlert:
    """Link an alert to an existing incident case."""
    # 1. Verify alert exists
    alert_stmt = select(Alert.id).where(Alert.id == alert_id)
    if not (await db.execute(alert_stmt)).scalar_one_or_none():
        raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")

    # 2. Verify incident exists
    inc_stmt = select(Incident).where(Incident.id == incident_id)
    incident = (await db.execute(inc_stmt)).scalar_one_or_none()
    if not incident:
        raise IncidentNotFoundError(f"Incident with ID '{incident_id}' not found.")

    # 3. Check for existing linkage
    check_stmt = select(IncidentAlert).where(
        IncidentAlert.incident_id == incident_id,
        IncidentAlert.alert_id == alert_id,
    )
    existing = (await db.execute(check_stmt)).scalar_one_or_none()
    if existing:
        raise DuplicateAlertAttachmentError(
            f"Alert '{alert_id}' is already linked to Incident '{incident.incident_id}'."
        )

    now = datetime.now(UTC)
    link = IncidentAlert(
        incident_id=incident_id,
        alert_id=alert_id,
        added_at=now,
        added_by_user_id=actor_user_id,
    )
    db.add(link)
    try:
        await db.commit()
        await db.refresh(link)
    except IntegrityError as err:
        await db.rollback()
        raise DuplicateAlertAttachmentError(
            f"Alert '{alert_id}' is already linked to Incident '{incident_id}'."
        ) from err

    await record_audit_log(
        db=db,
        action="ALERT_INCIDENT_LINKED",
        actor_user_id=actor_user_id,
        resource_type="alert",
        resource_id=str(alert_id),
        request_id=request_id,
        source_ip=source_ip,
        user_agent=user_agent,
        new_value={"incident_id": str(incident_id), "incident_ticket": incident.incident_id},
    )

    emit_alert_event(
        AlertOperationalEvent(
            event_type="ALERT_INCIDENT_LINKED",
            alert_id=alert_id,
            actor_user_id=actor_user_id,
            timestamp=now,
            metadata={"incident_id": str(incident_id), "incident_ticket": incident.incident_id},
        )
    )

    return link


async def list_alert_incidents(db: AsyncSession, alert_id: uuid.UUID) -> list[AlertIncidentSummary]:
    """Retrieve all incident cases linked to an alert."""
    stmt_alert = select(Alert.id).where(Alert.id == alert_id)
    if not (await db.execute(stmt_alert)).scalar_one_or_none():
        raise AlertNotFoundError(f"Alert with ID '{alert_id}' not found.")

    stmt = (
        select(IncidentAlert)
        .options(selectinload(IncidentAlert.incident))
        .where(IncidentAlert.alert_id == alert_id)
        .order_by(IncidentAlert.added_at.desc())
    )
    res = await db.execute(stmt)
    links = res.scalars().all()

    summaries: list[AlertIncidentSummary] = []
    for link in links:
        if link.incident:
            inc = link.incident
            summaries.append(
                AlertIncidentSummary(
                    incident_id=inc.id,
                    incident_ticket=inc.incident_id,
                    title=inc.title,
                    severity=inc.severity,
                    status=inc.status,
                    linked_at=_ensure_utc(link.added_at) or datetime.now(UTC),
                )
            )
    return summaries


def build_alert_investigation_link(alert_id: uuid.UUID) -> AlertInvestigationLink:
    """Build deterministic Phase 8 investigation URL links for an alert."""
    str_id = str(alert_id)
    return AlertInvestigationLink(
        alert_id=alert_id,
        anchor_type="ALERT",
        anchor_value=str_id,
        context_url=f"/api/v1/investigations/context?anchor_type=ALERT&anchor_value={str_id}",
        summary_url=f"/api/v1/investigations/summary?anchor_type=ALERT&anchor_value={str_id}",
        timeline_url=f"/api/v1/investigations/timeline?anchor_type=ALERT&anchor_value={str_id}",
    )


# ==============================================================================
# Alert Query & Detail Formatting
# ==============================================================================


def format_alert_response(
    alert: Alert,
    linked_incidents_count: int = 0,
    notes_count: int = 0,
    evidence_count: int = 0,
) -> AlertResponse:
    """Format ORM Alert model into complete AlertResponse with operational metadata."""
    prioritization = calculate_alert_prioritization(
        alert=alert,
        linked_incidents_count=linked_incidents_count,
        notes_count=notes_count,
        evidence_count=evidence_count,
    )

    return AlertResponse(
        id=alert.id,
        rule_id=alert.rule_id,
        rule_version=alert.rule_version,
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status=alert.status,
        dedup_key=alert.dedup_key,
        correlation_key=alert.correlation_key,
        observed_count=alert.observed_count,
        threshold=alert.threshold,
        evidence=alert.evidence,
        source_ip=alert.source_ip,
        username=alert.username,
        first_seen=_ensure_utc(alert.first_seen) or datetime.now(UTC),
        last_seen=_ensure_utc(alert.last_seen) or datetime.now(UTC),
        assignee_id=alert.assignee_id,
        assignee=_user_summary(alert.assignee),
        assigned_at=_ensure_utc(alert.assigned_at),
        acknowledged_by_id=alert.acknowledged_by_id,
        acknowledged_by=_user_summary(alert.acknowledged_by),
        acknowledged_at=_ensure_utc(alert.acknowledged_at),
        resolved_by_id=alert.resolved_by_id,
        resolved_by=_user_summary(alert.resolved_by),
        resolved_at=_ensure_utc(alert.resolved_at),
        resolution_notes=alert.resolution_notes,
        closed_by_id=alert.closed_by_id,
        closed_by=_user_summary(alert.closed_by),
        closed_at=_ensure_utc(alert.closed_at),
        suppressed_by_id=alert.suppressed_by_id,
        suppressed_by=_user_summary(alert.suppressed_by),
        suppressed_at=_ensure_utc(alert.suppressed_at),
        suppression_reason=alert.suppression_reason,
        suppressed_until=_ensure_utc(alert.suppressed_until),
        version=alert.version,
        prioritization=prioritization,
        created_at=_ensure_utc(alert.created_at) or datetime.now(UTC),
        updated_at=_ensure_utc(alert.updated_at) or datetime.now(UTC),
    )

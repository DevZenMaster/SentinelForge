"""Incident Management and Investigation ORM Models.

Supports SOC analyst triage, alert correlation, evidence preservation,
investigation notes, and auditable incident lifecycle state tracking.
"""

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.auth import User
    from app.models.event import Event


def _default_incident_id() -> str:
    """Generate a fallback incident ID if not explicitly assigned during creation."""
    return f"INC-{datetime.now(UTC).year}-{uuid.uuid4().hex[:6].upper()}"


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Security incident grouping correlated alerts and evidence into an investigation case."""

    __tablename__ = "incidents"

    # Human-readable stable ticket identifier (e.g. INC-2026-000001)
    incident_id: Mapped[str] = mapped_column(
        String(32),
        unique=True,
        index=True,
        nullable=False,
        default=_default_incident_id,
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Security significance (LOW, MEDIUM, HIGH, CRITICAL)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)

    # Operational triage handling priority (LOW, MEDIUM, HIGH, URGENT)
    priority: Mapped[str] = mapped_column(
        String(16), default="MEDIUM", server_default="MEDIUM", index=True, nullable=False
    )

    # Lifecycle status (OPEN, IN_PROGRESS, RESOLVED, CLOSED, REOPENED)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)

    # Analyst assignment
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Creator attribution
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Resolution details
    resolved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Closure details
    closed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Legacy notes JSON column preserved for backwards compatibility
    notes: Mapped[list[dict[str, Any]]] = mapped_column(JSON_COMPAT, default=list, nullable=False)

    # Relationships
    assigned_to_user: Mapped["User | None"] = relationship(
        "User", foreign_keys=[assigned_to_user_id], back_populates="incidents"
    )
    created_by_user: Mapped["User | None"] = relationship("User", foreign_keys=[created_by_user_id])
    resolved_by_user: Mapped["User | None"] = relationship(
        "User", foreign_keys=[resolved_by_user_id]
    )
    closed_by_user: Mapped["User | None"] = relationship("User", foreign_keys=[closed_by_user_id])

    incident_alerts: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="incident", cascade="all, delete-orphan"
    )
    incident_events: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="incident", cascade="all, delete-orphan"
    )
    incident_notes: Mapped[list["IncidentNote"]] = relationship(
        "IncidentNote",
        back_populates="incident",
        cascade="all, delete-orphan",
        order_by="IncidentNote.created_at",
    )

    __table_args__ = (
        Index("ix_incidents_status_created_at", "status", "created_at"),
        Index("ix_incidents_assigned_status", "assigned_to_user_id", "status"),
        Index("ix_incidents_severity_created_at", "severity", "created_at"),
        Index("ix_incidents_priority_created_at", "priority", "created_at"),
    )


class IncidentAlert(Base, UUIDPrimaryKeyMixin):
    """Association joining Incidents to grouped Alerts."""

    __tablename__ = "incident_alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    added_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_incident_id_alert_id"),
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="incident_alerts")
    alert: Mapped["Alert"] = relationship("Alert", back_populates="incident_alerts")
    added_by_user: Mapped["User | None"] = relationship("User", foreign_keys=[added_by_user_id])


class IncidentEvent(Base, UUIDPrimaryKeyMixin):
    """Forensic evidence association linking an Incident to constituent Events.

    Enforces RESTRICT deletion on events.id, ensuring referenced security telemetry
    cannot be purged or removed while linked as evidence to an incident case.
    """

    __tablename__ = "incident_events"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    added_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    __table_args__ = (
        UniqueConstraint("incident_id", "event_id", name="uq_incident_events_incident_id_event_id"),
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="incident_events")
    event: Mapped["Event"] = relationship("Event", back_populates="incident_events")
    added_by_user: Mapped["User | None"] = relationship("User", foreign_keys=[added_by_user_id])


class IncidentNote(Base, UUIDPrimaryKeyMixin):
    """Normalized investigation note attached to an incident.

    Enforces author attribution linking strictly to the authenticated user.
    """

    __tablename__ = "incident_notes"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    author_user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    __table_args__ = (Index("ix_incident_notes_incident_created", "incident_id", "created_at"),)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="incident_notes")
    author: Mapped["User"] = relationship("User", foreign_keys=[author_user_id])

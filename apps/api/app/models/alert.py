"""Alert, Evidence Linkage (AlertEvent), and Analyst Notes (AlertNote) ORM Models.

Maintains immutable evidence relationships linking triggered alerts to the underlying
events that caused them, ensuring forensic integrity, alongside operational triage,
ownership, and lifecycle tracking.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.auth import User
    from app.models.event import Event
    from app.models.incident import IncidentAlert


class Alert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Security alert raised by the detection engine."""

    __tablename__ = "alerts"

    # Triggering rule provenance
    rule_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    rule_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Core alert descriptor
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)

    # Deduplication and correlation
    dedup_key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    correlation_key: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    # Metrics and explainable evidence
    observed_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    evidence: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, default=dict, nullable=False)

    # Pivot entities
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Temporal bounds of detection window
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Analyst assignment and ownership
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    assigned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # State transition timestamps and actors
    acknowledged_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    resolved_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    closed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Suppression metadata
    suppressed_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppression_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppressed_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Optimistic concurrency version
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1", nullable=False)

    # Relationships
    assignee: Mapped["User | None"] = relationship(
        "User", foreign_keys=[assignee_id], lazy="select"
    )
    acknowledged_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[acknowledged_by_id], lazy="select"
    )
    resolved_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[resolved_by_id], lazy="select"
    )
    closed_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[closed_by_id], lazy="select"
    )
    suppressed_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[suppressed_by_id], lazy="select"
    )

    alert_events: Mapped[list["AlertEvent"]] = relationship(
        "AlertEvent", back_populates="alert", cascade="all, delete-orphan"
    )
    incident_alerts: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="alert", cascade="all, delete-orphan"
    )
    notes: Mapped[list["AlertNote"]] = relationship(
        "AlertNote",
        back_populates="alert",
        cascade="all, delete-orphan",
        order_by="AlertNote.created_at",
    )

    __table_args__ = (
        Index("ix_alerts_status_severity_created_at", "status", "severity", "created_at"),
        Index("ix_alerts_source_ip_created_at", "source_ip", "created_at"),
        Index("ix_alerts_rule_id_created_at", "rule_id", "created_at"),
        Index("ix_alerts_correlation_key_created_at", "correlation_key", "created_at"),
        Index("ix_alerts_status_assignee", "status", "assignee_id"),
        Index("ix_alerts_rule_version", "rule_id", "rule_version"),
        UniqueConstraint("dedup_key", name="uq_alerts_dedup_key"),
    )


class AlertEvent(Base, UUIDPrimaryKeyMixin):
    """Evidence association linking an Alert to its constituent triggering Events."""

    __tablename__ = "alert_events"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    __table_args__ = (
        UniqueConstraint("alert_id", "event_id", name="uq_alert_events_alert_id_event_id"),
    )

    alert: Mapped["Alert"] = relationship("Alert", back_populates="alert_events")
    event: Mapped["Event"] = relationship("Event", back_populates="alert_events")


class AlertNote(Base, UUIDPrimaryKeyMixin):
    """Normalized analyst triage note attached to an alert.

    Enforces author attribution linking strictly to the authenticated user.
    """

    __tablename__ = "alert_notes"

    alert_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("alerts.id", ondelete="CASCADE"),
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

    __table_args__ = (Index("ix_alert_notes_alert_created", "alert_id", "created_at"),)

    alert: Mapped["Alert"] = relationship("Alert", back_populates="notes")
    author: Mapped["User"] = relationship("User", foreign_keys=[author_user_id], lazy="select")

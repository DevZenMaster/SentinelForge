"""Alert and Evidence Linkage (AlertEvent) ORM Models.

Maintains immutable evidence relationships linking triggered alerts to the underlying
events that caused them, ensuring forensic integrity.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
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

    # Pivot entities
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)

    # Temporal bounds of detection window
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # State transition timestamps
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    alert_events: Mapped[list["AlertEvent"]] = relationship(
        "AlertEvent", back_populates="alert", cascade="all, delete-orphan"
    )
    incident_alerts: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="alert", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_alerts_status_severity_created_at", "status", "severity", "created_at"),
        Index("ix_alerts_source_ip_created_at", "source_ip", "created_at"),
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

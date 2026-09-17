"""Incident Management and Alert Grouping ORM Models.

Supports SOC analyst triage, alert correlation, investigation lifecycle states,
and structured incident containment tracking.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.auth import User


class Incident(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Security incident grouping correlated alerts into an investigation case."""

    __tablename__ = "incidents"

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="OPEN", index=True, nullable=False)

    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    notes: Mapped[list[dict[str, Any]]] = mapped_column(JSON_COMPAT, default=list, nullable=False)
    resolution_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    assigned_to_user: Mapped["User"] = relationship("User", back_populates="incidents")
    incident_alerts: Mapped[list["IncidentAlert"]] = relationship(
        "IncidentAlert", back_populates="incident", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_incidents_status_created_at", "status", "created_at"),
        Index("ix_incidents_assigned_status", "assigned_to_user_id", "status"),
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

    __table_args__ = (
        UniqueConstraint("incident_id", "alert_id", name="uq_incident_alerts_incident_id_alert_id"),
    )

    incident: Mapped["Incident"] = relationship("Incident", back_populates="incident_alerts")
    alert: Mapped["Alert"] = relationship("Alert", back_populates="incident_alerts")

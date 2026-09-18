"""Normalized Security Event ORM Model.

Preserves both full raw log payloads and extracted normalized fields
with targeted indexes designed for high-performance temporal detection window queries.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.alert import AlertEvent
    from app.models.incident import IncidentEvent
    from app.models.indicator import IndicatorEvent


class Event(Base, UUIDPrimaryKeyMixin):
    """Normalized security event record."""

    __tablename__ = "events"

    # Optional client-supplied or idempotency identifier
    external_event_id: Mapped[str | None] = mapped_column(
        String(128), unique=True, index=True, nullable=True
    )

    # Ingestion & event timestamps (always timezone-aware UTC)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Core source telemetry
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(64), default="generic", nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Event classification & taxonomy (derived canonical fields)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(64), default="observed", nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), default="unknown", nullable=False, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="INFO", nullable=False)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Normalization pipeline tracking & versioning
    normalization_status: Mapped[str] = mapped_column(
        String(16), default="PENDING", nullable=False, index=True
    )
    parser_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    parser_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    normalization_version: Mapped[str | None] = mapped_column(String(16), nullable=True)
    normalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    normalization_errors: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_COMPAT, default=list, nullable=False
    )

    # Traceability & audit
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Payloads: verbatim raw evidence and extracted source-specific attributes
    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, default=dict, nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSON_COMPAT, default=dict, nullable=False
    )

    # Relationships
    alert_events: Mapped[list["AlertEvent"]] = relationship(
        "AlertEvent", back_populates="event", cascade="all, delete-orphan"
    )
    incident_events: Mapped[list["IncidentEvent"]] = relationship(
        "IncidentEvent", back_populates="event"
    )
    indicator_events: Mapped[list["IndicatorEvent"]] = relationship(
        "IndicatorEvent", back_populates="event"
    )

    __table_args__ = (
        # Temporal compound indexes evaluated for detection rule sliding window scans
        Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),
        Index("ix_events_destination_ip_timestamp", "destination_ip", "timestamp"),
        Index("ix_events_username_timestamp", "username", "timestamp"),
        Index("ix_events_event_type_timestamp", "event_type", "timestamp"),
        Index("ix_events_action_timestamp", "action", "timestamp"),
        Index("ix_events_event_type_action_timestamp", "event_type", "action", "timestamp"),
    )

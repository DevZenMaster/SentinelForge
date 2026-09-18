"""Indicator of Compromise (IOC) and Threat Intelligence ORM Models.

Defines:
- Indicator: Canonical security indicators (IPs, domains, hashes, URLs, emails)
- IndicatorEvent: Forensic links between Indicators and Events (RESTRICT on delete)
- ThreatIntelligence: Multi-source threat intelligence records with confidence, attribution, and TTL
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.event import Event


class IndicatorType(StrEnum):
    """Taxonomic classification of Indicators of Compromise (IOCs)."""

    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    EMAIL = "EMAIL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"


class IndicatorStatus(StrEnum):
    """Lifecycle status of an indicator."""

    ACTIVE = "ACTIVE"
    WATCHLIST = "WATCHLIST"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REVOKED = "REVOKED"


class ThreatClassification(StrEnum):
    """Threat categorization of an indicator."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


class IntelligenceSeverity(StrEnum):
    """Severity level associated with a threat intelligence record."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Indicator(Base, UUIDPrimaryKeyMixin):
    """Normalized security indicator (IOC) cataloged in SentinelForge."""

    __tablename__ = "indicators"

    # Taxonomic indicator type
    type: Mapped[IndicatorType] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    # Verbatim presentation value upon creation
    value: Mapped[str] = mapped_column(Text, nullable=False)

    # Canonical normalized value used for deterministic deduplication and lookups
    normalized_value: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    # Status tracking (ACTIVE, WATCHLIST, FALSE_POSITIVE, REVOKED)
    status: Mapped[IndicatorStatus] = mapped_column(
        String(32),
        default=IndicatorStatus.ACTIVE,
        server_default="ACTIVE",
        nullable=False,
        index=True,
    )

    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    sightings_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    # Relationships
    threat_intelligences: Mapped[list["ThreatIntelligence"]] = relationship(
        "ThreatIntelligence",
        back_populates="indicator",
        cascade="all, delete-orphan",
        order_by="ThreatIntelligence.created_at.desc()",
    )
    indicator_events: Mapped[list["IndicatorEvent"]] = relationship(
        "IndicatorEvent",
        back_populates="indicator",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        UniqueConstraint("type", "normalized_value", name="uq_indicators_type_normalized_value"),
        Index("ix_indicators_type_normalized_value", "type", "normalized_value"),
        Index("ix_indicators_status_last_seen", "status", "last_seen_at"),
    )


class IndicatorEvent(Base, UUIDPrimaryKeyMixin):
    """Forensic link associating an Indicator to an Event where it was observed.

    Enforces RESTRICT on event deletion to protect evidentiary integrity.
    """

    __tablename__ = "indicator_events"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("events.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Provenance tracking: which event field produced this indicator
    extracted_from_field: Mapped[str] = mapped_column(String(64), nullable=False)

    # Original un-normalized string extracted from the event field
    raw_value: Mapped[str] = mapped_column(Text, nullable=False)

    # Relationship link timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # Relationships
    indicator: Mapped["Indicator"] = relationship("Indicator", back_populates="indicator_events")
    event: Mapped["Event"] = relationship("Event", back_populates="indicator_events")

    __table_args__ = (
        UniqueConstraint(
            "indicator_id",
            "event_id",
            "extracted_from_field",
            name="uq_indicator_events_indicator_event_field",
        ),
        Index("ix_indicator_events_event_created", "event_id", "created_at"),
    )


class ThreatIntelligence(Base, UUIDPrimaryKeyMixin):
    """Threat intelligence record providing context, confidence, and source attribution."""

    __tablename__ = "threat_intelligence"

    indicator_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("indicators.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Sourced provider or origin (INTERNAL, MANUAL, CURATED_FEED, etc.)
    source: Mapped[str] = mapped_column(String(128), nullable=False, index=True)

    # Threat classification (MALICIOUS, SUSPICIOUS, BENIGN, UNKNOWN)
    threat_classification: Mapped[ThreatClassification] = mapped_column(
        String(32),
        default=ThreatClassification.MALICIOUS,
        server_default="MALICIOUS",
        nullable=False,
    )

    # Operational severity (INFO, LOW, MEDIUM, HIGH, CRITICAL)
    severity: Mapped[IntelligenceSeverity] = mapped_column(
        String(16),
        default=IntelligenceSeverity.HIGH,
        server_default="HIGH",
        nullable=False,
    )

    # Quantitative confidence rating (0 - 100)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False)

    # External reference or advisory identifier
    source_reference: Mapped[str | None] = mapped_column(String(256), nullable=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # MITRE ATT&CK mappings
    mitre_tactics: Mapped[list[str] | None] = mapped_column(JSON_COMPAT, nullable=True)
    mitre_techniques: Mapped[list[str] | None] = mapped_column(JSON_COMPAT, nullable=True)
    tags: Mapped[list[str] | None] = mapped_column(JSON_COMPAT, nullable=True)

    threat_actor: Mapped[str | None] = mapped_column(String(128), nullable=True)
    campaign: Mapped[str | None] = mapped_column(String(128), nullable=True)
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON_COMPAT, nullable=True)

    # Temporal boundaries of intelligence validity
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    # Relationships
    indicator: Mapped["Indicator"] = relationship(
        "Indicator", back_populates="threat_intelligences"
    )

    __table_args__ = (
        CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name="confidence_range",
        ),
        UniqueConstraint(
            "indicator_id",
            "source",
            "source_reference",
            name="uq_threat_intelligence_indicator_source_ref",
        ),
        Index(
            "ix_threat_intelligence_classification_severity",
            "threat_classification",
            "severity",
        ),
    )

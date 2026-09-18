"""Schemas for Threat Intelligence and Indicator of Compromise (IOC) Enrichment."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.models.indicator import (
    IndicatorStatus,
    IndicatorType,
    IntelligenceSeverity,
    ThreatClassification,
)


class ThreatIntelligenceCreateRequest(BaseModel):
    """Payload to create threat intelligence for an indicator."""

    source: str = Field(..., min_length=1, max_length=128, description="Feed or provider name")
    threat_classification: ThreatClassification = Field(
        default=ThreatClassification.MALICIOUS, description="Threat classification"
    )
    severity: IntelligenceSeverity = Field(
        default=IntelligenceSeverity.HIGH, description="Assessed severity"
    )
    confidence: int = Field(
        ..., ge=0, le=100, description="Confidence score from 0 (unreliable) to 100 (confirmed)"
    )
    source_reference: str | None = Field(
        default=None, max_length=256, description="External reference ID or advisory identifier"
    )
    description: str | None = Field(
        default=None, max_length=2000, description="Threat context and analyst notes"
    )
    mitre_tactics: list[str] | None = Field(
        default=None, description="Associated MITRE ATT&CK tactic IDs or names"
    )
    mitre_techniques: list[str] | None = Field(
        default=None, description="Associated MITRE ATT&CK technique IDs"
    )
    tags: list[str] | None = Field(
        default=None, description="Classification tags (e.g. ransomware, c2, phishing)"
    )
    threat_actor: str | None = Field(
        default=None, max_length=128, description="Associated APT or threat actor group"
    )
    campaign: str | None = Field(
        default=None, max_length=128, description="Associated malware or attack campaign"
    )
    raw_data: dict[str, Any] | None = Field(
        default=None, description="Original raw feed telemetry preserving provenance"
    )
    expires_at: datetime | None = Field(
        default=None, description="Expiration timestamp (UTC) for TTL tracking"
    )


class ThreatIntelligenceUpdateRequest(BaseModel):
    """Payload to update existing threat intelligence."""

    threat_classification: ThreatClassification | None = Field(
        default=None, description="Updated threat classification"
    )
    severity: IntelligenceSeverity | None = Field(
        default=None, description="Updated assessed severity"
    )
    confidence: int | None = Field(
        default=None, ge=0, le=100, description="Updated confidence score (0-100)"
    )
    source_reference: str | None = Field(
        default=None, max_length=256, description="Updated source reference ID"
    )
    description: str | None = Field(
        default=None, max_length=2000, description="Updated threat context"
    )
    mitre_tactics: list[str] | None = Field(default=None, description="Updated MITRE tactics")
    mitre_techniques: list[str] | None = Field(default=None, description="Updated MITRE techniques")
    tags: list[str] | None = Field(default=None, description="Updated classification tags")
    threat_actor: str | None = Field(default=None, max_length=128, description="Threat actor")
    campaign: str | None = Field(default=None, max_length=128, description="Campaign")
    raw_data: dict[str, Any] | None = Field(default=None, description="Raw telemetry")
    expires_at: datetime | None = Field(default=None, description="Expiration timestamp (UTC)")


class ThreatIntelligenceResponse(BaseModel):
    """Full threat intelligence record response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique intelligence record ID")
    indicator_id: uuid.UUID = Field(..., description="Parent indicator ID")
    source: str = Field(..., description="Feed or provider name")
    threat_classification: ThreatClassification = Field(..., description="Threat classification")
    severity: IntelligenceSeverity = Field(..., description="Assessed severity")
    confidence: int = Field(..., description="Confidence score (0-100)")
    source_reference: str | None = Field(default=None, description="Source reference identifier")
    description: str | None = Field(default=None, description="Threat description")
    mitre_tactics: list[str] | None = Field(default=None, description="MITRE ATT&CK tactics")
    mitre_techniques: list[str] | None = Field(default=None, description="MITRE ATT&CK techniques")
    tags: list[str] | None = Field(default=None, description="Classification tags")
    threat_actor: str | None = Field(default=None, description="Threat actor name")
    campaign: str | None = Field(default=None, description="Attack campaign")
    raw_data: dict[str, Any] | None = Field(default=None, description="Raw source telemetry")
    first_seen: datetime = Field(..., description="Timestamp first recorded in threat intel (UTC)")
    last_seen: datetime = Field(..., description="Timestamp last updated in threat intel (UTC)")
    expires_at: datetime | None = Field(default=None, description="TTL expiration timestamp (UTC)")
    is_expired: bool = Field(..., description="Computed expiration flag based on current UTC time")
    created_at: datetime = Field(..., description="Creation timestamp (UTC)")
    updated_at: datetime = Field(..., description="Last update timestamp (UTC)")


class IndicatorCreateRequest(BaseModel):
    """Payload to create or register a standalone threat indicator."""

    type: IndicatorType = Field(..., description="Indicator type: IP, DOMAIN, URL, EMAIL, HASH_*")
    value: str = Field(..., min_length=1, max_length=2048, description="Raw indicator string value")
    description: str | None = Field(
        default=None, max_length=1000, description="Analyst notes regarding the indicator"
    )
    status: IndicatorStatus = Field(
        default=IndicatorStatus.ACTIVE, description="Lifecycle status of indicator"
    )
    threat_intel: ThreatIntelligenceCreateRequest | None = Field(
        default=None, description="Optional initial threat intelligence record"
    )


class IndicatorUpdateRequest(BaseModel):
    """Payload to update an indicator's lifecycle status or description."""

    status: IndicatorStatus | None = Field(default=None, description="New indicator status")
    description: str | None = Field(default=None, max_length=1000, description="Updated notes")


class IndicatorEventResponse(BaseModel):
    """Forensic evidence association between an indicator and a security event."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique link identifier")
    indicator_id: uuid.UUID = Field(..., description="Associated indicator ID")
    event_id: uuid.UUID = Field(..., description="Associated event ID")
    extracted_from_field: str = Field(..., description="Source field in event payload")
    raw_value: str = Field(..., description="Exact raw string extracted from event")
    created_at: datetime = Field(..., description="Link creation timestamp (UTC)")


class IndicatorResponse(BaseModel):
    """Standard representation of a threat indicator."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique indicator ID")
    type: IndicatorType = Field(..., description="Indicator type")
    value: str = Field(..., description="Original raw representation")
    normalized_value: str = Field(..., description="Canonical normalized representation")
    status: IndicatorStatus = Field(..., description="Lifecycle status")
    description: str | None = Field(default=None, description="Analyst description")
    first_seen_at: datetime = Field(..., description="Earliest observation timestamp (UTC)")
    last_seen_at: datetime = Field(..., description="Latest observation timestamp (UTC)")
    sightings_count: int = Field(..., description="Total observation count across events")
    created_at: datetime = Field(..., description="Record creation timestamp (UTC)")
    updated_at: datetime = Field(..., description="Record update timestamp (UTC)")
    threat_intelligences: list[ThreatIntelligenceResponse] = Field(
        default_factory=list, description="Associated threat intelligence records"
    )


class IndicatorDetailResponse(IndicatorResponse):
    """Extended representation of an indicator with linked events."""

    events: list[IndicatorEventResponse] = Field(
        default_factory=list, description="Linked event occurrences"
    )


class IndicatorEnrichmentDetail(BaseModel):
    """Enrichment result for a specific indicator found in an event."""

    indicator_id: uuid.UUID = Field(..., description="Indicator ID")
    type: IndicatorType = Field(..., description="Indicator type")
    value: str = Field(..., description="Original value")
    normalized_value: str = Field(..., description="Normalized canonical value")
    status: IndicatorStatus = Field(..., description="Indicator status")
    extracted_from_field: str = Field(..., description="Field path extracted from")
    raw_value: str = Field(..., description="Raw value extracted")
    is_threat: bool = Field(
        ..., description="True if indicator has active malicious or suspicious intelligence"
    )
    threat_intelligences: list[ThreatIntelligenceResponse] = Field(
        default_factory=list, description="Active threat intelligence records"
    )


class EventEnrichmentResponse(BaseModel):
    """Summary of threat intelligence enrichment performed on a security event."""

    event_id: uuid.UUID = Field(..., description="ID of enriched security event")
    total_indicators: int = Field(..., description="Total unique indicators identified in event")
    threat_count: int = Field(
        ..., description="Count of identified indicators with threat intelligence"
    )
    enriched_at: datetime = Field(..., description="Timestamp enrichment was computed (UTC)")
    indicators: list[IndicatorEnrichmentDetail] = Field(
        default_factory=list, description="List of enriched indicator details"
    )


class IndicatorListResponse(BaseModel):
    """Paginated collection of threat indicators."""

    items: list[IndicatorResponse] = Field(..., description="Indicators for current page")
    total: int = Field(..., description="Total matching indicators")
    page: int = Field(..., description="Current page number (1-based)")
    limit: int = Field(..., description="Items per page")

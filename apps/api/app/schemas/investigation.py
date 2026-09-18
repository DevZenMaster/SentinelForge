"""Investigation Analytics and Correlation Schemas (Phase 8).

Defines request and response contracts for:
- Investigation anchors (Incident, Alert, Indicator, IP, Username)
- Bounded time window validation (max 30 days, UTC timestamps)
- Deterministic investigation summary metrics (counts, first/last seen, unique entities)
- Unified chronological investigation timeline entries
- Correlated entity summaries (Events, Alerts, Incidents, Indicators)
- Investigation context envelope
"""

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_INVESTIGATION_WINDOW_SECONDS: int = 2592000  # 30 days


class InvestigationAnchorType(StrEnum):
    """Supported entity anchors for initiating an investigation."""

    INCIDENT = "INCIDENT"
    ALERT = "ALERT"
    INDICATOR = "INDICATOR"
    SOURCE_IP = "SOURCE_IP"
    DESTINATION_IP = "DESTINATION_IP"
    USERNAME = "USERNAME"


class InvestigationAnchor(BaseModel):
    """Anchor defining the subject and temporal boundaries of an investigation."""

    model_config = ConfigDict(extra="forbid")

    anchor_type: InvestigationAnchorType = Field(
        ..., description="Type of anchor entity: INCIDENT, ALERT, INDICATOR, SOURCE_IP, etc."
    )
    anchor_value: str = Field(
        ..., min_length=1, max_length=256, description="Anchor identifier or value"
    )
    start_time: datetime | None = Field(
        default=None, description="Optional UTC lower temporal bound"
    )
    end_time: datetime | None = Field(default=None, description="Optional UTC upper temporal bound")
    window_seconds: int | None = Field(
        default=None,
        ge=1,
        le=MAX_INVESTIGATION_WINDOW_SECONDS,
        description=(
            f"Optional relative time window in seconds (max {MAX_INVESTIGATION_WINDOW_SECONDS})"
        ),
    )

    @model_validator(mode="after")
    def validate_temporal_bounds(self) -> "InvestigationAnchor":
        # Ensure timezone-awareness
        if self.start_time is not None:
            if self.start_time.tzinfo is None:
                self.start_time = self.start_time.replace(tzinfo=UTC)
        if self.end_time is not None:
            if self.end_time.tzinfo is None:
                self.end_time = self.end_time.replace(tzinfo=UTC)

        if self.start_time is not None and self.end_time is not None:
            if self.start_time > self.end_time:
                raise ValueError("start_time must be earlier than or equal to end_time")
            delta_sec = (self.end_time - self.start_time).total_seconds()
            if delta_sec > MAX_INVESTIGATION_WINDOW_SECONDS:
                raise ValueError(
                    f"Time window between start_time and end_time exceeds maximum allowed limit "
                    f"of {MAX_INVESTIGATION_WINDOW_SECONDS} seconds (30 days)"
                )
        return self


class InvestigationSummary(BaseModel):
    """Deterministic, aggregate metrics describing an investigation context.

    Note: These are objective counts and observations, never risk scores.
    """

    model_config = ConfigDict(extra="forbid")

    event_count: int = Field(default=0, description="Total correlated canonical events")
    alert_count: int = Field(default=0, description="Total correlated detection alerts")
    incident_count: int = Field(default=0, description="Total correlated incidents")
    indicator_count: int = Field(default=0, description="Total correlated threat indicators")
    first_seen: datetime | None = Field(
        default=None, description="Earliest observed timestamp across correlated evidence"
    )
    last_seen: datetime | None = Field(
        default=None, description="Latest observed timestamp across correlated evidence"
    )
    unique_source_ips: int = Field(
        default=0, description="Count of distinct source IPs in correlated evidence"
    )
    unique_destination_ips: int = Field(
        default=0, description="Count of distinct destination IPs in correlated evidence"
    )
    unique_usernames: int = Field(
        default=0, description="Count of distinct usernames in correlated evidence"
    )


class InvestigationTimelineEntry(BaseModel):
    """Unified chronological entry in an investigation timeline."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Stable compound identifier (e.g. event:<uuid>)")
    entity_type: str = Field(
        ...,
        description=(
            "Entity classification: EVENT, ALERT, INCIDENT, INDICATOR, NOTE, INTELLIGENCE"
        ),
    )
    entity_id: str = Field(..., description="Underlying entity identifier")
    timestamp: datetime = Field(
        ..., description="Primary sortable UTC timestamp for this timeline entry"
    )
    occurred_at: datetime | None = Field(
        default=None,
        description="Original telemetric occurrence timestamp if distinct from record time",
    )
    action_at: datetime | None = Field(
        default=None, description="Operational action or triage timestamp if distinct"
    )
    title: str = Field(..., description="Concise human-readable description of the timeline item")
    severity: str | None = Field(
        default=None, description="Associated severity rating if applicable"
    )
    details: dict[str, Any] = Field(
        default_factory=dict, description="Structured evidentiary attributes"
    )


class InvestigationTimelineResponse(BaseModel):
    """Paginated collection of unified timeline entries."""

    model_config = ConfigDict(extra="forbid")

    anchor: InvestigationAnchor
    total_entries: int
    page: int
    limit: int
    entries: list[InvestigationTimelineEntry]


class InvestigationEventSummary(BaseModel):
    """Summary of a canonical event matching investigation criteria.

    Excludes full raw_payload to protect bandwidth and prevent unauthorized data leakage.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    timestamp: datetime
    source: str
    source_type: str
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    event_type: str
    action: str
    outcome: str
    username: str | None = None
    severity: str
    message: str | None = None


class InvestigationAlertSummary(BaseModel):
    """Summary of a detection alert correlated with the investigation."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    rule_id: str
    rule_version: int
    title: str
    description: str
    severity: str
    status: str
    source_ip: str | None = None
    username: str | None = None
    correlation_key: str
    observed_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


class InvestigationIncidentSummary(BaseModel):
    """Summary of an incident correlated with the investigation."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    incident_id: str
    title: str
    description: str
    severity: str
    priority: str
    status: str
    created_at: datetime


class InvestigationIndicatorSummary(BaseModel):
    """Summary of a threat indicator correlated with the investigation."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    type: str
    normalized_value: str
    status: str
    sightings_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    is_threat: bool = False
    threat_sources: list[str] = Field(default_factory=list)
    highest_severity: str | None = None


class InvestigationContextResponse(BaseModel):
    """Top-level investigation envelope providing a 360-degree correlated perspective."""

    model_config = ConfigDict(extra="forbid")

    anchor: InvestigationAnchor
    summary: InvestigationSummary
    correlated_incidents: list[InvestigationIncidentSummary] = Field(default_factory=list)
    correlated_alerts: list[InvestigationAlertSummary] = Field(default_factory=list)
    correlated_events: list[InvestigationEventSummary] = Field(default_factory=list)
    correlated_indicators: list[InvestigationIndicatorSummary] = Field(default_factory=list)
    recent_timeline: list[InvestigationTimelineEntry] = Field(default_factory=list)


class PaginatedInvestigationEvents(BaseModel):
    """Paginated collection of correlated events."""

    model_config = ConfigDict(extra="forbid")

    anchor: InvestigationAnchor
    total: int
    page: int
    limit: int
    items: list[InvestigationEventSummary]


class PaginatedInvestigationAlerts(BaseModel):
    """Paginated collection of correlated alerts."""

    model_config = ConfigDict(extra="forbid")

    anchor: InvestigationAnchor
    total: int
    page: int
    limit: int
    items: list[InvestigationAlertSummary]


class PaginatedInvestigationIncidents(BaseModel):
    """Paginated collection of correlated incidents."""

    model_config = ConfigDict(extra="forbid")

    anchor: InvestigationAnchor
    total: int
    page: int
    limit: int
    items: list[InvestigationIncidentSummary]


class PaginatedInvestigationIndicators(BaseModel):
    """Paginated collection of correlated indicators."""

    model_config = ConfigDict(extra="forbid")

    anchor: InvestigationAnchor
    total: int
    page: int
    limit: int
    items: list[InvestigationIndicatorSummary]

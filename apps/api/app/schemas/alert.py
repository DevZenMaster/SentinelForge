"""Schemas for Security Alerts, Operational Triage, and Evidence Associations."""

import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.event import EventResponse
from app.schemas.incident import UserSummaryResponse

MAX_SUPPRESSION_DAYS: int = 90


class AlertStatus(StrEnum):
    """Authoritative lifecycle triage states for security alerts."""

    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    SUPPRESSED = "SUPPRESSED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


# ==============================================================================
# Request Payloads
# ==============================================================================


class AlertAcknowledgeRequest(BaseModel):
    """Request payload to acknowledge an alert."""

    model_config = ConfigDict(extra="forbid")

    comment: str | None = Field(
        default=None,
        max_length=1000,
        description="Optional acknowledgement comment or triage context",
    )
    expected_version: int | None = Field(
        default=None,
        ge=1,
        description="Expected alert version counter for optimistic concurrency protection",
    )


class AlertAssignRequest(BaseModel):
    """Request payload to assign or reassign an alert to an analyst."""

    model_config = ConfigDict(extra="forbid")

    assigned_to_user_id: uuid.UUID | None = Field(
        ..., description="Target user ID to assign, or null to unassign"
    )


class AlertStatusTransitionRequest(BaseModel):
    """Request payload to transition alert lifecycle status."""

    model_config = ConfigDict(extra="forbid")

    status: AlertStatus = Field(..., description="Target lifecycle state")
    comment: str | None = Field(
        default=None, max_length=1000, description="Context or justification for state change"
    )
    expected_version: int | None = Field(
        default=None,
        ge=1,
        description="Expected alert version counter for optimistic concurrency protection",
    )


class AlertSuppressRequest(BaseModel):
    """Request payload to suppress an alert."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        ..., min_length=5, max_length=1000, description="Mandatory justification for suppression"
    )
    suppressed_until: datetime | None = Field(
        default=None,
        description=(
            "Optional UTC expiration timestamp for suppression "
            f"(must be in future, max {MAX_SUPPRESSION_DAYS} days)"
        ),
    )

    @field_validator("reason")
    @classmethod
    def validate_reason_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 5:
            raise ValueError("Suppression reason must contain at least 5 non-whitespace characters")
        return stripped

    @model_validator(mode="after")
    def validate_suppressed_until(self) -> "AlertSuppressRequest":
        if self.suppressed_until is not None:
            now = datetime.now(UTC)
            target = self.suppressed_until
            if target.tzinfo is None:
                target = target.replace(tzinfo=UTC)
                self.suppressed_until = target
            if target <= now:
                raise ValueError("suppressed_until timestamp must be in the future")
            max_limit = now + timedelta(days=MAX_SUPPRESSION_DAYS)
            if target > max_limit:
                raise ValueError(
                    f"suppressed_until cannot exceed {MAX_SUPPRESSION_DAYS} days in the future"
                )
        return self


class AlertResolveRequest(BaseModel):
    """Request payload to resolve an alert."""

    model_config = ConfigDict(extra="forbid")

    resolution_notes: str = Field(
        ...,
        min_length=5,
        max_length=10000,
        description="Mandatory documentation explaining alert findings and remediation",
    )

    @field_validator("resolution_notes")
    @classmethod
    def validate_notes_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 5:
            raise ValueError("Resolution notes must contain at least 5 non-whitespace characters")
        return stripped


class AlertCloseRequest(BaseModel):
    """Request payload to close an alert."""

    model_config = ConfigDict(extra="forbid")

    notes: str | None = Field(
        default=None, max_length=10000, description="Optional closure summary notes"
    )


class AlertNoteCreateRequest(BaseModel):
    """Request payload to append an analyst triage note to an alert."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(
        ...,
        min_length=1,
        max_length=10000,
        description="Analyst triage note content (max 10,000 characters)",
    )

    @field_validator("content")
    @classmethod
    def validate_content_non_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("Note content cannot be empty or whitespace-only")
        return stripped


class AlertIncidentLinkRequest(BaseModel):
    """Request payload to link an alert to an existing incident case."""

    model_config = ConfigDict(extra="forbid")

    incident_id: uuid.UUID = Field(..., description="ID of the target incident case")


# ==============================================================================
# Operational Metadata & Supporting Responses
# ==============================================================================


class AlertPrioritizationMetadata(BaseModel):
    """Deterministic, explainable operational prioritization metadata."""

    priority_tier: str = Field(
        ..., description="Deterministic priority classification: CRITICAL, HIGH, MEDIUM, LOW"
    )
    priority_score: int = Field(
        ..., description="Deterministic composite score based strictly on persisted facts"
    )
    sla_breach: bool = Field(
        default=False, description="True if alert has exceeded the initial acknowledgement SLA"
    )
    age_seconds: int = Field(
        ...,
        description="Persisted age in seconds calculated from creation timestamp to current UTC",
    )
    is_assigned: bool = Field(default=False, description="Whether an analyst is actively assigned")
    is_acknowledged: bool = Field(
        default=False, description="Whether the alert has been acknowledged"
    )
    is_suppressed: bool = Field(
        default=False, description="Whether the alert is currently suppressed"
    )
    is_resolved: bool = Field(default=False, description="Whether the alert has been resolved")
    is_closed: bool = Field(default=False, description="Whether the alert has been closed")
    linked_incident_count: int = Field(default=0, description="Number of associated incident cases")
    notes_count: int = Field(default=0, description="Number of analyst triage notes")
    evidence_count: int = Field(default=0, description="Number of triggering evidence events")
    factors: list[str] = Field(
        default_factory=list, description="Explainable factual drivers for the priority assignment"
    )


class AlertNoteResponse(BaseModel):
    """Representation of an analyst triage note attached to an alert."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    author: UserSummaryResponse
    content: str
    created_at: datetime
    updated_at: datetime


class AlertNoteListResponse(BaseModel):
    """Paginated collection of analyst triage notes."""

    items: list[AlertNoteResponse] = Field(..., description="Notes for current page")
    total: int = Field(..., description="Total matching notes count")
    page: int = Field(..., description="Current page index (1-based)")
    limit: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total available pages")


class AlertIncidentSummary(BaseModel):
    """Summary of an incident linked to an alert."""

    model_config = ConfigDict(from_attributes=True)

    incident_id: uuid.UUID
    incident_ticket: str
    title: str
    severity: str
    status: str
    linked_at: datetime


class AlertInvestigationLink(BaseModel):
    """Deterministic link to Phase 8 unified investigation analytics."""

    alert_id: uuid.UUID
    anchor_type: str = "ALERT"
    anchor_value: str
    context_url: str
    summary_url: str
    timeline_url: str


# ==============================================================================
# Primary Alert Representations
# ==============================================================================


class AlertResponse(BaseModel):
    """Complete representation of a security alert with operational metadata."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique internal alert identifier")
    rule_id: str = Field(..., description="Triggering rule identifier")
    rule_version: int = Field(default=1, description="Rule version at time of alert creation")
    title: str = Field(..., description="Alert headline title")
    description: str = Field(..., description="Detailed description of the detection condition")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field(
        ...,
        description=(
            "Alert triage state: OPEN, ACKNOWLEDGED, IN_PROGRESS, SUPPRESSED, RESOLVED, CLOSED"
        ),
    )
    dedup_key: str = Field(..., description="Deterministic deduplication key")
    correlation_key: str = Field(..., description="Pivot entity correlation key")
    observed_count: int = Field(..., description="Count of qualifying events in the window")
    threshold: int = Field(..., description="Configured rule threshold")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Explainable detection telemetry"
    )
    source_ip: str | None = Field(default=None, description="Pivot source IP if applicable")
    username: str | None = Field(default=None, description="Pivot username if applicable")
    first_seen: datetime = Field(..., description="Earliest event timestamp in detection window")
    last_seen: datetime = Field(..., description="Latest event timestamp in detection window")

    # Operational Assignment
    assignee_id: uuid.UUID | None = Field(default=None, description="Assigned analyst ID")
    assignee: UserSummaryResponse | None = Field(
        default=None, description="Assigned analyst profile"
    )
    assigned_at: datetime | None = Field(default=None, description="Timestamp of assignment")

    # Operational Lifecycle Attributions
    acknowledged_by_id: uuid.UUID | None = Field(default=None)
    acknowledged_by: UserSummaryResponse | None = Field(default=None)
    acknowledged_at: datetime | None = Field(default=None)

    resolved_by_id: uuid.UUID | None = Field(default=None)
    resolved_by: UserSummaryResponse | None = Field(default=None)
    resolved_at: datetime | None = Field(default=None)
    resolution_notes: str | None = Field(default=None)

    closed_by_id: uuid.UUID | None = Field(default=None)
    closed_by: UserSummaryResponse | None = Field(default=None)
    closed_at: datetime | None = Field(default=None)

    # Operational Suppression
    suppressed_by_id: uuid.UUID | None = Field(default=None)
    suppressed_by: UserSummaryResponse | None = Field(default=None)
    suppressed_at: datetime | None = Field(default=None)
    suppression_reason: str | None = Field(default=None)
    suppressed_until: datetime | None = Field(default=None)

    # Concurrency & Prioritization
    version: int = Field(default=1, description="Optimistic concurrency control version")
    prioritization: AlertPrioritizationMetadata | None = Field(
        default=None, description="Deterministic operational prioritization telemetry"
    )

    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


class AlertDetailResponse(AlertResponse):
    """Extended alert representation including evidence, notes, and links."""

    evidence_event_ids: list[uuid.UUID] = Field(
        default_factory=list, description="IDs of linked evidence events"
    )
    evidence_events: list[EventResponse] = Field(
        default_factory=list, description="Constituent canonical security events"
    )
    notes: list[AlertNoteResponse] = Field(
        default_factory=list, description="Analyst triage notes in chronological order"
    )
    linked_incidents: list[AlertIncidentSummary] = Field(
        default_factory=list, description="Correlated incident cases"
    )
    investigation: AlertInvestigationLink | None = Field(
        default=None, description="Phase 8 investigation analytics link"
    )


class AlertListResponse(BaseModel):
    """Paginated collection of security alerts."""

    items: list[AlertResponse] = Field(..., description="Alert records for current page")
    total: int = Field(..., description="Total matching alert count")
    page: int = Field(..., description="Current page index (1-based)")
    limit: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total pages available")

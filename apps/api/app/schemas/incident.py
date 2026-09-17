"""Pydantic Schemas for Incident Management and Investigation (Phase 6).

Defines strict request models, response serialization, and lifecycle validation
for incidents, alerts grouping, direct forensic event evidence, and notes.
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class IncidentSeverity(StrEnum):
    """Security significance of the incident."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentPriority(StrEnum):
    """Operational triage handling priority / SLA urgency."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    URGENT = "URGENT"


class IncidentStatus(StrEnum):
    """Lifecycle status states for an incident."""

    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class IncidentResolutionCategory(StrEnum):
    """Structured resolution classification."""

    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    BENIGN_POSITIVE = "BENIGN_POSITIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    DUPLICATE = "DUPLICATE"


class TimelineEntryType(StrEnum):
    """Type of timeline event."""

    INCIDENT_CREATED = "INCIDENT_CREATED"
    STATUS_CHANGED = "STATUS_CHANGED"
    ASSIGNMENT_CHANGED = "ASSIGNMENT_CHANGED"
    ALERT_ATTACHED = "ALERT_ATTACHED"
    ALERT_DETACHED = "ALERT_DETACHED"
    EVIDENCE_ATTACHED = "EVIDENCE_ATTACHED"
    EVIDENCE_DETACHED = "EVIDENCE_DETACHED"
    NOTE_ADDED = "NOTE_ADDED"


# ==============================================================================
# Request Schemas
# ==============================================================================


class IncidentCreateRequest(BaseModel):
    """Payload to open a new incident case file."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=3, max_length=255, description="Incident title")
    description: str = Field(
        ..., min_length=5, max_length=10000, description="Detailed case description"
    )
    severity: IncidentSeverity = Field(..., description="Security significance")
    priority: IncidentPriority = Field(
        default=IncidentPriority.MEDIUM, description="Operational urgency"
    )
    assigned_to_user_id: uuid.UUID | None = Field(
        default=None, description="Initial assigned analyst"
    )
    alert_ids: list[uuid.UUID] | None = Field(
        default=None, description="Optional initial alerts to correlate"
    )
    event_ids: list[uuid.UUID] | None = Field(
        default=None, description="Optional initial event evidence to link"
    )
    initial_note: str | None = Field(
        default=None, min_length=1, max_length=10000, description="Optional opening note"
    )


class IncidentUpdateRequest(BaseModel):
    """Payload to update core incident properties."""

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, min_length=5, max_length=10000)
    severity: IncidentSeverity | None = Field(default=None)
    priority: IncidentPriority | None = Field(default=None)


class IncidentStatusTransitionRequest(BaseModel):
    """Payload to transition incident lifecycle status."""

    model_config = ConfigDict(extra="forbid")

    status: IncidentStatus = Field(..., description="Target lifecycle state")
    resolution_category: IncidentResolutionCategory | None = Field(
        default=None, description="Required when status is RESOLVED"
    )
    resolution_notes: str | None = Field(
        default=None, max_length=10000, description="Required when status is RESOLVED"
    )
    comment: str | None = Field(
        default=None, max_length=10000, description="Context/reason for status change"
    )

    @model_validator(mode="after")
    def validate_transition_fields(self) -> "IncidentStatusTransitionRequest":
        if self.status == IncidentStatus.RESOLVED:
            if not self.resolution_category:
                raise ValueError("resolution_category is required when resolving an incident")
            if not self.resolution_notes or len(self.resolution_notes.strip()) < 5:
                raise ValueError(
                    "resolution_notes (minimum 5 characters) is required when resolving an incident"
                )
        elif self.status == IncidentStatus.REOPENED:
            if not self.comment or len(self.comment.strip()) < 3:
                raise ValueError(
                    "comment (minimum 3 characters) is required when reopening an incident"
                )
        return self


class IncidentAssignRequest(BaseModel):
    """Payload to assign or reassign an analyst to an incident."""

    model_config = ConfigDict(extra="forbid")

    assigned_to_user_id: uuid.UUID | None = Field(
        ..., description="Target user ID or None to unassign"
    )


class IncidentAlertAttachRequest(BaseModel):
    """Payload to link an alert to an incident."""

    model_config = ConfigDict(extra="forbid")

    alert_id: uuid.UUID = Field(..., description="ID of alert to attach")


class IncidentEventAttachRequest(BaseModel):
    """Payload to link an event as forensic evidence."""

    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID = Field(..., description="ID of security event to attach as evidence")


class IncidentNoteCreateRequest(BaseModel):
    """Payload to add an investigation note."""

    model_config = ConfigDict(extra="forbid")

    content: str = Field(
        ..., min_length=1, max_length=10000, description="Investigation note content"
    )


# ==============================================================================
# Response Schemas
# ==============================================================================


class UserSummaryResponse(BaseModel):
    """Attribution summary of a system user."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    full_name: str | None = None


class IncidentAlertSummaryResponse(BaseModel):
    """Summary of an alert linked to an incident."""

    model_config = ConfigDict(from_attributes=True)

    alert_id: uuid.UUID
    rule_id: str
    title: str
    severity: str
    status: str
    added_at: datetime
    added_by_user_id: uuid.UUID | None = None


class IncidentEventSummaryResponse(BaseModel):
    """Summary of a raw security event linked as forensic evidence."""

    model_config = ConfigDict(from_attributes=True)

    event_id: uuid.UUID
    timestamp: datetime = Field(..., description="Telemetric occurrence timestamp")
    event_type: str
    action: str
    source: str
    source_ip: str | None = None
    username: str | None = None
    severity: str
    added_at: datetime = Field(..., description="Forensic attachment timestamp")
    added_by_user_id: uuid.UUID | None = None


class IncidentNoteResponse(BaseModel):
    """Investigation note record with server-authenticated author attribution."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: uuid.UUID
    author: UserSummaryResponse
    content: str
    created_at: datetime
    updated_at: datetime


class IncidentResponse(BaseModel):
    """Core summary representation of an incident."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    priority: IncidentPriority
    status: IncidentStatus
    assigned_to: UserSummaryResponse | None = None
    created_by: UserSummaryResponse | None = None
    resolved_by: UserSummaryResponse | None = None
    closed_by: UserSummaryResponse | None = None
    resolved_at: datetime | None = None
    resolution_category: IncidentResolutionCategory | None = None
    resolution_notes: str | None = None
    closed_at: datetime | None = None
    alerts_count: int = 0
    events_count: int = 0
    notes_count: int = 0
    created_at: datetime
    updated_at: datetime


class IncidentDetailResponse(IncidentResponse):
    """Comprehensive incident case file including full alerts, events, and notes."""

    alerts: list[IncidentAlertSummaryResponse] = []
    events: list[IncidentEventSummaryResponse] = []
    notes: list[IncidentNoteResponse] = []


class IncidentListResponse(BaseModel):
    """Paginated collection of incidents."""

    items: list[IncidentResponse]
    total: int
    page: int
    limit: int


class IncidentTimelineEntry(BaseModel):
    """Unified chronological entry in an incident investigation timeline."""

    id: str
    entry_type: TimelineEntryType
    timestamp: datetime = Field(
        ..., description="UTC timestamp of the timeline investigation action"
    )
    event_timestamp: datetime | None = Field(
        default=None, description="Original telemetric occurrence timestamp if applicable"
    )
    actor: UserSummaryResponse | None = None
    title: str
    details: dict[str, Any] = Field(default_factory=dict)
    reference_id: str | None = None


class IncidentTimelineResponse(BaseModel):
    """Unified chronological investigation timeline."""

    incident_id: str
    total_entries: int
    entries: list[IncidentTimelineEntry]

"""Schemas for Security Alerts and Evidence Associations."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.event import EventResponse


class AlertResponse(BaseModel):
    """Complete representation of a security alert."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="Unique internal alert identifier")
    rule_id: str = Field(..., description="Triggering rule identifier")
    rule_version: int = Field(default=1, description="Rule version at time of alert creation")
    title: str = Field(..., description="Alert headline title")
    description: str = Field(..., description="Detailed description of the detection condition")
    severity: str = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field(
        ..., description="Alert triage state: OPEN, ACKNOWLEDGED, RESOLVED, DISMISSED"
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
    acknowledged_at: datetime | None = Field(default=None)
    resolved_at: datetime | None = Field(default=None)
    resolution_notes: str | None = Field(default=None)
    created_at: datetime = Field(...)
    updated_at: datetime = Field(...)


class AlertDetailResponse(AlertResponse):
    """Extended alert representation including linked forensic evidence events."""

    evidence_event_ids: list[uuid.UUID] = Field(
        default_factory=list, description="IDs of linked evidence events"
    )
    evidence_events: list[EventResponse] = Field(
        default_factory=list, description="Constituent canonical security events"
    )


class AlertListResponse(BaseModel):
    """Paginated collection of security alerts."""

    items: list[AlertResponse] = Field(..., description="Alert records for current page")
    total: int = Field(..., description="Total matching alert count")
    page: int = Field(..., description="Current page index (1-based)")
    limit: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total pages available")

"""Pydantic v2 Schemas for Detection Rule Management & Versioning (Phase 9)."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionRuleCreate(BaseModel):
    """Schema for authoring a new detection rule."""

    rule_id: str = Field(
        ...,
        min_length=3,
        max_length=32,
        pattern=r"^[A-Za-z0-9_-]{3,32}$",
        description="Unique stable rule identifier e.g. RULE-001",
    )
    name: str = Field(..., min_length=3, max_length=128)
    description: str = Field(..., min_length=5, max_length=2048)
    severity: str = Field(..., description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    category: str = Field(default="security", min_length=2, max_length=32)
    event_type: str = Field(..., description="Target canonical event type")
    threshold: int = Field(..., ge=1, le=10000)
    time_window_seconds: int = Field(..., ge=10, le=86400)
    conditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured declarative conditions (filters, group_by, aggregation)",
    )


class DetectionRuleUpdate(BaseModel):
    """Schema for modifying an editable DRAFT rule version."""

    name: str | None = Field(default=None, min_length=3, max_length=128)
    description: str | None = Field(default=None, min_length=5, max_length=2048)
    severity: str | None = None
    category: str | None = Field(default=None, min_length=2, max_length=32)
    event_type: str | None = None
    threshold: int | None = Field(default=None, ge=1, le=10000)
    time_window_seconds: int | None = Field(default=None, ge=10, le=86400)
    conditions: dict[str, Any] | None = None


class DetectionRuleVersionCreate(BaseModel):
    """Schema for creating a subsequent version of an existing rule."""

    name: str | None = Field(default=None, min_length=3, max_length=128)
    description: str | None = Field(default=None, min_length=5, max_length=2048)
    severity: str | None = None
    category: str | None = None
    event_type: str | None = None
    threshold: int | None = Field(default=None, ge=1, le=10000)
    time_window_seconds: int | None = Field(default=None, ge=10, le=86400)
    conditions: dict[str, Any] | None = None


class DetectionRuleDetailResponse(BaseModel):
    """Detailed view of a detection rule version."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    version: int
    name: str
    description: str
    severity: str
    category: str
    status: str
    enabled: bool
    event_type: str
    threshold: int
    time_window_seconds: int
    conditions: dict[str, Any]
    created_at: datetime
    updated_at: datetime
    created_by: uuid.UUID | None = None
    updated_by: uuid.UUID | None = None
    activated_at: datetime | None = None
    activated_by: uuid.UUID | None = None


class DetectionRuleVersionSummary(BaseModel):
    """Summary of a specific rule version in history."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    version: int
    name: str
    status: str
    enabled: bool
    severity: str
    threshold: int
    time_window_seconds: int
    created_at: datetime
    activated_at: datetime | None = None


class DetectionRuleListResponse(BaseModel):
    """Paginated response for detection rule listings."""

    items: list[DetectionRuleDetailResponse]
    total: int
    page: int
    limit: int
    total_pages: int


class DetectionRuleValidationRequest(BaseModel):
    """Dry-run payload for rule validation endpoint."""

    rule_id: str | None = None
    version: int | None = None
    name: str | None = None
    description: str | None = None
    severity: str | None = None
    category: str | None = None
    event_type: str | None = None
    threshold: int | None = None
    time_window_seconds: int | None = None
    conditions: dict[str, Any] | None = None


class DetectionRuleValidationResponse(BaseModel):
    """Outcome of declarative rule dry-run validation."""

    valid: bool
    errors: list[str]

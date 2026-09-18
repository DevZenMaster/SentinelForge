"""Pydantic schemas for Notification & Integration Subsystem (Phase 13).

Enforces strict input validation, secret masking, declarative filter allowlists,
bounded query parameters, and fail-closed security guarantees.
"""

import re
import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Declarative policy allowed filter fields
ALLOWED_FILTER_FIELDS = frozenset(
    {"rule_id", "rule_version", "status", "severity", "destination_type", "event_type"}
)

ALLOWED_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"})


class DestinationType(StrEnum):
    """Supported external notification destination types."""

    WEBHOOK = "WEBHOOK"
    EMAIL = "EMAIL"


class DeliveryStatus(StrEnum):
    """Explicit lifecycle states for notification delivery jobs."""

    PENDING = "PENDING"
    DELIVERING = "DELIVERING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"
    EXHAUSTED = "EXHAUSTED"
    CANCELLED = "CANCELLED"


class NotificationEventType(StrEnum):
    """Enumerated authoritative security operations events."""

    ALERT_CREATED = "ALERT_CREATED"
    ALERT_ESCALATED = "ALERT_ESCALATED"
    ALERT_ASSIGNED = "ALERT_ASSIGNED"
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    ALERT_CLOSED = "ALERT_CLOSED"
    ALERT_SUPPRESSED = "ALERT_SUPPRESSED"
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_STATE_CHANGED = "INCIDENT_STATE_CHANGED"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"
    SLA_BREACH_DETECTED = "SLA_BREACH_DETECTED"
    REPORT_EXPORTED = "REPORT_EXPORTED"


def mask_secret(secret: str | None) -> tuple[bool, str | None]:
    """Mask sensitive secret token for safe API response serialization."""
    if not secret:
        return False, None
    clean = secret.strip()
    if len(clean) <= 4:
        return True, "••••"
    return True, f"••••••••{clean[-4:]}"


# ==============================================================================
# Integration (Destination) Schemas
# ==============================================================================


class IntegrationCreate(BaseModel):
    """Payload for registering a new external notification destination."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., min_length=1, max_length=128, description="Unique destination name")
    type: DestinationType
    enabled: bool = Field(default=True)
    endpoint_url: str | None = Field(default=None, max_length=1024)
    email_recipients: list[str] | None = Field(default=None, max_length=20)
    secret_token: str | None = Field(
        default=None,
        min_length=16,
        max_length=512,
        description=(
            "Write-only HMAC signing secret or token. Auto-generated if omitted for webhooks."
        ),
    )

    @field_validator("email_recipients")
    @classmethod
    def validate_emails(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        email_regex = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        cleaned: list[str] = []
        for email in v:
            clean = email.strip().lower()
            if not email_regex.match(clean):
                raise ValueError(f"Invalid email address: '{email}'")
            if clean not in cleaned:
                cleaned.append(clean)
        return cleaned

    @model_validator(mode="after")
    def validate_destination_config(self) -> "IntegrationCreate":
        if self.type == DestinationType.WEBHOOK:
            if not self.endpoint_url:
                raise ValueError("endpoint_url is required for WEBHOOK destination type.")
            url = self.endpoint_url.lower()
            if not (url.startswith("https://") or url.startswith("http://")):
                raise ValueError("endpoint_url must start with https:// (or http:// in dev).")
        elif self.type == DestinationType.EMAIL:
            if not self.email_recipients or len(self.email_recipients) == 0:
                raise ValueError("email_recipients must contain at least 1 valid recipient email.")
        return self


class IntegrationUpdate(BaseModel):
    """Payload for modifying an existing external destination."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=128)
    endpoint_url: str | None = Field(default=None, max_length=1024)
    email_recipients: list[str] | None = Field(default=None, max_length=20)
    secret_token: str | None = Field(
        default=None, min_length=16, max_length=512, description="Write-only replacement secret"
    )
    enabled: bool | None = None
    version: int = Field(..., description="Optimistic concurrency version check")

    @field_validator("email_recipients")
    @classmethod
    def validate_emails(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        email_regex = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        cleaned: list[str] = []
        for email in v:
            clean = email.strip().lower()
            if not email_regex.match(clean):
                raise ValueError(f"Invalid email address: '{email}'")
            if clean not in cleaned:
                cleaned.append(clean)
        return cleaned


class IntegrationResponse(BaseModel):
    """Safe, sanitized representation of an integration destination."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    type: str
    enabled: bool
    endpoint_url: str | None
    email_recipients: list[str] | None
    is_secret_configured: bool
    secret_preview: str | None
    created_by_user_id: uuid.UUID | None
    updated_by_user_id: uuid.UUID | None
    last_delivery_at: datetime | None
    last_successful_delivery_at: datetime | None
    last_failed_delivery_at: datetime | None
    version: int
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# Notification Policy Schemas
# ==============================================================================


class NotificationPolicyCreate(BaseModel):
    """Payload for defining a declarative notification routing policy."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(..., min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    enabled: bool = Field(default=True)
    event_types: list[NotificationEventType] = Field(..., min_length=1)
    min_severity: str | None = Field(default=None)
    destination_ids: list[uuid.UUID] = Field(..., min_length=1, max_length=10)
    filters: dict[str, Any] = Field(default_factory=dict)
    cooldown_seconds: int = Field(default=0, ge=0, le=86400)

    @field_validator("min_severity")
    @classmethod
    def validate_severity(cls, v: str | None) -> str | None:
        if v is not None and v.upper() not in ALLOWED_SEVERITIES:
            raise ValueError(f"min_severity must be one of {sorted(ALLOWED_SEVERITIES)}")
        return v.upper() if v else None

    @field_validator("filters")
    @classmethod
    def validate_filters(cls, v: dict[str, Any]) -> dict[str, Any]:
        for key, val in v.items():
            if key not in ALLOWED_FILTER_FIELDS:
                msg = (
                    f"Unsupported filter field '{key}'. "
                    f"Allowed fields: {sorted(ALLOWED_FILTER_FIELDS)}"
                )
                raise ValueError(msg)
            if not isinstance(val, (str, int, float, bool, list)):
                msg = f"Filter value for '{key}' must be a primitive or list of primitives."
                raise ValueError(msg)
        return v


class NotificationPolicyUpdate(BaseModel):
    """Payload for updating an existing declarative notification policy."""

    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=1000)
    enabled: bool | None = None
    event_types: list[NotificationEventType] | None = Field(default=None, min_length=1)
    min_severity: str | None = None
    destination_ids: list[uuid.UUID] | None = Field(default=None, min_length=1, max_length=10)
    filters: dict[str, Any] | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0, le=86400)
    version: int = Field(..., description="Optimistic concurrency version check")

    @field_validator("min_severity")
    @classmethod
    def validate_severity(cls, v: str | None) -> str | None:
        if v is not None and v.upper() not in ALLOWED_SEVERITIES:
            raise ValueError(f"min_severity must be one of {sorted(ALLOWED_SEVERITIES)}")
        return v.upper() if v else None

    @field_validator("filters")
    @classmethod
    def validate_filters(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is None:
            return None
        for key, val in v.items():
            if key not in ALLOWED_FILTER_FIELDS:
                msg = (
                    f"Unsupported filter field '{key}'. "
                    f"Allowed fields: {sorted(ALLOWED_FILTER_FIELDS)}"
                )
                raise ValueError(msg)
            if not isinstance(val, (str, int, float, bool, list)):
                msg = f"Filter value for '{key}' must be a primitive or list of primitives."
                raise ValueError(msg)
        return v


class NotificationPolicyResponse(BaseModel):
    """Sanitized representation of a notification policy."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    enabled: bool
    event_types: list[str]
    min_severity: str | None
    destination_ids: list[str]
    filters: dict[str, Any]
    cooldown_seconds: int
    created_by_user_id: uuid.UUID | None
    updated_by_user_id: uuid.UUID | None
    version: int
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# Notification Delivery Schemas
# ==============================================================================


class NotificationDeliveryResponse(BaseModel):
    """Sanitized representation of a notification delivery job and execution status."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    event_id: uuid.UUID
    event_type: str
    source_resource_type: str
    source_resource_id: str
    policy_id: uuid.UUID
    policy_name: str
    destination_id: uuid.UUID
    destination_name: str
    destination_type: str
    idempotency_key: str
    status: str
    attempt_count: int
    max_attempts: int
    first_attempted_at: datetime | None
    last_attempted_at: datetime | None
    next_retry_at: datetime | None
    delivered_at: datetime | None
    http_status: int | None
    failure_reason: str | None
    response_metadata: dict[str, Any]
    created_at: datetime
    updated_at: datetime


# ==============================================================================
# Testing & Diagnostics Schemas
# ==============================================================================


class NotificationTestRequest(BaseModel):
    """Payload for manual destination connectivity testing."""

    model_config = ConfigDict(str_strip_whitespace=True)
    custom_message: str | None = Field(default=None, max_length=256)


class NotificationTestResponse(BaseModel):
    """Results of destination connectivity test."""

    destination_id: uuid.UUID
    destination_name: str
    destination_type: str
    status: str  # SUCCESS, FAILED
    http_status: int | None
    message: str
    latency_ms: float

"""Domain and contract models for Event Normalization & Canonicalization.

Defines:
- Controlled NormalizationStatus (PENDING, NORMALIZED, PARTIAL, FAILED)
- EventOutcome (success, failure, unknown)
- Structured NormalizationError and canonical error codes
- CanonicalEventData strongly-typed derived representation
- NormalizationResult envelope
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.event import EventSeverity, SourceType


class NormalizationStatus(StrEnum):
    """Lifecycle status of the event normalization pipeline."""

    PENDING = "PENDING"
    NORMALIZED = "NORMALIZED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class EventOutcome(StrEnum):
    """Canonical result classification for security events."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class NormalizationErrorCode(StrEnum):
    """Machine-readable normalization error classifications."""

    INVALID_TIMESTAMP = "INVALID_TIMESTAMP"
    INVALID_IP = "INVALID_IP"
    INVALID_PORT = "INVALID_PORT"
    MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD"
    UNSUPPORTED_SOURCE = "UNSUPPORTED_SOURCE"
    PARSER_ERROR = "PARSER_ERROR"
    PAYLOAD_STRUCTURE_ERROR = "PAYLOAD_STRUCTURE_ERROR"


class NormalizationError(BaseModel):
    """Structured diagnostic error record for normalization issues."""

    code: str = Field(..., description="Standardized error classification code")
    field: str | None = Field(default=None, description="Problematic field path if applicable")
    message: str = Field(..., description="Safe diagnostic description without raw secret content")


class CanonicalEventData(BaseModel):
    """Strongly-typed derived canonical representation for SIEM detection evaluation."""

    event_type: str = Field(
        ..., description="Normalized event category (e.g. authentication, web, network)"
    )
    action: str = Field(
        ..., description="Normalized operation performed (e.g. login_failed, http_401)"
    )
    outcome: EventOutcome = Field(
        default=EventOutcome.UNKNOWN, description="Deterministic operation result"
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO, description="Taxonomic severity level"
    )
    timestamp: datetime = Field(..., description="Timezone-aware UTC event timestamp")
    source: str = Field(..., description="Log source or sensor identifier")
    source_type: SourceType | str = Field(
        default=SourceType.GENERIC, description="Source classification"
    )
    source_ip: str | None = Field(default=None, description="Validated source IP address")
    destination_ip: str | None = Field(default=None, description="Validated destination IP address")
    source_port: int | None = Field(default=None, description="Validated source port (0-65535)")
    destination_port: int | None = Field(
        default=None, description="Validated destination port (0-65535)"
    )
    username: str | None = Field(default=None, description="Sanitized security principal name")
    message: str | None = Field(default=None, description="Human-readable message")
    attributes: dict[str, Any] = Field(
        default_factory=dict, description="Extracted source-specific telemetry"
    )


class NormalizationResult(BaseModel):
    """Complete outcome of normalizing a single security event."""

    status: NormalizationStatus = Field(..., description="Pipeline execution outcome status")
    canonical_data: CanonicalEventData | None = Field(
        default=None, description="Extracted canonical attributes if not FAILED"
    )
    parser_name: str = Field(..., description="Identifier of the executing parser")
    parser_version: str = Field(..., description="Semantic version of the parser logic")
    normalization_version: str = Field(
        ..., description="Semantic version of the canonical contract"
    )
    errors: list[NormalizationError] = Field(
        default_factory=list, description="Diagnostic error records encountered during processing"
    )

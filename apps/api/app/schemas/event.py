"""Pydantic Schemas for Security Event Ingestion.

Implements strict validation for:
- Severity enumeration (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- Source types taxonomy
- IPv4/IPv6 validation via standard library ipaddress without DNS lookups
- Timezone-aware UTC timestamps with temporal bounds
- Payload size boundaries
- Idempotency status outcomes
"""

import ipaddress
import json
import uuid
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import settings


class EventSeverity(StrEnum):
    """Standardized event severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SourceType(StrEnum):
    """Supported security log source classifications."""

    GENERIC = "generic"
    SYSLOG = "syslog"
    APPLICATION = "application"
    WEB = "web"
    LINUX = "linux"
    WINDOWS = "windows"
    FIREWALL = "firewall"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    CLOUD = "cloud"
    CUSTOM = "custom"


class EventCreateRequest(BaseModel):
    """Strict schema for accepting raw security events into the ingestion pipeline."""

    model_config = ConfigDict(extra="forbid")

    external_event_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Optional unique external identifier or client idempotency key",
    )
    timestamp: datetime = Field(
        ...,
        description="Timezone-aware UTC timestamp when the security event occurred",
    )
    source: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Originating log source or sensor name",
    )
    source_type: SourceType = Field(
        default=SourceType.GENERIC,
        description="Classification category of the source log producer",
    )
    source_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Originating source IPv4 or IPv6 address",
    )
    destination_ip: str | None = Field(
        default=None,
        max_length=45,
        description="Destination target IPv4 or IPv6 address",
    )
    destination_port: int | None = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination network port (0-65535)",
    )
    event_type: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Event category or telemetry event code",
    )
    action: str = Field(
        default="observed",
        min_length=1,
        max_length=64,
        description="Action taken or recorded by the sensor",
    )
    username: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Associated user account or security principal",
    )
    severity: EventSeverity = Field(
        default=EventSeverity.INFO,
        description="Event severity classification",
    )
    message: str | None = Field(
        default=None,
        max_length=4096,
        description="Human-readable event message or descriptive text",
    )
    raw_payload: dict[str, Any] = Field(
        ...,
        description="Full verbatim raw event payload to preserve evidentiary integrity",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional ingestion metadata tags",
    )

    @field_validator("external_event_id", mode="before")
    @classmethod
    def sanitize_external_event_id(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
        return v

    @field_validator("source", "event_type", "action", mode="before")
    @classmethod
    def strip_required_strings(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                raise ValueError("Value cannot be empty or whitespace only")
        return v

    @field_validator("username", mode="before")
    @classmethod
    def sanitize_username(cls, v: Any) -> Any:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return None
        return v

    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v: Any) -> Any:
        if isinstance(v, str):
            normalized = v.strip().upper()
            try:
                return EventSeverity(normalized)
            except ValueError:
                raise ValueError(
                    f"Invalid severity '{v}'. Allowed values: {[s.value for s in EventSeverity]}"
                ) from None
        return v

    @field_validator("source_type", mode="before")
    @classmethod
    def normalize_source_type(cls, v: Any) -> Any:
        if isinstance(v, str):
            normalized = v.strip().lower()
            try:
                return SourceType(normalized)
            except ValueError:
                raise ValueError(
                    f"Invalid source_type '{v}'. Allowed values: {[s.value for s in SourceType]}"
                ) from None
        return v

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() is None:
            raise ValueError(
                "Timestamp must be timezone-aware (e.g., ISO 8601 with UTC offset like "
                "'2026-09-17T09:00:00Z')"
            )
        utc_ts = v.astimezone(UTC)
        now = datetime.now(UTC)

        # Allow 5-minute future clock skew margin
        if utc_ts > now + timedelta(minutes=5):
            raise ValueError("Event timestamp cannot be more than 5 minutes in the future")

        # Disallow timestamps older than 365 days
        if utc_ts < now - timedelta(days=365):
            raise ValueError("Event timestamp cannot be older than 365 days")

        return utc_ts

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def validate_ip_address(cls, v: str | None) -> str | None:
        if v is None:
            return None
        clean_ip = v.strip()
        if not clean_ip:
            return None
        try:
            # Strictly validates IPv4 or IPv6 format without any DNS resolution
            parsed = ipaddress.ip_address(clean_ip)
            return str(parsed)
        except ValueError:
            raise ValueError(f"Invalid IP address format: '{clean_ip}'") from None

    @field_validator("raw_payload")
    @classmethod
    def validate_raw_payload(cls, v: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("raw_payload must be a valid JSON object/dictionary")
        try:
            serialized = json.dumps(v).encode("utf-8")
        except (TypeError, OverflowError) as exc:
            raise ValueError(f"raw_payload must be valid JSON: {exc}") from exc

        if len(serialized) > settings.MAX_EVENT_PAYLOAD_BYTES:
            raise ValueError(
                f"raw_payload size ({len(serialized)} bytes) exceeds maximum "
                f"permitted payload limit of {settings.MAX_EVENT_PAYLOAD_BYTES} bytes"
            )

        # Defensive recursion guard against deeply nested payloads (DoS prevention)
        def _check_depth(obj: Any, current_depth: int = 1, max_depth: int = 8) -> None:
            if current_depth > max_depth:
                raise ValueError(f"raw_payload exceeds maximum nesting depth of {max_depth}")
            if isinstance(obj, dict):
                for val in obj.values():
                    _check_depth(val, current_depth + 1, max_depth)
            elif isinstance(obj, list):
                for item in obj:
                    _check_depth(item, current_depth + 1, max_depth)

        _check_depth(v)
        return v


class EventIngestData(BaseModel):
    """Payload data returned after event ingestion processing."""

    event_id: uuid.UUID = Field(..., description="Unique internal event identifier")
    external_event_id: str | None = Field(
        default=None, description="Client or external idempotency identifier"
    )
    status: Literal["ingested", "duplicate"] = Field(
        ...,
        description="Ingestion outcome: 'ingested' for new events, 'duplicate' for retries",
    )
    ingested_at: datetime = Field(
        ..., description="UTC timestamp when the event was committed to storage"
    )
    timestamp: datetime = Field(..., description="Original event occurrence timestamp")


class EventResponse(BaseModel):
    """Complete representation of a stored security event."""

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: uuid.UUID = Field(..., description="Unique internal event identifier")
    external_event_id: str | None = Field(default=None)
    timestamp: datetime = Field(...)
    ingested_at: datetime = Field(...)
    source: str = Field(...)
    source_type: str = Field(...)
    source_ip: str | None = Field(default=None)
    destination_ip: str | None = Field(default=None)
    source_port: int | None = Field(default=None)
    destination_port: int | None = Field(default=None)
    event_type: str = Field(...)
    action: str = Field(...)
    outcome: str = Field(default="unknown")
    username: str | None = Field(default=None)
    severity: str = Field(...)
    message: str | None = Field(default=None)
    request_id: str | None = Field(default=None)
    raw_payload: dict[str, Any] = Field(...)
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_")
    normalization_status: str = Field(default="PENDING")
    parser_name: str | None = Field(default=None)
    parser_version: str | None = Field(default=None)
    normalization_version: str | None = Field(default=None)
    normalized_at: datetime | None = Field(default=None)
    normalization_errors: list[dict[str, Any]] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

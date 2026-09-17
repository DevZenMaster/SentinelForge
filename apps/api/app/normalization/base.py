"""Abstract base interfaces and defensive normalization primitives for Event Parsers."""

import ipaddress
import re
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol, runtime_checkable

from app.normalization.models import NormalizationError, NormalizationErrorCode, NormalizationResult
from app.schemas.event import EventSeverity

# Maximum permitted string length for individual scalar fields to prevent ReDoS / CPU attacks
MAX_PARSER_FIELD_LENGTH = 1024

# Disallow leading/trailing whitespace control characters, allow standard usernames
RE_SAFE_WHITESPACE = re.compile(r"^\s*(.*?)\s*$")


def normalize_ip(
    value: Any, field_name: str = "ip"
) -> tuple[str | None, NormalizationError | None]:
    """Validate and format IPv4 / IPv6 addresses deterministically without DNS lookups."""
    if value is None:
        return None, None
    if not isinstance(value, str):
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_IP,
            field=field_name,
            message=f"Field '{field_name}' must be a string, got {type(value).__name__}",
        )
    clean_ip = value.strip()
    if not clean_ip:
        return None, None
    if len(clean_ip) > 45:
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_IP,
            field=field_name,
            message=f"IP address string length ({len(clean_ip)}) exceeds maximum 45 characters",
        )
    try:
        # Standard library ip_address performs purely local numerical parsing (zero DNS lookups)
        parsed = ipaddress.ip_address(clean_ip)
        return str(parsed), None
    except ValueError:
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_IP,
            field=field_name,
            message=f"Invalid IP address format: '{clean_ip}'",
        )


def normalize_port(
    value: Any, field_name: str = "port"
) -> tuple[int | None, NormalizationError | None]:
    """Validate port numbers ensuring numeric bounds [0, 65535] without service resolution."""
    if value is None:
        return None, None
    if isinstance(value, str) and not value.strip():
        return None, None
    try:
        port_int = int(value)
    except (ValueError, TypeError):
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_PORT,
            field=field_name,
            message=f"Field '{field_name}' cannot be converted to integer: {value}",
        )
    if not (0 <= port_int <= 65535):
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_PORT,
            field=field_name,
            message=f"Port number {port_int} is out of allowable range [0, 65535]",
        )
    return port_int, None


def normalize_username(value: Any) -> str | None:
    """Normalize username formatting: trim whitespace while strictly preserving case."""
    if value is None:
        return None
    clean_str: str = value if isinstance(value, str) else str(value)
    clean = clean_str.strip()
    if not clean:
        return None
    # Strictly enforce 128-char limit matching Event database schema
    return str(clean[:128])


def normalize_timestamp(
    value: Any, field_name: str = "timestamp"
) -> tuple[datetime | None, NormalizationError | None]:
    """Validate and normalize timestamps to timezone-aware UTC datetime."""
    if value is None:
        return None, NormalizationError(
            code=NormalizationErrorCode.MISSING_REQUIRED_FIELD,
            field=field_name,
            message=f"Required timestamp field '{field_name}' is missing",
        )

    dt: datetime
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            dt = value.replace(tzinfo=UTC)
        else:
            dt = value
    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(value, tz=UTC)
        except (ValueError, OverflowError, OSError) as exc:
            return None, NormalizationError(
                code=NormalizationErrorCode.INVALID_TIMESTAMP,
                field=field_name,
                message=f"Invalid unix epoch timestamp '{value}': {exc}",
            )
    elif isinstance(value, str):
        clean_ts = value.strip()
        if not clean_ts:
            return None, NormalizationError(
                code=NormalizationErrorCode.INVALID_TIMESTAMP,
                field=field_name,
                message="Timestamp string cannot be empty",
            )
        try:
            # Handle Zulu trailing Z
            if clean_ts.endswith("Z"):
                clean_ts = clean_ts[:-1] + "+00:00"
            dt = datetime.fromisoformat(clean_ts)
        except ValueError as exc:
            return None, NormalizationError(
                code=NormalizationErrorCode.INVALID_TIMESTAMP,
                field=field_name,
                message=f"Malformed ISO 8601 timestamp '{value}': {exc}",
            )
    else:
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_TIMESTAMP,
            field=field_name,
            message=(
                f"Timestamp must be ISO 8601 string, unix epoch, or datetime object, "
                f"got {type(value).__name__}"
            ),
        )

    # Convert naive timestamps to UTC
    if dt.tzinfo is None or dt.utcoffset() is None:
        dt = dt.replace(tzinfo=UTC)

    utc_dt = dt.astimezone(UTC)
    now = datetime.now(UTC)

    # Enforce future and past sanity bounds
    if utc_dt > now + timedelta(minutes=5):
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_TIMESTAMP,
            field=field_name,
            message="Event timestamp cannot be more than 5 minutes in the future",
        )
    if utc_dt < now - timedelta(days=365):
        return None, NormalizationError(
            code=NormalizationErrorCode.INVALID_TIMESTAMP,
            field=field_name,
            message="Event timestamp cannot be older than 365 days",
        )

    return utc_dt, None


def normalize_severity(value: Any) -> tuple[EventSeverity, NormalizationError | None]:
    """Map arbitrary source severity representations into the controlled taxonomy."""
    if value is None:
        return EventSeverity.INFO, None
    clean = str(value).strip().upper()

    # Direct mapping
    if clean in EventSeverity.__members__:
        return EventSeverity[clean], None

    # Common syslog / vendor severity representations
    mapping = {
        "DEBUG": EventSeverity.INFO,
        "NOTICE": EventSeverity.INFO,
        "INFORMATIONAL": EventSeverity.INFO,
        "WARNING": EventSeverity.MEDIUM,
        "WARN": EventSeverity.MEDIUM,
        "ERR": EventSeverity.HIGH,
        "ERROR": EventSeverity.HIGH,
        "CRIT": EventSeverity.CRITICAL,
        "ALERT": EventSeverity.CRITICAL,
        "EMERG": EventSeverity.CRITICAL,
        "EMERGENCY": EventSeverity.CRITICAL,
        "FATAL": EventSeverity.CRITICAL,
    }
    if clean in mapping:
        return mapping[clean], None

    # Fallback to INFO with diagnostic warning error (does not fail normalization)
    return EventSeverity.INFO, NormalizationError(
        code=NormalizationErrorCode.UNSUPPORTED_SOURCE,
        field="severity",
        message=f"Unrecognized severity '{value}'; normalized to INFO default",
    )


@runtime_checkable
class EventParser(Protocol):
    """Protocol interface defining deterministic security log normalization logic."""

    parser_name: str
    parser_version: str
    normalization_version: str

    def can_parse(self, source_type: str, raw_payload: dict[str, Any]) -> bool:
        """Determine if this parser can interpret the given event and payload."""
        ...

    def parse(
        self,
        raw_payload: dict[str, Any],
        source: str,
        source_type: str,
        fallback_timestamp: datetime,
        base_metadata: dict[str, Any],
    ) -> NormalizationResult:
        """Transform raw payload into canonical representation without mutating raw_payload."""
        ...

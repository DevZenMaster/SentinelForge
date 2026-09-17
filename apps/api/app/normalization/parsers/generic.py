"""Generic baseline security event parser.

Acts as the universal fallback parser for standard security telemetry formats.
Extracts canonical fields, normalizes types, maps outcome, and preserves unknown
telemetry attributes in the attributes JSON structure.
"""

from datetime import datetime
from typing import Any

from app.normalization.base import (
    normalize_ip,
    normalize_port,
    normalize_severity,
    normalize_timestamp,
    normalize_username,
)
from app.normalization.models import (
    CanonicalEventData,
    EventOutcome,
    NormalizationError,
    NormalizationErrorCode,
    NormalizationResult,
    NormalizationStatus,
)
from app.schemas.event import EventSeverity

# Core fields that are mapped directly into canonical columns
RESERVED_CANONICAL_KEYS = {
    "timestamp",
    "event_type",
    "action",
    "outcome",
    "severity",
    "source",
    "source_type",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "username",
    "message",
}


class GenericParser:
    """Universal parser mapping standard security fields and preserving extra attributes."""

    parser_name: str = "generic"
    parser_version: str = "1.0.0"
    normalization_version: str = "1.0.0"

    def can_parse(self, source_type: str, raw_payload: dict[str, Any]) -> bool:
        """Universal parser accepts all event payloads as fallback."""
        return True

    def parse(
        self,
        raw_payload: dict[str, Any],
        source: str,
        source_type: str,
        fallback_timestamp: datetime,
        base_metadata: dict[str, Any],
    ) -> NormalizationResult:
        """Deterministically normalize raw payload into CanonicalEventData."""
        errors: list[NormalizationError] = []

        # 1. Timestamp normalization: check raw_payload timestamp first,
        # fallback to ingested timestamp
        ts_val = raw_payload.get("timestamp", fallback_timestamp)
        canonical_ts, ts_err = normalize_timestamp(ts_val, "timestamp")
        if ts_err:
            errors.append(ts_err)
            canonical_ts = fallback_timestamp

        # 2. IP addresses
        src_ip_val = raw_payload.get("source_ip", base_metadata.get("source_ip"))
        canonical_src_ip, src_ip_err = normalize_ip(src_ip_val, "source_ip")
        if src_ip_err:
            errors.append(src_ip_err)

        dst_ip_val = raw_payload.get("destination_ip", base_metadata.get("destination_ip"))
        canonical_dst_ip, dst_ip_err = normalize_ip(dst_ip_val, "destination_ip")
        if dst_ip_err:
            errors.append(dst_ip_err)

        # 3. Ports
        src_port_val = raw_payload.get("source_port", base_metadata.get("source_port"))
        canonical_src_port, src_port_err = normalize_port(src_port_val, "source_port")
        if src_port_err:
            errors.append(src_port_err)

        dst_port_val = raw_payload.get("destination_port", base_metadata.get("destination_port"))
        canonical_dst_port, dst_port_err = normalize_port(dst_port_val, "destination_port")
        if dst_port_err:
            errors.append(dst_port_err)

        # 4. Username
        user_val = raw_payload.get("username", base_metadata.get("username"))
        canonical_user = normalize_username(user_val)

        # 5. Severity
        sev_val = raw_payload.get("severity", base_metadata.get("severity", EventSeverity.INFO))
        canonical_sev, sev_err = normalize_severity(sev_val)
        if sev_err:
            errors.append(sev_err)

        # 6. Event classification & taxonomy
        raw_event_type = raw_payload.get("event_type", base_metadata.get("event_type", "unknown"))
        canonical_event_type = str(raw_event_type).strip().lower() if raw_event_type else "unknown"

        raw_action = raw_payload.get("action", base_metadata.get("action", "observed"))
        canonical_action = str(raw_action).strip().lower() if raw_action else "observed"

        # 7. Outcome mapping
        raw_outcome = raw_payload.get("outcome")
        canonical_outcome = EventOutcome.UNKNOWN
        if raw_outcome:
            clean_out = str(raw_outcome).strip().lower()
            if clean_out in ("success", "successful", "ok", "allow", "allowed", "passed"):
                canonical_outcome = EventOutcome.SUCCESS
            elif clean_out in (
                "failure",
                "failed",
                "error",
                "deny",
                "denied",
                "block",
                "blocked",
                "drop",
                "dropped",
            ):
                canonical_outcome = EventOutcome.FAILURE
        else:
            # Derive outcome from standard action naming conventions
            if (
                canonical_action.endswith(("_success", "_allowed", "_passed"))
                or canonical_action == "login_success"
            ):
                canonical_outcome = EventOutcome.SUCCESS
            elif canonical_action.endswith(
                ("_failed", "_failure", "_denied", "_blocked", "_drop")
            ) or canonical_action in ("login_failed", "http_401"):
                canonical_outcome = EventOutcome.FAILURE

        # 8. Source categorization
        canonical_source = str(raw_payload.get("source", source)).strip() or source
        canonical_source_type = raw_payload.get("source_type", source_type)
        if isinstance(canonical_source_type, str):
            canonical_source_type = canonical_source_type.strip().lower()

        # 9. Message
        canonical_message = raw_payload.get("message", base_metadata.get("message"))
        if canonical_message is not None:
            canonical_message = str(canonical_message).strip()

        # 10. Extract attributes: non-reserved fields from raw_payload preserved in JSONB
        extracted_attributes: dict[str, Any] = {}
        for k, v in raw_payload.items():
            if k not in RESERVED_CANONICAL_KEYS:
                extracted_attributes[k] = v

        canonical_data: CanonicalEventData | None = CanonicalEventData(
            event_type=canonical_event_type,
            action=canonical_action,
            outcome=canonical_outcome,
            severity=canonical_sev,
            timestamp=canonical_ts,
            source=canonical_source,
            source_type=canonical_source_type,
            source_ip=canonical_src_ip,
            destination_ip=canonical_dst_ip,
            source_port=canonical_src_port,
            destination_port=canonical_dst_port,
            username=canonical_user,
            message=canonical_message,
            attributes=extracted_attributes,
        )

        status = NormalizationStatus.NORMALIZED
        if any(
            e.code
            in (
                NormalizationErrorCode.INVALID_TIMESTAMP,
                NormalizationErrorCode.MISSING_REQUIRED_FIELD,
            )
            for e in errors
        ):
            status = NormalizationStatus.FAILED
            canonical_data = None
        elif errors:
            status = NormalizationStatus.PARTIAL

        return NormalizationResult(
            status=status,
            canonical_data=canonical_data,
            parser_name=self.parser_name,
            parser_version=self.parser_version,
            normalization_version=self.normalization_version,
            errors=errors,
        )

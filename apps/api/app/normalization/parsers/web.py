"""Web server and HTTP access log security event parser.

Specialized parser for HTTP telemetry (Nginx, Apache, FastAPI/web access logs, reverse proxies).
Normalizes HTTP access events to satisfy:
- RULE-004: Excessive 401 Unauthorized Responses
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
from app.schemas.event import EventSeverity, SourceType

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
    "status_code",
    "http_status",
    "http_method",
    "method",
    "http_path",
    "request_uri",
    "path",
    "user_agent",
    "client_ip",
}


class WebParser:
    """Parser for Web server, API gateway, and HTTP access telemetry."""

    parser_name: str = "web"
    parser_version: str = "1.0.0"
    normalization_version: str = "1.0.0"

    SUPPORTED_SOURCE_TYPES = {"web", "application", "nginx", "apache", "api_gateway"}
    HTTP_INDICATOR_KEYS = {
        "http_method",
        "method",
        "status_code",
        "http_status",
        "request_uri",
        "http_path",
        "path",
        "user_agent",
    }

    def can_parse(self, source_type: str, raw_payload: dict[str, Any]) -> bool:
        """Evaluate if payload represents HTTP or Web application telemetry."""
        clean_st = source_type.strip().lower()
        if clean_st in self.SUPPORTED_SOURCE_TYPES:
            return True
        if any(k in raw_payload for k in self.HTTP_INDICATOR_KEYS):
            return True
        return False

    def parse(
        self,
        raw_payload: dict[str, Any],
        source: str,
        source_type: str,
        fallback_timestamp: datetime,
        base_metadata: dict[str, Any],
    ) -> NormalizationResult:
        """Deterministically normalize HTTP access event into CanonicalEventData."""
        errors: list[NormalizationError] = []

        # 1. Timestamp
        ts_val = raw_payload.get("timestamp", fallback_timestamp)
        canonical_ts, ts_err = normalize_timestamp(ts_val, "timestamp")
        if ts_err:
            errors.append(ts_err)
            canonical_ts = fallback_timestamp

        # 2. Extract and normalize HTTP status code
        raw_status = raw_payload.get(
            "status_code",
            raw_payload.get("http_status", base_metadata.get("status_code")),
        )
        canonical_status_code: int | None = None
        if raw_status is not None:
            try:
                canonical_status_code = int(raw_status)
                if canonical_status_code < 100 or canonical_status_code > 599:
                    errors.append(
                        NormalizationError(
                            field="status_code",
                            code=NormalizationErrorCode.INVALID_PORT,  # or range error
                            message=(
                                f"HTTP status code {canonical_status_code} "
                                f"out of valid range (100-599)"
                            ),
                            raw_value=raw_status,
                        )
                    )
                    canonical_status_code = None
            except (ValueError, TypeError):
                errors.append(
                    NormalizationError(
                        field="status_code",
                        code=NormalizationErrorCode.INVALID_PORT,
                        message=f"HTTP status code '{raw_status}' is not a valid integer",
                        raw_value=raw_status,
                    )
                )

        # 3. HTTP method & path
        raw_method = raw_payload.get(
            "http_method",
            raw_payload.get("method", base_metadata.get("http_method")),
        )
        canonical_method: str | None = None
        if raw_method:
            canonical_method = str(raw_method).strip().upper()

        raw_path = raw_payload.get(
            "http_path",
            raw_payload.get("path", raw_payload.get("request_uri", base_metadata.get("http_path"))),
        )
        canonical_path: str | None = None
        if raw_path:
            canonical_path = str(raw_path).strip()

        user_agent = raw_payload.get("user_agent", base_metadata.get("user_agent"))
        canonical_user_agent: str | None = None
        if user_agent:
            canonical_user_agent = str(user_agent).strip()

        # 4. Action, Outcome, and Severity mapping (especially for RULE-004)
        canonical_action = "http_request"
        canonical_outcome = EventOutcome.UNKNOWN
        canonical_sev = EventSeverity.INFO

        if canonical_status_code is not None:
            if canonical_status_code == 401:
                canonical_action = "http_401"
                canonical_outcome = EventOutcome.FAILURE
                canonical_sev = EventSeverity.MEDIUM
            elif 400 <= canonical_status_code < 500:
                canonical_action = f"http_{canonical_status_code}"
                canonical_outcome = EventOutcome.FAILURE
                canonical_sev = (
                    EventSeverity.LOW if canonical_status_code != 403 else EventSeverity.MEDIUM
                )
            elif 500 <= canonical_status_code < 600:
                canonical_action = f"http_{canonical_status_code}"
                canonical_outcome = EventOutcome.FAILURE
                canonical_sev = EventSeverity.MEDIUM
            elif 200 <= canonical_status_code < 400:
                canonical_action = f"http_{canonical_status_code}"
                canonical_outcome = EventOutcome.SUCCESS
                canonical_sev = EventSeverity.INFO
        else:
            # Fallback action/outcome from payload if explicit status_code wasn't present
            raw_act = raw_payload.get("action", base_metadata.get("action", "http_request"))
            canonical_action = str(raw_act).strip().lower()
            if canonical_action in ("http_401", "login_failed", "unauthorized"):
                canonical_outcome = EventOutcome.FAILURE
                canonical_sev = EventSeverity.MEDIUM
            elif canonical_action in ("http_200", "login_success"):
                canonical_outcome = EventOutcome.SUCCESS

        # Allow explicit severity override if provided
        if "severity" in raw_payload or "severity" in base_metadata:
            explicit_sev, sev_err = normalize_severity(
                raw_payload.get("severity", base_metadata.get("severity"))
            )
            if sev_err:
                errors.append(sev_err)
            else:
                canonical_sev = explicit_sev

        # 5. IP Addresses
        raw_src_ip = raw_payload.get(
            "source_ip",
            raw_payload.get("client_ip", base_metadata.get("source_ip")),
        )
        canonical_src_ip, src_ip_err = normalize_ip(raw_src_ip, "source_ip")
        if src_ip_err:
            errors.append(src_ip_err)

        dst_ip_val = raw_payload.get("destination_ip", base_metadata.get("destination_ip"))
        canonical_dst_ip, dst_ip_err = normalize_ip(dst_ip_val, "destination_ip")
        if dst_ip_err:
            errors.append(dst_ip_err)

        # 6. Ports
        raw_src_port = raw_payload.get("source_port", base_metadata.get("source_port"))
        canonical_src_port, src_port_err = normalize_port(raw_src_port, "source_port")
        if src_port_err:
            errors.append(src_port_err)

        raw_dst_port = raw_payload.get("destination_port", base_metadata.get("destination_port"))
        canonical_dst_port, dst_port_err = normalize_port(raw_dst_port, "destination_port")
        if dst_port_err:
            errors.append(dst_port_err)

        # 7. Username
        raw_user = raw_payload.get(
            "username", raw_payload.get("user", base_metadata.get("username"))
        )
        canonical_user = normalize_username(raw_user)

        # 8. Attributes
        attributes: dict[str, Any] = {}
        if canonical_status_code is not None:
            attributes["status_code"] = canonical_status_code
        if canonical_method:
            attributes["http_method"] = canonical_method
        if canonical_path:
            attributes["http_path"] = canonical_path
        if canonical_user_agent:
            attributes["user_agent"] = canonical_user_agent

        for k, v in raw_payload.items():
            if k not in RESERVED_CANONICAL_KEYS and k not in attributes:
                attributes[k] = v

        canonical_data: CanonicalEventData | None = CanonicalEventData(
            event_type="web",
            action=canonical_action,
            outcome=canonical_outcome,
            severity=canonical_sev,
            timestamp=canonical_ts,
            source=str(raw_payload.get("source", source)).strip() or source,
            source_type=SourceType.APPLICATION if source_type == "application" else SourceType.WEB,
            source_ip=canonical_src_ip,
            destination_ip=canonical_dst_ip,
            source_port=canonical_src_port,
            destination_port=canonical_dst_port,
            username=canonical_user,
            message=raw_payload.get("message", base_metadata.get("message")),
            attributes=attributes,
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

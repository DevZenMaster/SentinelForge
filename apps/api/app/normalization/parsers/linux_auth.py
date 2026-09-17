"""Linux and Unix system authentication event parser.

Specialized parser for Linux PAM, sshd, and local authentication logs.
Normalizes authentication outcomes to satisfy:
- RULE-001: Brute Force Login
- RULE-002: Targeted Account Password Spray
- RULE-003: Suspicious Successful Login
"""

import re
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

# Safe, non-backtracking regular expressions for parsing standard Linux auth messages
RE_SSHD_FAILED = re.compile(
    r"Failed password for (?:invalid user )?([a-zA-Z0-9_\-\.]{1,128}) "
    r"from ([a-fA-F0-9\.:]{1,45})(?: port (\d{1,5}))?",
    re.IGNORECASE,
)
RE_SSHD_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for ([a-zA-Z0-9_\-\.]{1,128}) "
    r"from ([a-fA-F0-9\.:]{1,45})(?: port (\d{1,5}))?",
    re.IGNORECASE,
)
RE_PAM_FAILURE = re.compile(
    r"authentication failure;.*?\brhost=([a-fA-F0-9\.:]{1,45}).*?\buser=([a-zA-Z0-9_\-\.]{1,128})",
    re.IGNORECASE,
)


class LinuxAuthParser:
    """Parser for Linux and UNIX authentication telemetry (sshd, pam, sudo)."""

    parser_name: str = "linux_auth"
    parser_version: str = "1.0.0"
    normalization_version: str = "1.0.0"

    SUPPORTED_SOURCE_TYPES = {"linux", "authentication"}
    AUTH_SERVICES = {"sshd", "pam", "sudo", "systemd-logind", "login"}

    def can_parse(self, source_type: str, raw_payload: dict[str, Any]) -> bool:
        """Evaluate if payload represents Linux host or authentication telemetry."""
        clean_st = source_type.strip().lower()
        if clean_st in self.SUPPORTED_SOURCE_TYPES:
            return True
        service = str(raw_payload.get("service", "")).strip().lower()
        if service in self.AUTH_SERVICES:
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
        """Parse Linux authentication event and extract canonical identities and outcome."""
        errors: list[NormalizationError] = []

        # 1. Timestamp
        ts_val = raw_payload.get("timestamp", fallback_timestamp)
        canonical_ts, ts_err = normalize_timestamp(ts_val, "timestamp")
        if ts_err:
            errors.append(ts_err)
            canonical_ts = fallback_timestamp

        # 2. Extract raw message and candidates
        raw_msg = str(raw_payload.get("message", base_metadata.get("message", "")))

        raw_user = raw_payload.get(
            "username", raw_payload.get("user", base_metadata.get("username"))
        )
        raw_src_ip = raw_payload.get(
            "source_ip", raw_payload.get("rhost", base_metadata.get("source_ip"))
        )
        raw_src_port = raw_payload.get(
            "source_port", raw_payload.get("port", base_metadata.get("source_port"))
        )

        canonical_action = "observed"
        canonical_outcome = EventOutcome.UNKNOWN
        canonical_sev = EventSeverity.INFO

        # 3. Pattern match against standard syslog messages if explicit fields not supplied
        if "failed password" in raw_msg.lower():
            canonical_action = "login_failed"
            canonical_outcome = EventOutcome.FAILURE
            canonical_sev = EventSeverity.MEDIUM
            match = RE_SSHD_FAILED.search(raw_msg)
            if match:
                if not raw_user:
                    raw_user = match.group(1)
                if not raw_src_ip:
                    raw_src_ip = match.group(2)
                if not raw_src_port and match.group(3):
                    raw_src_port = match.group(3)
        elif "accepted password" in raw_msg.lower() or "accepted publickey" in raw_msg.lower():
            canonical_action = "login_success"
            canonical_outcome = EventOutcome.SUCCESS
            canonical_sev = EventSeverity.INFO
            match = RE_SSHD_ACCEPTED.search(raw_msg)
            if match:
                if not raw_user:
                    raw_user = match.group(1)
                if not raw_src_ip:
                    raw_src_ip = match.group(2)
                if not raw_src_port and match.group(3):
                    raw_src_port = match.group(3)
        elif "authentication failure" in raw_msg.lower():
            canonical_action = "login_failed"
            canonical_outcome = EventOutcome.FAILURE
            canonical_sev = EventSeverity.MEDIUM
            match = RE_PAM_FAILURE.search(raw_msg)
            if match:
                if not raw_src_ip:
                    raw_src_ip = match.group(1)
                if not raw_user:
                    raw_user = match.group(2)
        else:
            # Fallback to explicit payload status
            auth_status = str(raw_payload.get("auth_status", raw_payload.get("status", ""))).lower()
            if auth_status in ("failed", "failure", "deny", "denied"):
                canonical_action = "login_failed"
                canonical_outcome = EventOutcome.FAILURE
                canonical_sev = EventSeverity.MEDIUM
            elif auth_status in ("accepted", "success", "successful", "ok"):
                canonical_action = "login_success"
                canonical_outcome = EventOutcome.SUCCESS
                canonical_sev = EventSeverity.INFO
            else:
                raw_act = raw_payload.get("action", base_metadata.get("action", "login_attempt"))
                canonical_action = str(raw_act).strip().lower()
                if canonical_action in ("login_failed", "auth_failed"):
                    canonical_outcome = EventOutcome.FAILURE
                    canonical_sev = EventSeverity.MEDIUM
                elif canonical_action in ("login_success", "auth_success"):
                    canonical_outcome = EventOutcome.SUCCESS
                    canonical_sev = EventSeverity.INFO

        # 4. Normalize identities
        canonical_user = normalize_username(raw_user)
        canonical_src_ip, src_ip_err = normalize_ip(raw_src_ip, "source_ip")
        if src_ip_err:
            errors.append(src_ip_err)

        dst_ip_val = raw_payload.get("destination_ip", base_metadata.get("destination_ip"))
        canonical_dst_ip, dst_ip_err = normalize_ip(dst_ip_val, "destination_ip")
        if dst_ip_err:
            errors.append(dst_ip_err)

        canonical_src_port, src_port_err = normalize_port(raw_src_port, "source_port")
        if src_port_err:
            errors.append(src_port_err)

        dst_port_val = raw_payload.get("destination_port", base_metadata.get("destination_port"))
        canonical_dst_port, dst_port_err = normalize_port(dst_port_val, "destination_port")
        if dst_port_err:
            errors.append(dst_port_err)

        # Allow explicit severity override if source provided higher severity
        if "severity" in raw_payload or "severity" in base_metadata:
            explicit_sev, sev_err = normalize_severity(
                raw_payload.get("severity", base_metadata.get("severity"))
            )
            if sev_err:
                errors.append(sev_err)
            else:
                canonical_sev = explicit_sev

        # 5. Extract Linux-specific attributes safely
        attributes: dict[str, Any] = {}
        for attr_key in (
            "service",
            "pid",
            "terminal",
            "logname",
            "uid",
            "euid",
            "tty",
            "auth_method",
        ):
            if attr_key in raw_payload:
                attributes[attr_key] = raw_payload[attr_key]

        # Preserve any additional non-reserved fields in attributes
        for k, v in raw_payload.items():
            if k not in attributes and k not in (
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
                "auth_status",
                "status",
                "user",
                "rhost",
                "port",
            ):
                attributes[k] = v

        canonical_data: CanonicalEventData | None = CanonicalEventData(
            event_type="authentication",
            action=canonical_action,
            outcome=canonical_outcome,
            severity=canonical_sev,
            timestamp=canonical_ts,
            source=str(raw_payload.get("source", source)).strip() or source,
            source_type=SourceType.LINUX,
            source_ip=canonical_src_ip,
            destination_ip=canonical_dst_ip,
            source_port=canonical_src_port,
            destination_port=canonical_dst_port,
            username=canonical_user,
            message=raw_msg or None,
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

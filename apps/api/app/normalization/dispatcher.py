"""Normalization dispatcher for SentinelForge security events.

Orchestrates parser selection, schema validation, canonical transformation,
and persistence preparation while maintaining raw payload immutability.
"""

import copy
import logging
from datetime import UTC, datetime
from typing import Any

from app.models.event import Event
from app.normalization.models import (
    CanonicalEventData,
    EventOutcome,
    NormalizationError,
    NormalizationErrorCode,
    NormalizationResult,
    NormalizationStatus,
)
from app.normalization.registry import ParserRegistry, default_registry

logger = logging.getLogger("sentinelforge.normalization")


def normalize_event(
    event: Event,
    registry: ParserRegistry = default_registry,
) -> NormalizationResult:
    """Deterministically normalize an Event using the appropriate registered parser.

    Guarantees raw_payload is treated as strictly read-only and will never be mutated.
    Captures parser runtime exceptions gracefully into FAILED status without raising.
    """
    raw_payload_copy = (
        copy.deepcopy(event.raw_payload) if isinstance(event.raw_payload, dict) else {}
    )

    base_metadata: dict[str, Any] = {
        "event_type": event.event_type,
        "action": event.action,
        "severity": event.severity,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "source_port": getattr(event, "source_port", None),
        "destination_port": getattr(event, "destination_port", None),
        "username": event.username,
        "message": event.message,
    }

    parser = registry.get_parser(event.source_type, raw_payload_copy)

    try:
        result = parser.parse(
            raw_payload=raw_payload_copy,
            source=event.source,
            source_type=event.source_type,
            fallback_timestamp=event.timestamp,
            base_metadata=base_metadata,
        )
    except Exception as exc:
        logger.exception(
            "Parser '%s' raised an unhandled exception for event %s", parser.parser_name, event.id
        )
        return NormalizationResult(
            status=NormalizationStatus.FAILED,
            canonical_data=None,
            parser_name=parser.parser_name,
            parser_version=parser.parser_version,
            normalization_version=parser.normalization_version,
            errors=[
                NormalizationError(
                    field="raw_payload",
                    code=NormalizationErrorCode.PARSER_ERROR,
                    message=f"Parser unhandled exception: {exc}",
                )
            ],
        )

    # Verify immutability of raw payload
    if event.raw_payload != raw_payload_copy:
        logger.error("Raw payload mutation detected during normalization of event %s", event.id)
        # Restore raw_payload copy if parser somehow mutated it
        event.raw_payload = raw_payload_copy

    return result


def apply_normalization_to_event(event: Event, result: NormalizationResult) -> None:
    """Apply the NormalizationResult canonical fields and metadata directly onto an Event model.

    Updates canonical attributes, sets outcome, parser info, and normalization status
    while strictly preserving the existing event.raw_payload, external_event_id, and id.
    """
    event.normalization_status = result.status.value
    event.parser_name = result.parser_name
    event.parser_version = result.parser_version
    event.normalization_version = result.normalization_version
    event.normalized_at = datetime.now(UTC)
    event.normalization_errors = [e.model_dump() for e in result.errors]

    if result.canonical_data:
        cdata: CanonicalEventData = result.canonical_data
        event.outcome = cdata.outcome.value
        event.event_type = cdata.event_type
        event.action = cdata.action
        event.severity = cdata.severity.value
        if cdata.source_ip:
            event.source_ip = cdata.source_ip
        if cdata.destination_ip:
            event.destination_ip = cdata.destination_ip
        if cdata.source_port is not None:
            event.source_port = cdata.source_port
        if cdata.destination_port is not None:
            event.destination_port = cdata.destination_port
        if cdata.username:
            event.username = cdata.username
        if cdata.message:
            event.message = cdata.message
        event.attributes = cdata.attributes
    else:
        # FAILED status: preserve existing fields, ensure outcome is unknown
        # and attributes is a dict
        if not event.outcome:
            event.outcome = EventOutcome.UNKNOWN.value
        if event.attributes is None:
            event.attributes = {}

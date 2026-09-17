"""SentinelForge Event Normalization & Canonicalization subsystem."""

from app.normalization.base import EventParser
from app.normalization.dispatcher import apply_normalization_to_event, normalize_event
from app.normalization.models import (
    CanonicalEventData,
    EventOutcome,
    NormalizationError,
    NormalizationErrorCode,
    NormalizationResult,
    NormalizationStatus,
)
from app.normalization.registry import ParserRegistry, default_registry

__all__ = [
    "EventParser",
    "normalize_event",
    "apply_normalization_to_event",
    "ParserRegistry",
    "default_registry",
    "CanonicalEventData",
    "EventOutcome",
    "NormalizationError",
    "NormalizationErrorCode",
    "NormalizationResult",
    "NormalizationStatus",
]

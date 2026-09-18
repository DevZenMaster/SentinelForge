"""Base Detection Rule Interface.

Defines the abstract contract for all deterministic SIEM detection rules.
Every rule specifies its target event type, sliding time window, evaluation
threshold, correlation key semantics, and isolated evaluation logic.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from app.detection.deduplication import calculate_dedup_key
from app.detection.models import DetectionContext, DetectionResult


class BaseDetectionRule(ABC):
    """Abstract base class for all SentinelForge detection rules."""

    rule_id: str
    name: str
    version: int = 1
    description: str
    severity: str
    event_type: str
    time_window_seconds: int
    threshold: int

    def __init__(
        self,
        *,
        rule_id: str | None = None,
        name: str | None = None,
        version: int | None = None,
        description: str | None = None,
        severity: str | None = None,
        event_type: str | None = None,
        time_window_seconds: int | None = None,
        threshold: int | None = None,
    ) -> None:
        if rule_id is not None:
            self.rule_id = rule_id
        if name is not None:
            self.name = name
        if version is not None:
            self.version = version
        if description is not None:
            self.description = description
        if severity is not None:
            self.severity = severity
        if event_type is not None:
            self.event_type = event_type
        if time_window_seconds is not None:
            self.time_window_seconds = time_window_seconds
        if threshold is not None:
            self.threshold = threshold

    def calculate_time_window(self, event_timestamp: datetime) -> tuple[datetime, datetime]:
        """Calculate inclusive sliding time window [window_start, window_end]."""
        window_end = event_timestamp
        window_start = event_timestamp - timedelta(seconds=self.time_window_seconds)
        return window_start, window_end

    def calculate_dedup_key(self, correlation_key: str, event_timestamp: datetime) -> str:
        """Calculate deterministic deduplication key for this rule."""
        return calculate_dedup_key(
            rule_id=self.rule_id,
            correlation_key=correlation_key,
            timestamp=event_timestamp,
            window_seconds=self.time_window_seconds,
        )

    @abstractmethod
    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        """Evaluate the event within context against rule criteria.

        Returns:
            DetectionResult if rule conditions and thresholds are matched, None otherwise.
        """
        pass

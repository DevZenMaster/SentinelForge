"""Domain models for SentinelForge Detection Engine.

Defines:
- DetectionResult: Structured outcome from evaluating a detection rule
- DetectionContext: Execution context enclosing event, db session, and bounded query facilities
- RuleEvaluationError: Isolated exception type for rule runtime issues
"""

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.event import Event


class RuleEvaluationError(Exception):
    """Exception raised when an individual rule evaluation fails."""

    def __init__(self, rule_id: str, message: str) -> None:
        super().__init__(f"Rule {rule_id} evaluation error: {message}")
        self.rule_id = rule_id
        self.message = message


class DetectionResult(BaseModel):
    """Structured detection output produced when a rule conditions and thresholds are met."""

    matched: bool = Field(..., description="Whether detection conditions and thresholds matched")
    rule_id: str = Field(..., description="Unique rule identifier e.g. RULE-001")
    rule_version: int = Field(default=1, description="Version number of the evaluated rule")
    title: str = Field(..., description="Human-readable alert title")
    description: str = Field(..., description="Detailed description explaining the detection")
    severity: str = Field(
        ..., description="Alert severity level: INFO, LOW, MEDIUM, HIGH, CRITICAL"
    )
    correlation_key: str = Field(
        ..., description="Entity pivot key (e.g. source IP or username) used for aggregation"
    )
    dedup_key: str = Field(
        ..., description="Deterministic deduplication key matching rule:correlation_key:bucket"
    )
    threshold: int = Field(..., description="Configured rule threshold")
    observed_count: int = Field(..., description="Observed event count satisfying the rule")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Forensic and explainable detection telemetry"
    )
    contributing_event_ids: list[uuid.UUID] = Field(
        default_factory=list, description="IDs of events contributing to the detection"
    )
    first_seen: datetime = Field(..., description="Earliest timestamp in the detection window")
    last_seen: datetime = Field(..., description="Latest timestamp in the detection window")
    source_ip: str | None = Field(default=None, description="Pivot source IP if applicable")
    username: str | None = Field(default=None, description="Pivot username if applicable")


class DetectionContext:
    """Execution context provided to detection rules during event evaluation.

    Encapsulates the triggering event, database session, and safe, bounded sliding
    window queries backed by compound temporal indexes.
    """

    def __init__(
        self,
        event: Event,
        db: AsyncSession,
        max_window_events: int = 1000,
    ) -> None:
        self.event = event
        self.db = db
        self.max_window_events = max_window_events

    async def get_window_events(
        self,
        *,
        window_seconds: int,
        source_ip: str | None = None,
        username: str | None = None,
        event_type: str | None = None,
        action: str | None = None,
        destination_port_not_null: bool = False,
    ) -> Sequence[Event]:
        """Fetch historical events matching criteria within the correlation window.

        Window range: [event.timestamp - window_seconds, event.timestamp].

        Enforces:
        - Consistent inclusive bounds [window_start, window_end]
        - Parameterized query filters protecting against injection
        - Bound limit to prevent memory exhaustion from high-frequency log streams
        - Ascending timestamp ordering for chronological evidence tracking
        """
        window_end = self.event.timestamp
        window_start = window_end - timedelta(seconds=window_seconds)

        stmt = select(Event).where(
            Event.timestamp >= window_start,
            Event.timestamp <= window_end,
        )

        if source_ip is not None:
            stmt = stmt.where(Event.source_ip == source_ip)
        if username is not None:
            stmt = stmt.where(Event.username == username)
        if event_type is not None:
            stmt = stmt.where(Event.event_type == event_type)
        if action is not None:
            stmt = stmt.where(Event.action == action)
        if destination_port_not_null:
            stmt = stmt.where(Event.destination_port.isnot(None))

        stmt = stmt.order_by(Event.timestamp.asc()).limit(self.max_window_events)
        result = await self.db.execute(stmt)
        return result.scalars().all()

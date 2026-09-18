"""Configurable Declarative Detection Rule Evaluator.

Executes database-backed declarative detection rule configurations securely and deterministically
against the sliding event window. Evaluates only approved operators without any eval or raw SQL.
"""

from typing import Any

from app.detection.base import BaseDetectionRule
from app.detection.models import DetectionContext, DetectionResult
from app.models.event import Event


class ConfigurableDetectionRule(BaseDetectionRule):
    """Detection rule evaluated dynamically from structured configuration parameters."""

    def __init__(
        self,
        *,
        rule_id: str,
        name: str,
        version: int = 1,
        description: str,
        severity: str,
        event_type: str,
        threshold: int,
        time_window_seconds: int,
        conditions: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            rule_id=rule_id,
            name=name,
            version=version,
            description=description,
            severity=severity,
            event_type=event_type,
            threshold=threshold,
            time_window_seconds=time_window_seconds,
        )
        self.conditions: dict[str, Any] = conditions or {}

    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        event = context.event

        # 1. Gate on event type
        if event.event_type != self.event_type:
            return None

        # 2. Gate on triggering event action / filters
        if not self._matches_triggering_event(event):
            return None

        # 3. Extract correlation entity pivot
        group_by = self.conditions.get("group_by", "source_ip")
        pivot_val = getattr(event, group_by, None)
        if pivot_val is None:
            return None

        # 4. Fetch bounded sliding window events
        window_events = await self._fetch_window_events(context, group_by, pivot_val)

        # 5. Filter window events if specific window filters are configured
        matched_events = [e for e in window_events if self._matches_window_event(e)]

        # 6. Compute aggregation count
        aggregation = self.conditions.get("aggregation", "count")
        if aggregation == "distinct_count":
            distinct_field = self.conditions.get("distinct_field", "destination_port")
            distinct_vals = {
                getattr(e, distinct_field)
                for e in matched_events
                if getattr(e, distinct_field, None) is not None
            }
            observed_count = len(distinct_vals)
        else:
            observed_count = len(matched_events)

        if observed_count < self.threshold:
            return None

        # 7. Construct evidence and detection result
        earliest_event = matched_events[0] if matched_events else event
        latest_event = event

        # Ensure triggering event is in contributing list
        contributing_event_ids = [e.id for e in matched_events]
        if event.id not in contributing_event_ids:
            contributing_event_ids.append(event.id)

        dedup_key = self.calculate_dedup_key(str(pivot_val), event.timestamp)

        evidence = {
            "rule_id": self.rule_id,
            "rule_version": self.version,
            "group_by": group_by,
            "pivot_value": str(pivot_val),
            "observed_count": observed_count,
            "threshold": self.threshold,
            "window_seconds": self.time_window_seconds,
            "triggering_event_id": str(event.id),
        }

        return DetectionResult(
            matched=True,
            rule_id=self.rule_id,
            rule_version=self.version,
            title=f"{self.name} Detected on {pivot_val}",
            description=(
                f"Detected {observed_count} event(s) satisfying rule '{self.name}' "
                f"for {group_by}='{pivot_val}' within {self.time_window_seconds}s "
                f"(threshold: {self.threshold})."
            ),
            severity=self.severity,
            correlation_key=str(pivot_val),
            dedup_key=dedup_key,
            threshold=self.threshold,
            observed_count=observed_count,
            evidence=evidence,
            contributing_event_ids=contributing_event_ids,
            first_seen=earliest_event.timestamp,
            last_seen=latest_event.timestamp,
            source_ip=event.source_ip,
            username=event.username,
        )

    def _matches_triggering_event(self, event: Event) -> bool:
        """Check if triggering event satisfies rule precondition."""
        triggering_action = self.conditions.get("triggering_action")
        if triggering_action:
            return bool(event.action == triggering_action)

        action = self.conditions.get("action")
        if action and event.action != action:
            return False

        filters = self.conditions.get("filters")
        if filters and isinstance(filters, list):
            return self._matches_filters(event, filters)

        return True

    def _matches_window_event(self, event: Event) -> bool:
        """Check if a window event satisfies criteria for aggregation."""
        preceding_action = self.conditions.get("preceding_action")
        if preceding_action:
            return bool(event.action == preceding_action)

        action = self.conditions.get("action")
        if action and event.action != action:
            return False

        filters = self.conditions.get("filters")
        if filters and isinstance(filters, list):
            return self._matches_filters(event, filters)

        return True

    async def _fetch_window_events(
        self, context: DetectionContext, group_by: str, pivot_val: Any
    ) -> list[Event]:
        """Fetch candidate events within sliding time window matching the pivot entity."""
        kwargs: dict[str, Any] = {
            "window_seconds": self.time_window_seconds,
            "event_type": self.event_type,
        }

        if group_by == "source_ip":
            kwargs["source_ip"] = str(pivot_val)
        elif group_by == "username":
            kwargs["username"] = str(pivot_val)

        preceding_action = self.conditions.get("preceding_action")
        action = self.conditions.get("action")
        if preceding_action:
            kwargs["action"] = preceding_action
        elif action:
            kwargs["action"] = action

        aggregation = self.conditions.get("aggregation")
        distinct_field = self.conditions.get("distinct_field")
        if aggregation == "distinct_count" and distinct_field == "destination_port":
            kwargs["destination_port_not_null"] = True

        return list(await context.get_window_events(**kwargs))

    def _matches_filters(self, event: Event, filters: list[dict[str, Any]]) -> bool:
        """Evaluate declarative filters against event fields."""
        for flt in filters:
            field = flt.get("field", "")
            operator = flt.get("operator", "equals")
            target_val = flt.get("value")

            actual_val = self._extract_field_value(event, field)
            if not self._evaluate_operator(actual_val, operator, target_val):
                return False

        return True

    @staticmethod
    def _extract_field_value(event: Event, field: str) -> Any:
        """Extract field value from canonical event column or JSON attributes."""
        if field.startswith("attributes."):
            attr_key = field[len("attributes.") :]
            if isinstance(event.attributes, dict):
                return event.attributes.get(attr_key)
            return None
        return getattr(event, field, None)

    @staticmethod
    def _evaluate_operator(actual: Any, operator: str, expected: Any) -> bool:
        """Deterministically evaluate single safe operator."""
        if actual is None:
            return False

        if operator == "equals":
            return bool(actual == expected)
        if operator == "not_equals":
            return bool(actual != expected)
        if operator == "greater_than":
            return bool(actual > expected)
        if operator == "greater_than_or_equal":
            return bool(actual >= expected)
        if operator == "less_than":
            return bool(actual < expected)
        if operator == "less_than_or_equal":
            return bool(actual <= expected)
        if operator == "contains":
            return str(expected) in str(actual)
        if operator == "starts_with":
            return str(actual).startswith(str(expected))
        if operator == "ends_with":
            return str(actual).endswith(str(expected))
        if operator == "in":
            return bool(isinstance(expected, (list, set, tuple)) and actual in expected)

        return False

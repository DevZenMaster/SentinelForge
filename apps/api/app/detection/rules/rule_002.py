"""RULE-002: Targeted Account Password Spray.

Detects a high volume of failed authentication attempts against a specific username
regardless of source IP variation, indicating targeted credential stuffing or
account lock attack.
"""

from app.detection.base import BaseDetectionRule
from app.detection.models import DetectionContext, DetectionResult


class Rule002AccountSpray(BaseDetectionRule):
    """Rule detecting >= 10 failed authentications for a specific username in 600 seconds."""

    rule_id = "RULE-002"
    name = "Targeted Account Password Spray"
    version = 1
    description = (
        "Detects a high volume of failed authentication attempts against a specific username "
        "regardless of source IP variation, indicating targeted credential stuffing or "
        "account lock attack."
    )
    severity = "HIGH"
    event_type = "authentication"
    time_window_seconds = 600
    threshold = 10

    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        event = context.event

        # Gate on target event classification and action
        if event.event_type != self.event_type or event.action != "login_failed":
            return None

        # Pivot entity: username is required for correlation
        if not event.username:
            return None

        # Query failed login events against this username in the sliding window
        window_events = await context.get_window_events(
            window_seconds=self.time_window_seconds,
            username=event.username,
            event_type=self.event_type,
            action="login_failed",
        )

        observed_count = len(window_events)
        if observed_count < self.threshold:
            return None

        earliest_event = window_events[0]
        latest_event = window_events[-1]
        dedup_key = self.calculate_dedup_key(event.username, event.timestamp)

        unique_source_ips = sorted(list({e.source_ip for e in window_events if e.source_ip}))

        evidence = {
            "rule_id": self.rule_id,
            "username": event.username,
            "failed_attempts": observed_count,
            "threshold": self.threshold,
            "window_seconds": self.time_window_seconds,
            "triggering_event_id": str(event.id),
            "distinct_source_ips_count": len(unique_source_ips),
            "source_ips": unique_source_ips[:20],
        }

        return DetectionResult(
            matched=True,
            rule_id=self.rule_id,
            rule_version=self.version,
            title=f"Targeted Account Attack Against User {event.username}",
            description=(
                f"Detected {observed_count} failed authentication attempts against "
                f"username '{event.username}' within {self.time_window_seconds}s "
                f"(threshold: {self.threshold})."
            ),
            severity=self.severity,
            correlation_key=event.username,
            dedup_key=dedup_key,
            threshold=self.threshold,
            observed_count=observed_count,
            evidence=evidence,
            contributing_event_ids=[e.id for e in window_events],
            first_seen=earliest_event.timestamp,
            last_seen=latest_event.timestamp,
            source_ip=event.source_ip,
            username=event.username,
        )

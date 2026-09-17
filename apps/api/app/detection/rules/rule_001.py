"""RULE-001: Brute Force Login.

Detects repeated authentication failures originating from a single source IP address
within a compressed time window, indicating an automated password guessing or
credential brute-force attack.
"""

from app.detection.base import BaseDetectionRule
from app.detection.models import DetectionContext, DetectionResult


class Rule001BruteForceLogin(BaseDetectionRule):
    """Rule detecting >= 5 failed authentications from a single source IP in 300 seconds."""

    rule_id = "RULE-001"
    name = "Brute Force Login"
    version = 1
    description = (
        "Detects repeated authentication failures originating from a single source IP address "
        "within a compressed time window, indicating an automated password guessing or "
        "credential brute-force attack."
    )
    severity = "HIGH"
    event_type = "authentication"
    time_window_seconds = 300
    threshold = 5

    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        event = context.event

        # Gate on target event classification and action
        if event.event_type != self.event_type or event.action != "login_failed":
            return None

        # Pivot entity: source_ip is required for correlation
        if not event.source_ip:
            return None

        # Query failed login events from this source IP in the sliding window
        window_events = await context.get_window_events(
            window_seconds=self.time_window_seconds,
            source_ip=event.source_ip,
            event_type=self.event_type,
            action="login_failed",
        )

        observed_count = len(window_events)
        if observed_count < self.threshold:
            return None

        earliest_event = window_events[0]
        latest_event = window_events[-1]
        dedup_key = self.calculate_dedup_key(event.source_ip, event.timestamp)

        evidence = {
            "rule_id": self.rule_id,
            "source_ip": event.source_ip,
            "failed_attempts": observed_count,
            "threshold": self.threshold,
            "window_seconds": self.time_window_seconds,
            "triggering_event_id": str(event.id),
            "usernames_targeted": sorted(list({e.username for e in window_events if e.username}))[
                :20
            ],
        }

        return DetectionResult(
            matched=True,
            rule_id=self.rule_id,
            rule_version=self.version,
            title=f"Brute Force Authentication Attempt from {event.source_ip}",
            description=(
                f"Detected {observed_count} failed authentication attempts from {event.source_ip} "
                f"within {self.time_window_seconds}s (threshold: {self.threshold})."
            ),
            severity=self.severity,
            correlation_key=event.source_ip,
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

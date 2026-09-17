"""RULE-003: Suspicious Login Following Failures.

Detects an authentication success preceded by multiple authentication failures from the
same source IP within a short sliding window, signaling a potentially successful
brute-force or credential compromise.
"""

from app.detection.base import BaseDetectionRule
from app.detection.models import DetectionContext, DetectionResult


class Rule003SuspiciousLoginFollowingFailures(BaseDetectionRule):
    """Rule detecting login success preceded by >= 3 failed logins from same IP in 600s."""

    rule_id = "RULE-003"
    name = "Suspicious Login Following Failures"
    version = 1
    description = (
        "Detects an authentication success preceded by multiple authentication failures from the "
        "same source IP within a short sliding window, signaling a potentially successful "
        "brute-force or credential compromise."
    )
    severity = "HIGH"
    event_type = "authentication"
    time_window_seconds = 600
    threshold = 3  # Preceding failed attempts required

    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        event = context.event

        # Gate on target event classification and triggering action
        if event.event_type != self.event_type or event.action != "login_success":
            return None

        # Pivot entity: source_ip is required for correlation
        if not event.source_ip:
            return None

        # Query failed login events from this source IP in the preceding sliding window
        prior_failed_events = await context.get_window_events(
            window_seconds=self.time_window_seconds,
            source_ip=event.source_ip,
            event_type=self.event_type,
            action="login_failed",
        )

        # Exclude current event: since current is login_success,
        # action filter already isolates login_failed events.
        observed_failures = len(prior_failed_events)
        if observed_failures < self.threshold:
            return None

        earliest_event = prior_failed_events[0]
        dedup_key = self.calculate_dedup_key(event.source_ip, event.timestamp)

        # Contributing events includes both preceding failures and the triggering success
        contributing_event_ids = [e.id for e in prior_failed_events] + [event.id]

        evidence = {
            "rule_id": self.rule_id,
            "source_ip": event.source_ip,
            "prior_failures_count": observed_failures,
            "threshold": self.threshold,
            "window_seconds": self.time_window_seconds,
            "triggering_event_id": str(event.id),
            "compromised_username": event.username,
            "targeted_usernames": sorted(
                list({e.username for e in prior_failed_events if e.username})
            )[:20],
        }

        return DetectionResult(
            matched=True,
            rule_id=self.rule_id,
            rule_version=self.version,
            title=f"Successful Authentication from {event.source_ip} Following Failures",
            description=(
                f"Detected successful login from {event.source_ip} preceded by {observed_failures} "
                f"failed attempts within {self.time_window_seconds}s (threshold: {self.threshold})."
            ),
            severity=self.severity,
            correlation_key=event.source_ip,
            dedup_key=dedup_key,
            threshold=self.threshold,
            observed_count=observed_failures,
            evidence=evidence,
            contributing_event_ids=contributing_event_ids,
            first_seen=earliest_event.timestamp,
            last_seen=event.timestamp,
            source_ip=event.source_ip,
            username=event.username,
        )

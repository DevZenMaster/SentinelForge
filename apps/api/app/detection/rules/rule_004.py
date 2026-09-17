"""RULE-004: HTTP Authentication Abuse.

Detects repeated HTTP 401 Unauthorized responses emitted by web application logs from
a single client IP, indicating API token brute-force or unauthorized web endpoint enumeration.
"""

from app.detection.base import BaseDetectionRule
from app.detection.models import DetectionContext, DetectionResult


class Rule004HttpAuthAbuse(BaseDetectionRule):
    """Rule detecting >= 15 HTTP 401 responses from a single source IP in 300 seconds."""

    rule_id = "RULE-004"
    name = "HTTP Authentication Abuse"
    version = 1
    description = (
        "Detects repeated HTTP 401 Unauthorized responses emitted by web application logs "
        "from a single client IP, indicating API token brute-force or unauthorized web endpoint "
        "enumeration."
    )
    severity = "MEDIUM"
    event_type = "web"
    time_window_seconds = 300
    threshold = 15

    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        event = context.event

        # Gate on target event classification and action
        if event.event_type != self.event_type or event.action != "http_401":
            return None

        # Pivot entity: source_ip is required for correlation
        if not event.source_ip:
            return None

        # Query HTTP 401 events from this source IP in the sliding window
        window_events = await context.get_window_events(
            window_seconds=self.time_window_seconds,
            source_ip=event.source_ip,
            event_type=self.event_type,
            action="http_401",
        )

        observed_count = len(window_events)
        if observed_count < self.threshold:
            return None

        earliest_event = window_events[0]
        latest_event = window_events[-1]
        dedup_key = self.calculate_dedup_key(event.source_ip, event.timestamp)

        uris_set: set[str] = set()
        for e in window_events:
            if isinstance(e.attributes, dict):
                uri_val = e.attributes.get("uri")
                if isinstance(uri_val, str) and uri_val:
                    uris_set.add(uri_val)
        uris_targeted = sorted(list(uris_set))

        evidence = {
            "rule_id": self.rule_id,
            "source_ip": event.source_ip,
            "http_401_count": observed_count,
            "threshold": self.threshold,
            "window_seconds": self.time_window_seconds,
            "triggering_event_id": str(event.id),
            "uris_targeted": uris_targeted[:20],
        }

        return DetectionResult(
            matched=True,
            rule_id=self.rule_id,
            rule_version=self.version,
            title=f"Excessive HTTP 401 Unauthorized from {event.source_ip}",
            description=(
                f"Detected {observed_count} HTTP 401 unauthorized responses from {event.source_ip} "
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

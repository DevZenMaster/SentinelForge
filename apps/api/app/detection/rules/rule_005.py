"""RULE-005: Network Port Scan Pattern.

Detects connection attempts from a single source IP targeting multiple distinct
destination ports within a short period, characteristic of reconnaissance and
port scanning tools (e.g. Nmap, Masscan).
"""

from app.detection.base import BaseDetectionRule
from app.detection.models import DetectionContext, DetectionResult


class Rule005PortScan(BaseDetectionRule):
    """Rule detecting connection attempts to >= 10 distinct destination ports in 120s."""

    rule_id = "RULE-005"
    name = "Network Port Scan Pattern"
    version = 1
    description = (
        "Detects connection attempts from a single source IP targeting multiple distinct "
        "destination ports within a short period, characteristic of reconnaissance and "
        "port scanning tools (e.g. Nmap, Masscan)."
    )
    severity = "HIGH"
    event_type = "network"
    time_window_seconds = 120
    threshold = 10  # Distinct destination ports required

    async def evaluate(self, context: DetectionContext) -> DetectionResult | None:
        event = context.event

        # Gate on target event classification, action, and presence of destination_port
        if event.event_type != self.event_type or event.action != "connection_attempt":
            return None

        if event.destination_port is None:
            return None

        # Pivot entity: source_ip is required for correlation
        if not event.source_ip:
            return None

        # Query connection attempt events from this source IP in the sliding window
        window_events = await context.get_window_events(
            window_seconds=self.time_window_seconds,
            source_ip=event.source_ip,
            event_type=self.event_type,
            action="connection_attempt",
            destination_port_not_null=True,
        )

        distinct_ports = {
            e.destination_port for e in window_events if e.destination_port is not None
        }

        observed_distinct_count = len(distinct_ports)
        if observed_distinct_count < self.threshold:
            return None

        earliest_event = window_events[0]
        latest_event = window_events[-1]
        dedup_key = self.calculate_dedup_key(event.source_ip, event.timestamp)

        evidence = {
            "rule_id": self.rule_id,
            "source_ip": event.source_ip,
            "distinct_ports_count": observed_distinct_count,
            "distinct_ports": sorted(list(distinct_ports))[:50],
            "total_attempts": len(window_events),
            "threshold": self.threshold,
            "window_seconds": self.time_window_seconds,
            "triggering_event_id": str(event.id),
        }

        return DetectionResult(
            matched=True,
            rule_id=self.rule_id,
            rule_version=self.version,
            title=f"Reconnaissance Port Scan Detected from {event.source_ip}",
            description=(
                f"Detected connection attempts targeting {observed_distinct_count} "
                f"distinct destination ports from {event.source_ip} within "
                f"{self.time_window_seconds}s (threshold: {self.threshold})."
            ),
            severity=self.severity,
            correlation_key=event.source_ip,
            dedup_key=dedup_key,
            threshold=self.threshold,
            observed_count=observed_distinct_count,
            evidence=evidence,
            contributing_event_ids=[e.id for e in window_events],
            first_seen=earliest_event.timestamp,
            last_seen=latest_event.timestamp,
            source_ip=event.source_ip,
            username=event.username,
        )

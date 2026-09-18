"""Controlled, bounded, thread-safe operational metrics registry for SentinelForge.

Enforces zero-leakage metrics design:
- Zero high-cardinality dimensions (no user_id, IP, event_id, or full URLs).
- Bounded memory footprint.
- Zero sensitive payload or credential exposure.
"""

import threading
import time
from typing import Any


class SystemMetrics:
    """Thread-safe operational telemetry counters and latency metrics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time = time.time()

        # API Request Counters
        self._total_requests: int = 0
        self._total_errors: int = 0
        self._status_distribution: dict[str, int] = {
            "2xx": 0,
            "3xx": 0,
            "4xx": 0,
            "5xx": 0,
        }
        self._method_distribution: dict[str, int] = {
            "GET": 0,
            "POST": 0,
            "PUT": 0,
            "PATCH": 0,
            "DELETE": 0,
            "OPTIONS": 0,
            "OTHER": 0,
        }
        self._total_duration_ms: float = 0.0
        self._min_duration_ms: float | None = None
        self._max_duration_ms: float | None = None

        # Security Operations Counters
        self._alerts_created: int = 0
        self._alerts_acknowledged: int = 0
        self._alerts_resolved: int = 0
        self._alerts_closed: int = 0
        self._alerts_suppressed: int = 0

        self._incidents_created: int = 0
        self._incidents_resolved: int = 0
        self._incidents_closed: int = 0

        self._rule_evaluations: int = 0
        self._rule_matches: int = 0
        self._rule_errors: int = 0

        self._reports_requested: int = 0
        self._reports_exported: int = 0
        self._reports_failed: int = 0

    def record_request(self, method: str, status_code: int, duration_ms: float) -> None:
        """Record an incoming API request with bounded cardinality."""
        with self._lock:
            self._total_requests += 1

            # Method tracking
            m = method.upper() if method.upper() in self._method_distribution else "OTHER"
            self._method_distribution[m] += 1

            # Status code tier
            if 200 <= status_code < 300:
                self._status_distribution["2xx"] += 1
            elif 300 <= status_code < 400:
                self._status_distribution["3xx"] += 1
            elif 400 <= status_code < 500:
                self._status_distribution["4xx"] += 1
            elif status_code >= 500:
                self._status_distribution["5xx"] += 1
                self._total_errors += 1

            # Duration tracking
            self._total_duration_ms += duration_ms
            if self._min_duration_ms is None or duration_ms < self._min_duration_ms:
                self._min_duration_ms = duration_ms
            if self._max_duration_ms is None or duration_ms > self._max_duration_ms:
                self._max_duration_ms = duration_ms

    def record_alert_event(self, action: str) -> None:
        """Record alert lifecycle transition."""
        with self._lock:
            act = action.lower()
            if act == "created":
                self._alerts_created += 1
            elif act == "acknowledged":
                self._alerts_acknowledged += 1
            elif act == "resolved":
                self._alerts_resolved += 1
            elif act == "closed":
                self._alerts_closed += 1
            elif act == "suppressed":
                self._alerts_suppressed += 1

    def record_incident_event(self, action: str) -> None:
        """Record incident lifecycle transition."""
        with self._lock:
            act = action.lower()
            if act == "created":
                self._incidents_created += 1
            elif act == "resolved":
                self._incidents_resolved += 1
            elif act == "closed":
                self._incidents_closed += 1

    def record_detection_event(self, evaluated: int = 1, matched: int = 0, errors: int = 0) -> None:
        """Record detection rule evaluation metrics."""
        with self._lock:
            self._rule_evaluations += evaluated
            self._rule_matches += matched
            self._rule_errors += errors

    def record_report_event(self, action: str) -> None:
        """Record security report generation and export activity."""
        with self._lock:
            act = action.lower()
            if act == "requested":
                self._reports_requested += 1
            elif act == "exported":
                self._reports_exported += 1
            elif act == "failed":
                self._reports_failed += 1

    def get_snapshot(self) -> dict[str, Any]:
        """Return non-sensitive operational metrics snapshot."""
        with self._lock:
            uptime_seconds = round(time.time() - self._start_time, 2)
            avg_duration = (
                round(self._total_duration_ms / self._total_requests, 2)
                if self._total_requests > 0
                else 0.0
            )

            return {
                "uptime_seconds": uptime_seconds,
                "api": {
                    "total_requests": self._total_requests,
                    "total_errors": self._total_errors,
                    "status_distribution": dict(self._status_distribution),
                    "method_distribution": dict(self._method_distribution),
                    "duration_ms": {
                        "avg": avg_duration,
                        "min": self._min_duration_ms or 0.0,
                        "max": self._max_duration_ms or 0.0,
                    },
                },
                "security_operations": {
                    "alerts": {
                        "created": self._alerts_created,
                        "acknowledged": self._alerts_acknowledged,
                        "resolved": self._alerts_resolved,
                        "closed": self._alerts_closed,
                        "suppressed": self._alerts_suppressed,
                    },
                    "incidents": {
                        "created": self._incidents_created,
                        "resolved": self._incidents_resolved,
                        "closed": self._incidents_closed,
                    },
                    "detection": {
                        "rule_evaluations": self._rule_evaluations,
                        "rule_matches": self._rule_matches,
                        "rule_errors": self._rule_errors,
                    },
                    "reports": {
                        "requested": self._reports_requested,
                        "exported": self._reports_exported,
                        "failed": self._reports_failed,
                    },
                },
            }


# Global singleton instance
system_metrics = SystemMetrics()

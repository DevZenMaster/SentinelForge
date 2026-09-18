"""Observability and Delivery Metrics for Notification Subsystem (Phase 13).

Maintains thread-safe in-process metrics tracking delivery counts, retries,
exhaustions, and latencies.
"""

import threading
from dataclasses import dataclass, field


@dataclass
class NotificationMetrics:
    """Thread-safe notification delivery counters and latency stats."""

    notifications_created_total: int = 0
    notifications_delivered_total: int = 0
    notifications_failed_total: int = 0
    notifications_retried_total: int = 0
    notifications_exhausted_total: int = 0
    _total_latency_ms: float = 0.0
    _latency_sample_count: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def record_created(self, count: int = 1) -> None:
        with self._lock:
            self.notifications_created_total += count

    def record_delivered(self, latency_ms: float) -> None:
        with self._lock:
            self.notifications_delivered_total += 1
            self._total_latency_ms += latency_ms
            self._latency_sample_count += 1

    def record_failed(self) -> None:
        with self._lock:
            self.notifications_failed_total += 1

    def record_retried(self) -> None:
        with self._lock:
            self.notifications_retried_total += 1

    def record_exhausted(self) -> None:
        with self._lock:
            self.notifications_exhausted_total += 1

    @property
    def avg_delivery_latency_ms(self) -> float:
        with self._lock:
            if self._latency_sample_count == 0:
                return 0.0
            return round(self._total_latency_ms / self._latency_sample_count, 2)

    def to_dict(self) -> dict[str, float | int]:
        with self._lock:
            return {
                "notifications_created_total": self.notifications_created_total,
                "notifications_delivered_total": self.notifications_delivered_total,
                "notifications_failed_total": self.notifications_failed_total,
                "notifications_retried_total": self.notifications_retried_total,
                "notifications_exhausted_total": self.notifications_exhausted_total,
                "notification_delivery_latency_avg_ms": self.avg_delivery_latency_ms,
            }

    def clear(self) -> None:
        with self._lock:
            self.notifications_created_total = 0
            self.notifications_delivered_total = 0
            self.notifications_failed_total = 0
            self.notifications_retried_total = 0
            self.notifications_exhausted_total = 0
            self._total_latency_ms = 0.0
            self._latency_sample_count = 0


# Global singleton metrics instance
notification_metrics = NotificationMetrics()

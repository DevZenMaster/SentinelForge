"""Base Notification Provider Interface (Phase 13)."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.schemas.notification import DeliveryStatus


@dataclass
class DeliveryResult:
    """Outcome of an external delivery attempt."""

    status: DeliveryStatus
    http_status: int | None = None
    failure_reason: str | None = None
    response_metadata: dict[str, Any] = field(default_factory=dict)
    retry_after: int | None = None
    latency_ms: float = 0.0


class NotificationProvider(ABC):
    """Abstract base provider for outbound notification dispatch."""

    @abstractmethod
    async def send(
        self,
        destination_config: dict[str, Any],
        payload: dict[str, Any],
        secret_token: str | None = None,
    ) -> DeliveryResult:
        """Deliver notification payload to the destination."""

    @abstractmethod
    async def test_connection(
        self,
        destination_config: dict[str, Any],
        secret_token: str | None = None,
        custom_message: str | None = None,
    ) -> DeliveryResult:
        """Test outbound connectivity to the destination with a synthetic probe."""

"""Webhook Notification Delivery Provider (Phase 13).

Provides outbound HTTP delivery with:
- Strict SSRF defense (IP checking, scheme checking, no redirect following)
- HMAC-SHA256 request authentication
- Timeouts and bounded payload/response constraints
- Deterministic failure classification (retryable vs non-retryable)
"""

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import settings
from app.schemas.notification import DeliveryStatus
from app.services.notifications.providers.base import DeliveryResult, NotificationProvider
from app.services.notifications.signing import generate_hmac_signature
from app.services.notifications.ssrf import SSRFValidationError, validate_url_ssrf

logger = logging.getLogger("sentinelforge.notifications.webhook")


class WebhookProvider(NotificationProvider):
    """Outbound HTTPS webhook dispatcher."""

    async def send(
        self,
        destination_config: dict[str, Any],
        payload: dict[str, Any],
        secret_token: str | None = None,
    ) -> DeliveryResult:
        """Deliver JSON payload to external webhook endpoint."""
        url = destination_config.get("endpoint_url", "")

        # 1. SSRF Validation
        try:
            validated_url, _, _ = validate_url_ssrf(url)
        except SSRFValidationError as exc:
            logger.warning(
                "SSRF validation blocked webhook dispatch",
                extra={"url": url, "error": str(exc)},
            )
            return DeliveryResult(
                status=DeliveryStatus.FAILED,
                failure_reason=f"SSRF validation rejected destination: {exc}",
            )

        # 2. Payload Serialization and Bounding
        try:
            raw_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        except Exception as exc:
            return DeliveryResult(
                status=DeliveryStatus.FAILED,
                failure_reason=f"Failed to serialize webhook payload: {exc}",
            )

        body_bytes = raw_body.encode("utf-8")
        if len(body_bytes) > settings.WEBHOOK_MAX_PAYLOAD_BYTES:
            return DeliveryResult(
                status=DeliveryStatus.FAILED,
                failure_reason=(
                    f"Payload size ({len(body_bytes)} bytes) exceeds configured limit "
                    f"({settings.WEBHOOK_MAX_PAYLOAD_BYTES} bytes)."
                ),
            )

        # 3. Signature & Headers
        event_id = str(payload.get("event_id", "unknown"))
        timestamp = datetime.now(UTC).isoformat()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "SentinelForge-Webhook/1.0",
            "X-SentinelForge-Event-ID": event_id,
            "X-SentinelForge-Timestamp": timestamp,
        }
        if secret_token:
            signature = generate_hmac_signature(secret_token, timestamp, raw_body)
            headers["X-SentinelForge-Signature"] = signature

        # 4. HTTP Dispatch with Timeouts and Redirect Prohibition
        timeout = httpx.Timeout(
            settings.WEBHOOK_TIMEOUT_SECONDS,
            connect=settings.WEBHOOK_CONNECT_TIMEOUT_SECONDS,
        )

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                verify=True,
            ) as client:
                response = await client.post(
                    validated_url,
                    content=body_bytes,
                    headers=headers,
                )
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        except httpx.TimeoutException as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DeliveryResult(
                status=DeliveryStatus.RETRYING,
                failure_reason=f"Webhook connection/read timed out: {exc}",
                latency_ms=latency_ms,
            )
        except (httpx.ConnectError, httpx.NetworkError) as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DeliveryResult(
                status=DeliveryStatus.RETRYING,
                failure_reason=f"Network error during webhook dispatch: {exc}",
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DeliveryResult(
                status=DeliveryStatus.FAILED,
                failure_reason=f"Unexpected error during webhook dispatch: {exc}",
                latency_ms=latency_ms,
            )

        # 5. Extract Safe Response Metadata
        resp_meta: dict[str, Any] = {
            "content_type": response.headers.get("content-type", "unknown"),
        }

        # 6. Evaluate HTTP Status Code
        http_code = response.status_code
        if 200 <= http_code < 300:
            return DeliveryResult(
                status=DeliveryStatus.DELIVERED,
                http_status=http_code,
                response_metadata=resp_meta,
                latency_ms=latency_ms,
            )

        if http_code == 429 or http_code >= 500:
            # Parse Retry-After if provided
            retry_after_hdr = response.headers.get("Retry-After")
            retry_after_sec = None
            if retry_after_hdr and retry_after_hdr.isdigit():
                retry_after_sec = min(
                    int(retry_after_hdr), settings.NOTIFICATION_MAX_BACKOFF_SECONDS
                )

            return DeliveryResult(
                status=DeliveryStatus.RETRYING,
                http_status=http_code,
                failure_reason=f"Destination returned HTTP {http_code}",
                retry_after=retry_after_sec,
                response_metadata=resp_meta,
                latency_ms=latency_ms,
            )

        # 4xx client errors (other than 429) are non-retryable
        return DeliveryResult(
            status=DeliveryStatus.FAILED,
            http_status=http_code,
            failure_reason=f"Destination rejected payload with HTTP {http_code}",
            response_metadata=resp_meta,
            latency_ms=latency_ms,
        )

    async def test_connection(
        self,
        destination_config: dict[str, Any],
        secret_token: str | None = None,
        custom_message: str | None = None,
    ) -> DeliveryResult:
        """Send a test ping notification to verify destination connectivity."""
        probe_payload = {
            "event_id": "test-probe",
            "event_type": "TEST_NOTIFICATION",
            "timestamp": datetime.now(UTC).isoformat(),
            "payload_version": 1,
            "source_resource_type": "integration",
            "source_resource_id": str(destination_config.get("id", "test")),
            "data": {
                "message": custom_message or "SentinelForge Integration Connectivity Test Probe",
                "test": True,
            },
        }
        return await self.send(destination_config, probe_payload, secret_token)

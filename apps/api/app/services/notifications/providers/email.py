"""Email Notification Delivery Provider (Phase 13).

Provides email notification dispatch with:
- Standard MIME multipart formatting (plain text + sanitized HTML)
- SMTP with TLS encryption
- Minimal security payload attribution
- Graceful test/stub mode when external SMTP server is unconfigured
"""

import asyncio
import email.message
import logging
import smtplib
import time
from datetime import UTC, datetime
from typing import Any

from app.core.config import settings
from app.schemas.notification import DeliveryStatus
from app.services.notifications.providers.base import DeliveryResult, NotificationProvider
from app.services.notifications.templates import format_email_content

logger = logging.getLogger("sentinelforge.notifications.email")


class EmailProvider(NotificationProvider):
    """Outbound email dispatcher using standard SMTP/TLS."""

    async def send(
        self,
        destination_config: dict[str, Any],
        payload: dict[str, Any],
        secret_token: str | None = None,
    ) -> DeliveryResult:
        """Deliver email notification to configured recipients."""
        recipients = destination_config.get("email_recipients")
        if not recipients or not isinstance(recipients, list) or len(recipients) == 0:
            return DeliveryResult(
                status=DeliveryStatus.FAILED,
                failure_reason="No email recipients configured for destination.",
            )

        event_id = str(payload.get("event_id", "unknown"))
        event_type = str(payload.get("event_type", "SECURITY_EVENT"))
        created_at = datetime.now(UTC)
        source_type = str(payload.get("source_resource_type", "security"))
        source_id = str(payload.get("source_resource_id", "unknown"))
        data = payload.get("data", {})

        subject, plain_text, html_body = format_email_content(
            event_id=event_id,
            event_type=event_type,
            created_at=created_at,
            source_resource_type=source_type,
            source_resource_id=source_id,
            payload_data=data,
        )

        start_time = time.perf_counter()

        # If SMTP server is not configured, operate in safe stub mode
        if not settings.SMTP_HOST:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.info(
                "SMTP host not configured; email recorded in stub mode",
                extra={
                    "event_id": event_id,
                    "event_type": event_type,
                    "recipients": recipients,
                    "subject": subject,
                },
            )
            return DeliveryResult(
                status=DeliveryStatus.DELIVERED,
                response_metadata={
                    "mode": "stub",
                    "recipients": recipients,
                    "subject": subject,
                },
                latency_ms=latency_ms,
            )

        # Dispatch via SMTP in worker thread
        try:
            await asyncio.to_thread(
                self._dispatch_smtp,
                recipients=recipients,
                subject=subject,
                plain_text=plain_text,
                html_body=html_body,
            )
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DeliveryResult(
                status=DeliveryStatus.DELIVERED,
                response_metadata={"recipients_count": len(recipients)},
                latency_ms=latency_ms,
            )
        except (smtplib.SMTPConnectError, smtplib.SMTPServerDisconnected, TimeoutError) as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DeliveryResult(
                status=DeliveryStatus.RETRYING,
                failure_reason=f"SMTP connection error: {exc}",
                latency_ms=latency_ms,
            )
        except Exception as exc:
            latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return DeliveryResult(
                status=DeliveryStatus.FAILED,
                failure_reason=f"SMTP dispatch failure: {exc}",
                latency_ms=latency_ms,
            )

    def _dispatch_smtp(
        self,
        recipients: list[str],
        subject: str,
        plain_text: str,
        html_body: str,
    ) -> None:
        """Synchronous SMTP dispatch executed in thread pool."""
        msg = email.message.EmailMessage()
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM_EMAIL
        msg["To"] = ", ".join(recipients)
        msg.set_content(plain_text)
        msg.add_alternative(html_body, subtype="html")

        host = settings.SMTP_HOST or "localhost"
        port = settings.SMTP_PORT

        with smtplib.SMTP(host, port, timeout=10.0) as server:
            if settings.SMTP_USE_TLS:
                server.starttls()
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)

    async def test_connection(
        self,
        destination_config: dict[str, Any],
        secret_token: str | None = None,
        custom_message: str | None = None,
    ) -> DeliveryResult:
        """Send a test email probe."""
        probe_payload = {
            "event_id": "test-email-probe",
            "event_type": "TEST_NOTIFICATION",
            "timestamp": datetime.now(UTC).isoformat(),
            "source_resource_type": "integration",
            "source_resource_id": str(destination_config.get("id", "test")),
            "data": {
                "title": custom_message or "SentinelForge Email Connectivity Test Probe",
                "severity": "INFO",
                "status": "TEST",
            },
        }
        return await self.send(destination_config, probe_payload, secret_token)

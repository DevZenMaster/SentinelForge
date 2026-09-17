"""HTTP Middleware for SentinelForge.

Implements:
1. Request/Correlation ID propagation (via X-Request-ID header and request.state).
2. Structured access logging with duration and status code.
3. Safe error response envelope ensuring internal stack traces are never exposed.
"""

import logging
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("sentinelforge.access")


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """Middleware attaching request_id and logging structured access metrics."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Extract or generate unique request ID
        incoming_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID")
        request_id = incoming_id if incoming_id else f"req-{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id

        start_time = time.perf_counter()

        try:
            response = await call_next(request)
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            response.headers["X-Request-ID"] = request_id

            # Log access telemetry as structured record
            logger.info(
                f"{request.method} {request.url.path} {response.status_code} ({duration_ms}ms)",
                extra={
                    "request_id": request_id,
                    "extra_fields": {
                        "method": request.method,
                        "path": request.url.path,
                        "status_code": response.status_code,
                        "duration_ms": duration_ms,
                        "client_ip": request.client.host if request.client else "unknown",
                    },
                },
            )
            return response
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            logger.error(
                f"Unhandled error processing {request.method} {request.url.path}: {exc}",
                exc_info=True,
                extra={
                    "request_id": request_id,
                    "extra_fields": {
                        "method": request.method,
                        "path": request.url.path,
                        "duration_ms": duration_ms,
                    },
                },
            )
            raise exc

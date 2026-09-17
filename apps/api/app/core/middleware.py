"""HTTP Middleware for SentinelForge.

Implements:
1. Request/Correlation ID propagation (via X-Request-ID header and request.state).
2. Structured access logging with duration and status code.
3. Security headers enforcement (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
4. Defense-in-depth CSRF protection for cookie-authenticated state-changing requests.
"""

import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

logger = logging.getLogger("sentinelforge.access")

SAFE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-:.]{1,64}$")


class RequestCorrelationMiddleware(BaseHTTPMiddleware):
    """Middleware attaching request_id and logging structured access metrics."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Extract or generate unique request ID, sanitizing against header/log injection
        incoming_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID")
        if incoming_id and SAFE_REQUEST_ID_REGEX.match(incoming_id):
            request_id = incoming_id
        else:
            request_id = f"req-{uuid.uuid4().hex[:16]}"
        request.state.request_id = request_id

        # Enforce maximum payload size
        # (Content-Length check or streaming check for chunked/missing header)
        if request.method in ("POST", "PUT", "PATCH"):
            content_length_header = request.headers.get("content-length")
            if content_length_header:
                try:
                    content_length = int(content_length_header)
                    if content_length > settings.MAX_EVENT_PAYLOAD_BYTES:
                        return JSONResponse(
                            status_code=413,
                            content={
                                "data": None,
                                "meta": {
                                    "timestamp": datetime.now(UTC).isoformat(),
                                    "request_id": str(request_id),
                                },
                                "error": {
                                    "code": "PAYLOAD_TOO_LARGE",
                                    "message": (
                                        f"Request payload exceeds maximum permitted size "
                                        f"of {settings.MAX_EVENT_PAYLOAD_BYTES} bytes."
                                    ),
                                    "details": None,
                                },
                            },
                            headers={"X-Request-ID": str(request_id)},
                        )
                except ValueError:
                    pass
            else:
                # Enforce streaming body size limit to protect against unbounded chunked transfers
                body = bytearray()
                async for chunk in request.stream():
                    body.extend(chunk)
                    if len(body) > settings.MAX_EVENT_PAYLOAD_BYTES:
                        return JSONResponse(
                            status_code=413,
                            content={
                                "data": None,
                                "meta": {
                                    "timestamp": datetime.now(UTC).isoformat(),
                                    "request_id": str(request_id),
                                },
                                "error": {
                                    "code": "PAYLOAD_TOO_LARGE",
                                    "message": (
                                        f"Request payload exceeds maximum permitted size "
                                        f"of {settings.MAX_EVENT_PAYLOAD_BYTES} bytes."
                                    ),
                                    "details": None,
                                },
                            },
                            headers={"X-Request-ID": str(request_id)},
                        )
                request._body = bytes(body)

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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing defense-in-depth security headers on all responses."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; frame-ancestors 'none'; object-src 'none';"
        )
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """Protects cookie-authenticated state-changing requests against CSRF.

    For state-changing methods (POST, PUT, PATCH, DELETE) with an active session cookie:
    1. Validates custom header (X-Requested-With / X-CSRF-Token / application/json content).
    2. Validates Origin/Referer against allowed CORS origins or host.
    """

    UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not settings.CSRF_PROTECTION_ENABLED:
            return await call_next(request)

        if request.method in self.UNSAFE_METHODS:
            session_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
            if session_cookie:
                # 1. Custom header check to prevent ambient HTML form submission
                has_custom_header = bool(
                    request.headers.get("X-Requested-With")
                    or request.headers.get("X-CSRF-Token")
                    or request.headers.get("Content-Type", "").startswith("application/json")
                )
                if not has_custom_header:
                    request_id = getattr(request.state, "request_id", "unknown")
                    return JSONResponse(
                        status_code=403,
                        content={
                            "data": None,
                            "meta": {
                                "timestamp": datetime.now(UTC).isoformat(),
                                "request_id": str(request_id),
                            },
                            "error": {
                                "code": "CSRF_ERROR",
                                "message": (
                                    "Cross-Site Request Forgery validation failed: "
                                    "missing required anti-CSRF request header."
                                ),
                                "details": None,
                            },
                        },
                        headers={"X-Request-ID": str(request_id)},
                    )

                # 2. Origin/Referer verification
                origin = request.headers.get("Origin") or request.headers.get("Referer")
                if origin:
                    origin_clean = origin.rstrip("/")
                    allowed = False
                    for allowed_origin in settings.BACKEND_CORS_ORIGINS:
                        if origin_clean.startswith(allowed_origin.rstrip("/")):
                            allowed = True
                            break
                    host = request.headers.get("Host", "")
                    if host and host in origin_clean:
                        allowed = True

                    if not allowed:
                        request_id = getattr(request.state, "request_id", "unknown")
                        return JSONResponse(
                            status_code=403,
                            content={
                                "data": None,
                                "meta": {
                                    "timestamp": datetime.now(UTC).isoformat(),
                                    "request_id": str(request_id),
                                },
                                "error": {
                                    "code": "CSRF_ERROR",
                                    "message": (
                                        "Cross-Site Request Forgery validation failed: "
                                        "untrusted request origin."
                                    ),
                                    "details": None,
                                },
                            },
                            headers={"X-Request-ID": str(request_id)},
                        )

        return await call_next(request)

"""Standardized error codes and error response builders for SentinelForge API.

Defines the authoritative error taxonomy required for deterministic error monitoring,
preventing leaking internal implementation details, Python tracebacks, or raw SQL queries.
"""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from fastapi.responses import JSONResponse


class ErrorCode(StrEnum):
    """Authoritative API error taxonomy."""

    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    AUTHORIZATION_ERROR = "AUTHORIZATION_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    CSRF_ERROR = "CSRF_ERROR"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    DATABASE_ERROR = "DATABASE_ERROR"
    INTEGRATION_ERROR = "INTEGRATION_ERROR"
    INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR"


def create_error_response(
    status_code: int,
    code: ErrorCode | str,
    message: str,
    request_id: str = "unknown",
    details: Any = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Build a deterministic, standardized API error response envelope."""
    response_headers = {"X-Request-ID": str(request_id)}
    if headers:
        response_headers.update(headers)

    code_str = code.value if isinstance(code, ErrorCode) else str(code)

    return JSONResponse(
        status_code=status_code,
        content={
            "data": None,
            "meta": {
                "timestamp": datetime.now(UTC).isoformat(),
                "request_id": str(request_id),
            },
            "error": {
                "code": code_str,
                "message": message,
                "details": details,
            },
        },
        headers=response_headers,
    )

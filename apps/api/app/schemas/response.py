"""Standardized API Response Envelopes.

Enforces consistent `{ "data": ..., "meta": ..., "error": ... }` envelope format
across all API endpoints.
"""

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Structured error payload."""

    code: str = Field(..., description="Machine-readable error code")
    message: str = Field(..., description="Human-readable error description")
    details: Any | None = Field(default=None, description="Optional diagnostic details")


class ResponseMetadata(BaseModel):
    """Envelope metadata including request correlation ID and UTC timestamp."""

    timestamp: str = Field(..., description="ISO 8601 UTC timestamp")
    request_id: str = Field(..., description="Correlation / Request ID")
    page: int | None = Field(default=None, description="Current page number if paginated")
    limit: int | None = Field(default=None, description="Page size if paginated")
    total: int | None = Field(default=None, description="Total record count if paginated")


class APIResponse[DataT](BaseModel):
    """Standardized top-level API response envelope."""

    data: DataT | None = None
    meta: ResponseMetadata
    error: ErrorDetail | None = None

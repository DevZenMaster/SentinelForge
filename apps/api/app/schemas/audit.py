"""Audit Log Schemas for Security Monitoring."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuditLogResponse(BaseModel):
    """Sanitized representation of an application audit trail record."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_user_id: uuid.UUID | None = None
    actor_username: str | None = None
    action: str
    resource_type: str
    resource_id: str
    old_value: dict[str, Any] | None = None
    new_value: dict[str, Any] | None = None
    source_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None
    timestamp: datetime


class AuditLogListResponse(BaseModel):
    """Paginated collection of security audit log records."""

    items: list[AuditLogResponse]
    total: int = Field(..., description="Total matching audit records")
    page: int = Field(..., description="Current page index (1-based)")
    limit: int = Field(..., description="Items per page")
    total_pages: int = Field(..., description="Total pages available")

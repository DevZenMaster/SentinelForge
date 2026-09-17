"""Append-Only Security Audit Log ORM Model.

Tracks all security-sensitive actions, identity changes, rule revisions,
and investigation events.
Note: Audit logging is strictly append-only at the application layer;
no API routes exist to mutate or delete existing audit entries.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.auth import User


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """Application-level append-only audit record."""

    __tablename__ = "audit_logs"

    # Actor attribution (nullable to support unauthenticated attempts or system jobs)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    # State capture for forensic diffing
    old_value: Mapped[dict[str, Any] | None] = mapped_column(JSON_COMPAT, nullable=True)
    new_value: Mapped[dict[str, Any] | None] = mapped_column(JSON_COMPAT, nullable=True)

    # Network & trace context
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    # Timestamp (strictly UTC)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    # Relationships
    actor: Mapped["User"] = relationship("User")

    __table_args__ = (
        Index("ix_audit_logs_actor_timestamp", "actor_user_id", "timestamp"),
        Index("ix_audit_logs_resource_timestamp", "resource_type", "resource_id", "timestamp"),
    )

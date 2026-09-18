"""Detection Rule ORM Model.

Supports deterministic rule configuration with full versioning so alerts
accurately identify the exact rule definition and logic that triggered them.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.auth import User


class DetectionRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Detection rule entity supporting versioned rule management."""

    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(
        String(32), default="security", server_default="security", index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(16), default="DRAFT", server_default="DRAFT", index=True, nullable=False
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    time_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, default=dict, nullable=False)

    # Attribution and lifecycle audit metadata
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    activated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    creator: Mapped["User | None"] = relationship("User", foreign_keys=[created_by], lazy="select")
    updater: Mapped["User | None"] = relationship("User", foreign_keys=[updated_by], lazy="select")
    activator: Mapped["User | None"] = relationship(
        "User", foreign_keys=[activated_by], lazy="select"
    )

    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_detection_rules_rule_id_version"),
        Index(
            "uq_detection_rules_rule_id_active",
            "rule_id",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
            sqlite_where=text("status = 'ACTIVE'"),
        ),
        Index("ix_detection_rules_lookup", "rule_id", "enabled", "event_type"),
    )

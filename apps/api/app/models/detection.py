"""Detection Rule ORM Model.

Supports deterministic rule configuration with full versioning so alerts
accurately identify the exact rule definition and logic that triggered them.
"""

from typing import Any

from sqlalchemy import Boolean, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import JSON_COMPAT, Base, TimestampMixin, UUIDPrimaryKeyMixin


class DetectionRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Detection rule entity supporting versioned rule management."""

    __tablename__ = "detection_rules"

    rule_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)
    time_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    conditions: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, default=dict, nullable=False)

    __table_args__ = (
        UniqueConstraint("rule_id", "version", name="uq_detection_rules_rule_id_version"),
        Index("ix_detection_rules_lookup", "rule_id", "enabled", "event_type"),
    )

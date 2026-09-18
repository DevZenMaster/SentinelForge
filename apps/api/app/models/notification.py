"""Notification and External Integration Models (Phase 13).

Provides persistent models for external integration destinations (webhooks, email),
declarative notification routing policies, authoritative security operations events,
and auditable delivery attempts with deterministic idempotency.
"""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import JSON_COMPAT, Base, TimestampMixin, UUIDPrimaryKeyMixin, utc_now

if TYPE_CHECKING:
    from app.models.auth import User


class Integration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Configured external delivery destination (Webhook or Email)."""

    __tablename__ = "integrations"

    # Destination naming and type
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # WEBHOOK, EMAIL
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)

    # Destination targets
    endpoint_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    email_recipients: Mapped[list[str] | None] = mapped_column(JSON_COMPAT, nullable=True)

    # Security credentials (write-only / masked)
    secret_token: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Actor attribution
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Operational delivery health metrics
    last_delivery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_successful_delivery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failed_delivery_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Optimistic concurrency version
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Relationships
    created_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[created_by_user_id], lazy="selectin"
    )
    updated_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[updated_by_user_id], lazy="selectin"
    )
    deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        "NotificationDelivery",
        back_populates="destination",
        cascade="all, delete-orphan",
        lazy="select",
    )


class NotificationPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Declarative policy routing authoritative security events to destinations."""

    __tablename__ = "notification_policies"

    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)

    # Filter criteria
    event_types: Mapped[list[str]] = mapped_column(JSON_COMPAT, nullable=False)
    min_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    destination_ids: Mapped[list[str]] = mapped_column(JSON_COMPAT, nullable=False)
    filters: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, default=dict, nullable=False)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Actor attribution
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    updated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Optimistic concurrency version
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Relationships
    created_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[created_by_user_id], lazy="selectin"
    )
    updated_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[updated_by_user_id], lazy="selectin"
    )
    deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        "NotificationDelivery",
        back_populates="policy",
        cascade="all, delete-orphan",
        lazy="select",
    )


class NotificationEvent(Base, UUIDPrimaryKeyMixin):
    """Authoritative security operations event eligible for notification routing."""

    __tablename__ = "notification_events"

    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_resource_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    source_resource_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    payload_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(128), index=True, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON_COMPAT, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )

    # Relationships
    deliveries: Mapped[list["NotificationDelivery"]] = relationship(
        "NotificationDelivery",
        back_populates="event",
        cascade="all, delete-orphan",
        lazy="select",
    )

    __table_args__ = (
        Index(
            "ix_notification_events_source",
            "source_resource_type",
            "source_resource_id",
        ),
    )


class NotificationDelivery(Base, UUIDPrimaryKeyMixin):
    """Specific delivery job bound to an event, policy, and destination."""

    __tablename__ = "notification_deliveries"

    event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_events.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("notification_policies.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    destination_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("integrations.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    # Deterministic idempotency key: event_id + policy_id + destination_id
    idempotency_key: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )

    # Delivery lifecycle state:
    # PENDING, DELIVERING, DELIVERED, FAILED, RETRYING, EXHAUSTED, CANCELLED
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True, nullable=False)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    # Temporal execution tracking
    first_attempted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_attempted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Response and failure metadata
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSON_COMPAT, default=dict, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

    # Relationships
    event: Mapped["NotificationEvent"] = relationship(
        "NotificationEvent", back_populates="deliveries", lazy="selectin"
    )
    policy: Mapped["NotificationPolicy"] = relationship(
        "NotificationPolicy", back_populates="deliveries", lazy="selectin"
    )
    destination: Mapped["Integration"] = relationship(
        "Integration", back_populates="deliveries", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint("idempotency_key", name="uq_notification_deliveries_idempotency_key"),
        Index("ix_notification_deliveries_status_next_retry", "status", "next_retry_at"),
    )

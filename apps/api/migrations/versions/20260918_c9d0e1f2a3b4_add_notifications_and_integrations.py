"""add_notifications_and_integrations

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-09-18 16:30:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c9d0e1f2a3b4"
down_revision: str | None = "b8c9d0e1f2a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

json_type = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")


def upgrade() -> None:
    # 1. integrations table
    op.create_table(
        "integrations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("endpoint_url", sa.String(length=1024), nullable=True),
        sa.Column("email_recipients", json_type, nullable=True),
        sa.Column("secret_token", sa.String(length=512), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("updated_by_user_id", sa.UUID(), nullable=True),
        sa.Column("last_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_successful_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_failed_delivery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_integrations_created_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_integrations_updated_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_integrations"),
    )
    op.create_index("ix_integrations_name", "integrations", ["name"], unique=True)
    op.create_index("ix_integrations_type", "integrations", ["type"], unique=False)
    op.create_index("ix_integrations_enabled", "integrations", ["enabled"], unique=False)

    # 2. notification_policies table
    op.create_table(
        "notification_policies",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("event_types", json_type, nullable=False),
        sa.Column("min_severity", sa.String(length=16), nullable=True),
        sa.Column("destination_ids", json_type, nullable=False),
        sa.Column("filters", json_type, server_default=sa.text("'{}'"), nullable=False),
        sa.Column("cooldown_seconds", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
        sa.Column("updated_by_user_id", sa.UUID(), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_notification_policies_created_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["updated_by_user_id"],
            ["users.id"],
            name="fk_notification_policies_updated_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_notification_policies"),
    )
    op.create_index(
        "ix_notification_policies_name", "notification_policies", ["name"], unique=True
    )
    op.create_index(
        "ix_notification_policies_enabled", "notification_policies", ["enabled"], unique=False
    )

    # 3. notification_events table
    op.create_table(
        "notification_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("source_resource_type", sa.String(length=32), nullable=False),
        sa.Column("source_resource_id", sa.String(length=128), nullable=False),
        sa.Column("payload_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=True),
        sa.Column("payload", json_type, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_notification_events"),
    )
    op.create_index(
        "ix_notification_events_created_at", "notification_events", ["created_at"], unique=False
    )
    op.create_index(
        "ix_notification_events_event_type", "notification_events", ["event_type"], unique=False
    )
    op.create_index(
        "ix_notification_events_correlation_id",
        "notification_events",
        ["correlation_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_events_source",
        "notification_events",
        ["source_resource_type", "source_resource_id"],
        unique=False,
    )

    # 4. notification_deliveries table
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("event_id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("destination_id", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="PENDING", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="3", nullable=False),
        sa.Column("first_attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_attempted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("response_metadata", json_type, server_default=sa.text("'{}'"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["notification_events.id"],
            name="fk_notification_deliveries_event_id_notification_events",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["policy_id"],
            ["notification_policies.id"],
            name="fk_notification_deliveries_policy_id_notification_policies",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["destination_id"],
            ["integrations.id"],
            name="fk_notification_deliveries_destination_id_integrations",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_notification_deliveries"),
        sa.UniqueConstraint(
            "idempotency_key", name="uq_notification_deliveries_idempotency_key"
        ),
    )
    op.create_index(
        "ix_notification_deliveries_event_id",
        "notification_deliveries",
        ["event_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_policy_id",
        "notification_deliveries",
        ["policy_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_destination_id",
        "notification_deliveries",
        ["destination_id"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_status",
        "notification_deliveries",
        ["status"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_created_at",
        "notification_deliveries",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_next_retry_at",
        "notification_deliveries",
        ["next_retry_at"],
        unique=False,
    )
    op.create_index(
        "ix_notification_deliveries_status_next_retry",
        "notification_deliveries",
        ["status", "next_retry_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table("notification_deliveries")
    op.drop_table("notification_events")
    op.drop_table("notification_policies")
    op.drop_table("integrations")

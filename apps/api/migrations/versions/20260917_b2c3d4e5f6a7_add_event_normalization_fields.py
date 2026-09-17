"""add_event_normalization_fields

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-17 10:15:00.000000+00:00

"""

from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: str | None = "a1b2c3d4e5f6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add canonical telemetry fields
    op.add_column("events", sa.Column("source_port", sa.Integer(), nullable=True))
    op.add_column(
        "events",
        sa.Column("outcome", sa.String(length=16), server_default="unknown", nullable=False),
    )
    op.create_index(op.f("ix_events_outcome"), "events", ["outcome"], unique=False)

    # 2. Add normalization tracking and versioning metadata
    op.add_column(
        "events",
        sa.Column("normalization_status", sa.String(length=16), server_default="PENDING", nullable=False),
    )
    op.create_index(
        op.f("ix_events_normalization_status"), "events", ["normalization_status"], unique=False
    )
    op.add_column("events", sa.Column("parser_name", sa.String(length=64), nullable=True))
    op.add_column("events", sa.Column("parser_version", sa.String(length=16), nullable=True))
    op.add_column("events", sa.Column("normalization_version", sa.String(length=16), nullable=True))
    op.add_column("events", sa.Column("normalized_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "events",
        sa.Column(
            "normalization_errors",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default="[]",
            nullable=False,
        ),
    )

    # 3. Add extracted source-specific attributes payload
    op.add_column(
        "events",
        sa.Column(
            "attributes",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default="{}",
            nullable=False,
        ),
    )

    # 4. Add multi-field temporal compound index for detection rule lookups
    op.create_index(
        "ix_events_event_type_action_timestamp",
        "events",
        ["event_type", "action", "timestamp"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_events_event_type_action_timestamp", table_name="events")
    op.drop_index(op.f("ix_events_normalization_status"), table_name="events")
    op.drop_index(op.f("ix_events_outcome"), table_name="events")

    op.drop_column("events", "attributes")
    op.drop_column("events", "normalization_errors")
    op.drop_column("events", "normalized_at")
    op.drop_column("events", "normalization_version")
    op.drop_column("events", "parser_version")
    op.drop_column("events", "parser_name")
    op.drop_column("events", "normalization_status")
    op.drop_column("events", "outcome")
    op.drop_column("events", "source_port")

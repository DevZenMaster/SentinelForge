"""add_alert_dedup_and_evidence_fields

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-17 11:00:00.000000+00:00

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: str | None = "b2c3d4e5f6a7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add deduplication and correlation fields
    op.add_column(
        "alerts",
        sa.Column("dedup_key", sa.String(length=255), nullable=False),
    )
    op.add_column(
        "alerts",
        sa.Column("correlation_key", sa.String(length=255), nullable=False),
    )

    # 2. Add metrics and explainable evidence
    op.add_column(
        "alerts",
        sa.Column("observed_count", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "alerts",
        sa.Column("threshold", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "alerts",
        sa.Column(
            "evidence",
            postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), "sqlite"),
            server_default="{}",
            nullable=False,
        ),
    )

    # 3. Add unique constraint and indexes
    op.create_unique_constraint("uq_alerts_dedup_key", "alerts", ["dedup_key"])
    op.create_index(op.f("ix_alerts_dedup_key"), "alerts", ["dedup_key"], unique=False)
    op.create_index(op.f("ix_alerts_correlation_key"), "alerts", ["correlation_key"], unique=False)
    op.create_index("ix_alerts_rule_id_created_at", "alerts", ["rule_id", "created_at"], unique=False)
    op.create_index(
        "ix_alerts_correlation_key_created_at",
        "alerts",
        ["correlation_key", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_correlation_key_created_at", table_name="alerts")
    op.drop_index("ix_alerts_rule_id_created_at", table_name="alerts")
    op.drop_index(op.f("ix_alerts_correlation_key"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_dedup_key"), table_name="alerts")
    op.drop_constraint("uq_alerts_dedup_key", "alerts", type_="unique")

    op.drop_column("alerts", "evidence")
    op.drop_column("alerts", "threshold")
    op.drop_column("alerts", "observed_count")
    op.drop_column("alerts", "correlation_key")
    op.drop_column("alerts", "dedup_key")

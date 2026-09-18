"""add_alert_operations_and_triage

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-09-18 08:30:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b8c9d0e1f2a3"
down_revision: str | None = "a7b8c9d0e1f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add operational triage columns to alerts table
    op.add_column("alerts", sa.Column("assignee_id", sa.UUID(), nullable=True))
    op.add_column(
        "alerts", sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("alerts", sa.Column("acknowledged_by_id", sa.UUID(), nullable=True))
    op.add_column("alerts", sa.Column("resolved_by_id", sa.UUID(), nullable=True))
    op.add_column("alerts", sa.Column("closed_by_id", sa.UUID(), nullable=True))
    op.add_column(
        "alerts", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("alerts", sa.Column("suppressed_by_id", sa.UUID(), nullable=True))
    op.add_column(
        "alerts", sa.Column("suppressed_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("alerts", sa.Column("suppression_reason", sa.Text(), nullable=True))
    op.add_column(
        "alerts", sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "alerts",
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
    )

    # 2. Add foreign keys
    op.create_foreign_key(
        op.f("fk_alerts_assignee_id_users"),
        "alerts",
        "users",
        ["assignee_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_alerts_acknowledged_by_id_users"),
        "alerts",
        "users",
        ["acknowledged_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_alerts_resolved_by_id_users"),
        "alerts",
        "users",
        ["resolved_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_alerts_closed_by_id_users"),
        "alerts",
        "users",
        ["closed_by_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_alerts_suppressed_by_id_users"),
        "alerts",
        "users",
        ["suppressed_by_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # 3. Add indexes to alerts
    op.create_index(op.f("ix_alerts_assignee_id"), "alerts", ["assignee_id"], unique=False)
    op.create_index(
        "ix_alerts_status_assignee", "alerts", ["status", "assignee_id"], unique=False
    )
    op.create_index(
        "ix_alerts_rule_version", "alerts", ["rule_id", "rule_version"], unique=False
    )

    # 4. Create alert_notes table
    op.create_table(
        "alert_notes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("alert_id", sa.UUID(), nullable=False),
        sa.Column("author_user_id", sa.UUID(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_alert_notes")),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
            name=op.f("fk_alert_notes_alert_id_alerts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["author_user_id"],
            ["users.id"],
            name=op.f("fk_alert_notes_author_user_id_users"),
            ondelete="RESTRICT",
        ),
    )
    op.create_index(
        op.f("ix_alert_notes_alert_id"), "alert_notes", ["alert_id"], unique=False
    )
    op.create_index(
        op.f("ix_alert_notes_author_user_id"),
        "alert_notes",
        ["author_user_id"],
        unique=False,
    )
    op.create_index(
        "ix_alert_notes_alert_created",
        "alert_notes",
        ["alert_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    # 1. Drop alert_notes table and its indexes
    op.drop_index("ix_alert_notes_alert_created", table_name="alert_notes")
    op.drop_index(op.f("ix_alert_notes_author_user_id"), table_name="alert_notes")
    op.drop_index(op.f("ix_alert_notes_alert_id"), table_name="alert_notes")
    op.drop_table("alert_notes")

    # 2. Drop indexes on alerts
    op.drop_index("ix_alerts_rule_version", table_name="alerts")
    op.drop_index("ix_alerts_status_assignee", table_name="alerts")
    op.drop_index(op.f("ix_alerts_assignee_id"), table_name="alerts")

    # 3. Drop foreign keys on alerts
    op.drop_constraint(
        op.f("fk_alerts_suppressed_by_id_users"), "alerts", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_alerts_closed_by_id_users"), "alerts", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_alerts_resolved_by_id_users"), "alerts", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_alerts_acknowledged_by_id_users"), "alerts", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_alerts_assignee_id_users"), "alerts", type_="foreignkey"
    )

    # 4. Drop columns on alerts
    op.drop_column("alerts", "version")
    op.drop_column("alerts", "suppressed_until")
    op.drop_column("alerts", "suppression_reason")
    op.drop_column("alerts", "suppressed_at")
    op.drop_column("alerts", "suppressed_by_id")
    op.drop_column("alerts", "closed_at")
    op.drop_column("alerts", "closed_by_id")
    op.drop_column("alerts", "resolved_by_id")
    op.drop_column("alerts", "acknowledged_by_id")
    op.drop_column("alerts", "assigned_at")
    op.drop_column("alerts", "assignee_id")

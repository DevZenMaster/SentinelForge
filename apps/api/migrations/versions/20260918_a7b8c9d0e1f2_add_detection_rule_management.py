"""add_detection_rule_management

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-09-18 07:45:00.000000+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a7b8c9d0e1f2"
down_revision: str | None = "f6a7b8c9d0e1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "detection_rules",
        sa.Column("category", sa.String(length=32), server_default="security", nullable=False),
    )
    op.add_column(
        "detection_rules",
        sa.Column("status", sa.String(length=16), server_default="DRAFT", nullable=False),
    )
    op.add_column("detection_rules", sa.Column("created_by", sa.UUID(), nullable=True))
    op.add_column("detection_rules", sa.Column("updated_by", sa.UUID(), nullable=True))
    op.add_column(
        "detection_rules", sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("detection_rules", sa.Column("activated_by", sa.UUID(), nullable=True))

    op.create_foreign_key(
        op.f("fk_detection_rules_created_by_users"),
        "detection_rules",
        "users",
        ["created_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_detection_rules_updated_by_users"),
        "detection_rules",
        "users",
        ["updated_by"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        op.f("fk_detection_rules_activated_by_users"),
        "detection_rules",
        "users",
        ["activated_by"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_index("ix_detection_rules_status", "detection_rules", ["status"], unique=False)
    op.create_index("ix_detection_rules_category", "detection_rules", ["category"], unique=False)
    op.create_index(
        "uq_detection_rules_rule_id_active",
        "detection_rules",
        ["rule_id"],
        unique=True,
        postgresql_where=sa.text("status = 'ACTIVE'"),
        sqlite_where=sa.text("status = 'ACTIVE'"),
    )


def downgrade() -> None:
    op.drop_index("uq_detection_rules_rule_id_active", table_name="detection_rules")
    op.drop_index("ix_detection_rules_category", table_name="detection_rules")
    op.drop_index("ix_detection_rules_status", table_name="detection_rules")

    op.drop_constraint(
        op.f("fk_detection_rules_activated_by_users"), "detection_rules", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_detection_rules_updated_by_users"), "detection_rules", type_="foreignkey"
    )
    op.drop_constraint(
        op.f("fk_detection_rules_created_by_users"), "detection_rules", type_="foreignkey"
    )

    op.drop_column("detection_rules", "activated_by")
    op.drop_column("detection_rules", "activated_at")
    op.drop_column("detection_rules", "updated_by")
    op.drop_column("detection_rules", "created_by")
    op.drop_column("detection_rules", "status")
    op.drop_column("detection_rules", "category")

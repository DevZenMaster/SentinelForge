"""add_external_event_id_to_events

Revision ID: a1b2c3d4e5f6
Revises: f955ae36ab9f
Create Date: 2026-09-17 08:56:00.000000+00:00

"""

from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "f955ae36ab9f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("events", sa.Column("external_event_id", sa.String(length=128), nullable=True))
    op.create_index(
        op.f("ix_events_external_event_id"),
        "events",
        ["external_event_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_events_external_event_id"), table_name="events")
    op.drop_column("events", "external_event_id")

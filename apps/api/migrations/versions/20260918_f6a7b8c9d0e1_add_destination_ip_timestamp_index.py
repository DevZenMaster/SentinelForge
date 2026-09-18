"""add_destination_ip_timestamp_index

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-09-18 02:30:00.000000+00:00

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f6a7b8c9d0e1"
down_revision: str | None = "e5f6a7b8c9d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "ix_events_destination_ip_timestamp",
        "events",
        ["destination_ip", "timestamp"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_events_destination_ip_timestamp", table_name="events")

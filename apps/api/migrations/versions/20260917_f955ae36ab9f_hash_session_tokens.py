"""hash_session_tokens

Revision ID: f955ae36ab9f
Revises: 596e87f010e6
Create Date: 2026-09-17 03:03:26.320921+00:00

"""

from collections.abc import Sequence
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "f955ae36ab9f"
down_revision: str | None = "596e87f010e6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop index on old raw token column
    op.drop_index(op.f("ix_sessions_session_token"), table_name="sessions")

    # Rename column session_token to session_token_hash and resize to 64 chars (SHA-256 hex)
    op.alter_column(
        "sessions",
        "session_token",
        new_column_name="session_token_hash",
        existing_type=sa.String(length=128),
        type_=sa.String(length=64),
        nullable=False,
    )

    # Create new unique index on session_token_hash
    op.create_index(
        op.f("ix_sessions_session_token_hash"),
        "sessions",
        ["session_token_hash"],
        unique=True,
    )


def downgrade() -> None:
    # Drop new index
    op.drop_index(op.f("ix_sessions_session_token_hash"), table_name="sessions")

    # Rename back to session_token
    op.alter_column(
        "sessions",
        "session_token_hash",
        new_column_name="session_token",
        existing_type=sa.String(length=64),
        type_=sa.String(length=128),
        nullable=False,
    )

    # Re-create old index
    op.create_index(
        op.f("ix_sessions_session_token"),
        "sessions",
        ["session_token"],
        unique=True,
    )

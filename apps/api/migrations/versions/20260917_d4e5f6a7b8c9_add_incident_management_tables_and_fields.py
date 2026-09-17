"""add_incident_management_tables_and_fields

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-17 12:00:00.000000+00:00

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: str | None = "c3d4e5f6a7b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add fields and constraints to incidents table
    op.add_column("incidents", sa.Column("incident_id", sa.String(length=32), nullable=False))
    op.add_column(
        "incidents",
        sa.Column("priority", sa.String(length=16), server_default="MEDIUM", nullable=False),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "created_by_user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column(
        "incidents",
        sa.Column(
            "resolved_by_user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column("incidents", sa.Column("resolution_category", sa.String(length=32), nullable=True))
    op.add_column(
        "incidents",
        sa.Column(
            "closed_by_user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.add_column("incidents", sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))

    op.create_unique_constraint("uq_incidents_incident_id", "incidents", ["incident_id"])
    op.create_index(op.f("ix_incidents_incident_id"), "incidents", ["incident_id"], unique=False)
    op.create_index(op.f("ix_incidents_priority"), "incidents", ["priority"], unique=False)
    op.create_index(
        "ix_incidents_severity_created_at", "incidents", ["severity", "created_at"], unique=False
    )
    op.create_index(
        "ix_incidents_priority_created_at", "incidents", ["priority", "created_at"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_created_by_user_id"), "incidents", ["created_by_user_id"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_resolved_by_user_id"), "incidents", ["resolved_by_user_id"], unique=False
    )
    op.create_index(
        op.f("ix_incidents_closed_by_user_id"), "incidents", ["closed_by_user_id"], unique=False
    )

    # 2. Add added_by_user_id to incident_alerts table
    op.add_column(
        "incident_alerts",
        sa.Column(
            "added_by_user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index(
        op.f("ix_incident_alerts_added_by_user_id"),
        "incident_alerts",
        ["added_by_user_id"],
        unique=False,
    )

    # 3. Create incident_events table (RESTRICT on event_id for evidence preservation)
    op.create_table(
        "incident_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "incident_id",
            sa.UUID(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.UUID(),
            sa.ForeignKey("events.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "added_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "added_by_user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("incident_id", "event_id", name="uq_incident_events_incident_id_event_id"),
    )
    op.create_index(
        op.f("ix_incident_events_incident_id"), "incident_events", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_events_event_id"), "incident_events", ["event_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_events_added_by_user_id"),
        "incident_events",
        ["added_by_user_id"],
        unique=False,
    )

    # 4. Create incident_notes table (RESTRICT on author_user_id)
    op.create_table(
        "incident_notes",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "incident_id",
            sa.UUID(),
            sa.ForeignKey("incidents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "author_user_id",
            sa.UUID(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
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
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_incident_notes_incident_id"), "incident_notes", ["incident_id"], unique=False
    )
    op.create_index(
        op.f("ix_incident_notes_author_user_id"), "incident_notes", ["author_user_id"], unique=False
    )
    op.create_index(
        "ix_incident_notes_incident_created",
        "incident_notes",
        ["incident_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    # 1. Drop incident_notes
    op.drop_index("ix_incident_notes_incident_created", table_name="incident_notes")
    op.drop_index(op.f("ix_incident_notes_author_user_id"), table_name="incident_notes")
    op.drop_index(op.f("ix_incident_notes_incident_id"), table_name="incident_notes")
    op.drop_table("incident_notes")

    # 2. Drop incident_events
    op.drop_index(op.f("ix_incident_events_added_by_user_id"), table_name="incident_events")
    op.drop_index(op.f("ix_incident_events_event_id"), table_name="incident_events")
    op.drop_index(op.f("ix_incident_events_incident_id"), table_name="incident_events")
    op.drop_table("incident_events")

    # 3. Drop added_by_user_id from incident_alerts
    op.drop_index(op.f("ix_incident_alerts_added_by_user_id"), table_name="incident_alerts")
    op.drop_column("incident_alerts", "added_by_user_id")

    # 4. Drop columns and indexes from incidents
    op.drop_index(op.f("ix_incidents_closed_by_user_id"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_resolved_by_user_id"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_created_by_user_id"), table_name="incidents")
    op.drop_index("ix_incidents_priority_created_at", table_name="incidents")
    op.drop_index("ix_incidents_severity_created_at", table_name="incidents")
    op.drop_index(op.f("ix_incidents_priority"), table_name="incidents")
    op.drop_index(op.f("ix_incidents_incident_id"), table_name="incidents")
    op.drop_constraint("uq_incidents_incident_id", "incidents", type_="unique")

    op.drop_column("incidents", "closed_at")
    op.drop_column("incidents", "closed_by_user_id")
    op.drop_column("incidents", "resolution_category")
    op.drop_column("incidents", "resolved_by_user_id")
    op.drop_column("incidents", "created_by_user_id")
    op.drop_column("incidents", "priority")
    op.drop_column("incidents", "incident_id")

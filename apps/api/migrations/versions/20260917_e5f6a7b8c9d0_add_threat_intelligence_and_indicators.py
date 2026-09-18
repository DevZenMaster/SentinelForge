"""add_threat_intelligence_and_indicators

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-09-17 18:00:00.000000+00:00

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "e5f6a7b8c9d0"
down_revision: str | None = "d4e5f6a7b8c9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Create indicators table
    op.create_table(
        "indicators",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("type", sa.String(length=32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("normalized_value", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="ACTIVE", nullable=False),
        sa.Column("description", sa.String(length=1000), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sightings_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicators")),
        sa.UniqueConstraint("type", "normalized_value", name="uq_indicators_type_normalized_value"),
    )
    op.create_index(
        "ix_indicators_type_normalized_value",
        "indicators",
        ["type", "normalized_value"],
        unique=False,
    )
    op.create_index(
        "ix_indicators_status_last_seen",
        "indicators",
        ["status", "last_seen_at"],
        unique=False,
    )
    op.create_index(op.f("ix_indicators_type"), "indicators", ["type"], unique=False)
    op.create_index(op.f("ix_indicators_status"), "indicators", ["status"], unique=False)
    op.create_index(op.f("ix_indicators_last_seen_at"), "indicators", ["last_seen_at"], unique=False)

    # 2. Create indicator_events table (RESTRICT on event_id for evidence immutability)
    op.create_table(
        "indicator_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "indicator_id",
            sa.UUID(),
            sa.ForeignKey("indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "event_id",
            sa.UUID(),
            sa.ForeignKey("events.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("extracted_from_field", sa.String(length=64), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_indicator_events")),
        sa.UniqueConstraint(
            "indicator_id",
            "event_id",
            "extracted_from_field",
            name="uq_indicator_events_indicator_event_field",
        ),
    )
    op.create_index(
        op.f("ix_indicator_events_indicator_id"),
        "indicator_events",
        ["indicator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_indicator_events_event_id"),
        "indicator_events",
        ["event_id"],
        unique=False,
    )
    op.create_index(
        "ix_indicator_events_event_created",
        "indicator_events",
        ["event_id", "created_at"],
        unique=False,
    )

    # 3. Create threat_intelligence table
    json_compat = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
    op.create_table(
        "threat_intelligence",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column(
            "indicator_id",
            sa.UUID(),
            sa.ForeignKey("indicators.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("threat_classification", sa.String(length=32), server_default="MALICIOUS", nullable=False),
        sa.Column("severity", sa.String(length=16), server_default="HIGH", nullable=False),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("source_reference", sa.String(length=256), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("mitre_tactics", json_compat, nullable=True),
        sa.Column("mitre_techniques", json_compat, nullable=True),
        sa.Column("tags", json_compat, nullable=True),
        sa.Column("threat_actor", sa.String(length=128), nullable=True),
        sa.Column("campaign", sa.String(length=128), nullable=True),
        sa.Column("raw_data", json_compat, nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_threat_intelligence")),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 100",
            name=op.f("ck_threat_intelligence_confidence_range"),
        ),
        sa.UniqueConstraint(
            "indicator_id",
            "source",
            "source_reference",
            name="uq_threat_intelligence_indicator_source_ref",
        ),
    )
    op.create_index(
        op.f("ix_threat_intelligence_indicator_id"),
        "threat_intelligence",
        ["indicator_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intelligence_source"),
        "threat_intelligence",
        ["source"],
        unique=False,
    )
    op.create_index(
        "ix_threat_intelligence_classification_severity",
        "threat_intelligence",
        ["threat_classification", "severity"],
        unique=False,
    )
    op.create_index(
        op.f("ix_threat_intelligence_expires_at"),
        "threat_intelligence",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    # Drop in reverse order
    op.drop_index(op.f("ix_threat_intelligence_expires_at"), table_name="threat_intelligence")
    op.drop_index("ix_threat_intelligence_classification_severity", table_name="threat_intelligence")
    op.drop_index(op.f("ix_threat_intelligence_source"), table_name="threat_intelligence")
    op.drop_index(op.f("ix_threat_intelligence_indicator_id"), table_name="threat_intelligence")
    op.drop_table("threat_intelligence")

    op.drop_index("ix_indicator_events_event_created", table_name="indicator_events")
    op.drop_index(op.f("ix_indicator_events_event_id"), table_name="indicator_events")
    op.drop_index(op.f("ix_indicator_events_indicator_id"), table_name="indicator_events")
    op.drop_table("indicator_events")

    op.drop_index(op.f("ix_indicators_last_seen_at"), table_name="indicators")
    op.drop_index(op.f("ix_indicators_status"), table_name="indicators")
    op.drop_index(op.f("ix_indicators_type"), table_name="indicators")
    op.drop_index("ix_indicators_status_last_seen", table_name="indicators")
    op.drop_index("ix_indicators_type_normalized_value", table_name="indicators")
    op.drop_table("indicators")

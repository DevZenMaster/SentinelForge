"""SQLAlchemy 2.x Declarative Base and Common Mixins.

Defines the declarative root with standard constraint naming conventions,
UUID primary keys, and timezone-aware UTC timestamp tracking.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, MetaData
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# Type that renders as native JSONB in PostgreSQL, and JSON in SQLite (for tests)
JSON_COMPAT = postgresql.JSONB().with_variant(JSON(), "sqlite")


@compiles(UUID, "sqlite")
def _compile_uuid_sqlite(type_: UUID[Any], compiler: object, **kw: object) -> str:
    """Compile PostgreSQL UUID as CHAR(36) in SQLite to guarantee TEXT affinity."""
    return "CHAR(36)"


# Explicit naming convention for constraints to ensure deterministic Alembic migrations
POSTGRES_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_`%(constraint_name)s`",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative root class for all SentinelForge ORM models."""

    metadata = MetaData(naming_convention=POSTGRES_NAMING_CONVENTION)


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(UTC)


class UUIDPrimaryKeyMixin:
    """Mixin providing UUID v4 primary key column."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )


class TimestampMixin:
    """Mixin providing timezone-aware created_at and updated_at timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        nullable=False,
    )

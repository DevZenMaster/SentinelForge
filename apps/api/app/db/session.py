"""Database engine and asynchronous session management using asyncpg."""

import logging
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import QueuePool

from app.core.config import settings

logger = logging.getLogger("sentinelforge.db")

# Create asynchronous engine targeting PostgreSQL with asyncpg driver
engine: AsyncEngine = create_async_engine(
    settings.async_database_url,
    echo=settings.DEBUG,
    pool_pre_ping=settings.DB_POOL_PRE_PING,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE,
)


def get_pool_status() -> dict[str, int | None]:
    """Retrieve connection pool metrics for operational observability."""
    try:
        pool = engine.pool
        if isinstance(pool, QueuePool):
            return {
                "size": pool.size(),
                "checkedin": pool.checkedin(),
                "checkedout": pool.checkedout(),
                "overflow": pool.overflow(),
            }
        return {
            "size": None,
            "checkedin": None,
            "checkedout": None,
            "overflow": None,
        }
    except Exception:
        return {
            "size": None,
            "checkedin": None,
            "checkedout": None,
            "overflow": None,
        }


# Configured session factory for async transaction boundaries
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Dependency yielding an async database session with automated rollback on exception."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as exc:
            await session.rollback()
            logger.error(f"Database session rolled back due to error: {exc}")
            raise
        finally:
            await session.close()


async def check_database_readiness() -> bool:
    """Verify active database connectivity and query execution for readiness health probes."""
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as exc:
        logger.warning(f"Database readiness probe failed: {exc}")
        return False

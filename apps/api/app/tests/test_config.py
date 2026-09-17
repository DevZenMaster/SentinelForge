"""Tests for typed application configuration and fail-closed security invariants."""

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_settings_development_defaults() -> None:
    """Verify safe defaults in development mode."""
    cfg = Settings(ENVIRONMENT="development")
    assert cfg.PROJECT_NAME == "SentinelForge"
    assert cfg.API_V1_STR == "/api/v1"
    assert "postgresql+asyncpg://" in cfg.async_database_url
    assert cfg.AUTH_RATE_LIMIT_PER_MINUTE == 10
    assert cfg.EVENTS_RATE_LIMIT_PER_MINUTE == 1000


def test_settings_production_fail_closed_insecure_secret() -> None:
    """Production must reject default dev secret keys."""
    with pytest.raises(ValidationError, match="SECRET_KEY must be a cryptographically secure"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="dev-insecure-secret-key-must-be-changed-in-production-0987654321",
            POSTGRES_PASSWORD="a-very-strong-production-database-password-12345",
        )


def test_settings_production_fail_closed_wildcard_cors() -> None:
    """Production must reject wildcard '*' CORS origins."""
    with pytest.raises(ValidationError, match="Wildcard CORS origin"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="this-is-a-valid-production-secret-key-exceeding-32-bytes-length",
            POSTGRES_PASSWORD="a-very-strong-production-database-password-12345",
            BACKEND_CORS_ORIGINS=["*"],
        )


def test_settings_production_fail_closed_default_db_password() -> None:
    """Production must reject default database password."""
    with pytest.raises(ValidationError, match="Default database password detected"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="this-is-a-valid-production-secret-key-exceeding-32-bytes-length",
            POSTGRES_PASSWORD="sentinel_dev_password_change_me",
        )


def test_settings_database_url_normalization() -> None:
    """Custom DATABASE_URL with postgresql:// must be normalized to postgresql+asyncpg://."""
    cfg = Settings(
        DATABASE_URL="postgresql://user:pass@dbhost:5432/custom_db",
        ENVIRONMENT="development",
    )
    assert cfg.async_database_url == "postgresql+asyncpg://user:pass@dbhost:5432/custom_db"

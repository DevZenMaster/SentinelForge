"""SentinelForge Core Application Configuration.

Uses Pydantic Settings for strongly typed configuration loading from environment variables.
Enforces fail-closed security guarantees in production environments.
"""

from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, computed_field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _parse_cors_origins(v: object) -> list[str]:
    """Parse CORS origins from JSON list or comma-separated string."""
    if isinstance(v, str):
        if v.startswith("[") and v.endswith("]"):
            import json

            try:
                parsed = json.loads(v)
                if isinstance(parsed, list):
                    return [str(item).strip() for item in parsed if item]
            except json.JSONDecodeError:
                pass
        return [origin.strip() for origin in v.split(",") if origin.strip()]
    if isinstance(v, (list, tuple, set)):
        return [str(origin).strip() for origin in v if origin]
    return []


class Settings(BaseSettings):
    """Application settings schema."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # Application Metadata
    APP_VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = False
    PROJECT_NAME: str = "SentinelForge"
    API_V1_STR: str = "/api/v1"

    # Cryptographic & Security Keys
    SECRET_KEY: str = Field(
        default="dev-insecure-secret-key-must-be-changed-in-production-0987654321",
        description=(
            "Master secret key used for signing session identifiers or cryptographic materials."
        ),
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, ge=1, le=10080)
    ALGORITHM: str = "HS256"

    # PostgreSQL Database Settings & Connection Pool
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "sentinelforge"
    POSTGRES_PASSWORD: str = "sentinel_dev_password_change_me"  # noqa: S105
    POSTGRES_DB: str = "sentinelforge_db"
    DATABASE_URL: str | None = None
    DB_POOL_SIZE: int = Field(default=20, ge=1, le=100)
    DB_MAX_OVERFLOW: int = Field(default=10, ge=0, le=100)
    DB_POOL_TIMEOUT: float = Field(default=30.0, ge=1.0, le=120.0)
    DB_POOL_RECYCLE: int = Field(default=1800, ge=60, le=7200)
    DB_POOL_PRE_PING: bool = True

    # Reverse Proxy & Edge Security
    TRUSTED_PROXIES: list[str] = ["127.0.0.1", "::1"]

    # CORS Settings
    BACKEND_CORS_ORIGINS: Annotated[list[str], BeforeValidator(_parse_cors_origins)] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Rate Limiting & Ingestion Constraints
    AUTH_RATE_LIMIT_PER_MINUTE: int = 10
    EVENTS_RATE_LIMIT_PER_MINUTE: int = 1000
    MAX_EVENT_PAYLOAD_BYTES: int = Field(default=1048576, ge=1024, le=10485760)

    # Session Cookie & CSRF Security Settings
    SESSION_COOKIE_NAME: str = "sentinelforge_session"
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    SESSION_EXPIRE_HOURS: int = Field(default=12, ge=1, le=168)
    CSRF_PROTECTION_ENABLED: bool = True

    # Notification & Integration Settings (Phase 13)
    NOTIFICATIONS_ENABLED: bool = True
    WEBHOOK_TIMEOUT_SECONDS: float = Field(default=10.0, ge=1.0, le=60.0)
    WEBHOOK_CONNECT_TIMEOUT_SECONDS: float = Field(default=5.0, ge=0.5, le=30.0)
    WEBHOOK_MAX_PAYLOAD_BYTES: int = Field(default=65536, ge=1024, le=1048576)
    WEBHOOK_MAX_RESPONSE_BYTES: int = Field(default=16384, ge=512, le=262144)
    WEBHOOK_ALLOW_INSECURE_HTTP: bool = False
    NOTIFICATION_MAX_RETRIES: int = Field(default=3, ge=1, le=10)
    NOTIFICATION_MAX_DESTINATIONS_PER_POLICY: int = Field(default=10, ge=1, le=50)
    NOTIFICATION_BASE_BACKOFF_SECONDS: int = Field(default=5, ge=1, le=60)
    NOTIFICATION_MAX_BACKOFF_SECONDS: int = Field(default=300, ge=10, le=3600)
    SMTP_HOST: str | None = None
    SMTP_PORT: int = Field(default=587, ge=1, le=65535)
    SMTP_USER: str | None = None
    SMTP_PASSWORD: str | None = None
    SMTP_FROM_EMAIL: str = "notifications@sentinelforge.local"
    SMTP_USE_TLS: bool = True

    @computed_field  # type: ignore[prop-decorator]
    @property
    def async_database_url(self) -> str:
        """Construct asyncpg connection URL if DATABASE_URL is not explicitly specified."""
        if self.DATABASE_URL:
            # Normalize driver prefix to postgresql+asyncpg
            if self.DATABASE_URL.startswith("postgresql://"):
                return self.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        """Enforce fail-closed security invariants in production environments."""
        return self._check_production_security()

    def _check_production_security(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            if self.DEBUG:
                raise ValueError(
                    "CRITICAL: DEBUG mode must be disabled (False) in production environment."
                )

            insecure_keys = {
                "dev-insecure-secret-key-must-be-changed-in-production-0987654321",
                "change-this-to-a-secure-random-secret-key-in-production",
                "secret",
                "password",
            }
            if self.SECRET_KEY in insecure_keys or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "CRITICAL: In production environment, SECRET_KEY must be a cryptographically "
                    "secure random string of at least 32 characters."
                )

            if "*" in self.BACKEND_CORS_ORIGINS:
                raise ValueError(
                    "CRITICAL: Wildcard CORS origin ('*') is strictly forbidden in production."
                )

            if not self.POSTGRES_PASSWORD or self.POSTGRES_PASSWORD in {
                "sentinel_dev_password_change_me",
                "postgres",
                "password",
                "",
            }:
                raise ValueError(
                    "CRITICAL: Default database password detected in production configuration."
                )

            if not self.POSTGRES_USER or not self.POSTGRES_DB:
                raise ValueError(
                    "CRITICAL: Database user and database name must be "
                    "explicitly configured in production."
                )

            if not self.SESSION_COOKIE_SECURE:
                raise ValueError(
                    "CRITICAL: In production environment, SESSION_COOKIE_SECURE must be True."
                )

            if not self.SESSION_COOKIE_HTTPONLY:
                raise ValueError(
                    "CRITICAL: In production environment, SESSION_COOKIE_HTTPONLY must be True."
                )

            if self.WEBHOOK_ALLOW_INSECURE_HTTP:
                raise ValueError(
                    "CRITICAL: In production environment, "
                    "WEBHOOK_ALLOW_INSECURE_HTTP must be False."
                )

        # In all environments, disallow wildcard origin with credentials
        if "*" in self.BACKEND_CORS_ORIGINS and len(self.BACKEND_CORS_ORIGINS) > 1:
            raise ValueError(
                "CORS configuration cannot combine wildcard '*' with explicit origins."
            )

        return self


def validate_startup_configuration(cfg: Settings | None = None) -> None:
    """Explicit startup validator executed during application lifespan.

    Fails fast with detailed, actionable diagnostics if production configuration invariants
    are violated.
    """
    conf = cfg or settings
    if conf.ENVIRONMENT == "production":
        conf._check_production_security()


# Global singleton settings instance
settings = Settings()

"""Health check schemas."""

from pydantic import BaseModel, Field


class ServiceHealth(BaseModel):
    """Health status details."""

    status: str = Field(..., description="Overall service status (healthy, degraded)")
    version: str = Field(..., description="API build version")
    environment: str = Field(..., description="Deployment environment mode")
    database: str = Field(
        ..., description="Database connectivity state (ready, degraded, unreachable)"
    )

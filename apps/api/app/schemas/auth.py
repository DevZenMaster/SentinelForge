"""Pydantic Schemas for Authentication and User Identity."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    """Credentials payload for authentication."""

    username_or_email: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Username or Email address of the account",
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Account password",
    )


class UserResponse(BaseModel):
    """Sanitized user profile and authorization capabilities."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID = Field(..., description="User unique identifier")
    username: str = Field(..., description="System username")
    email: str = Field(..., max_length=255, description="User email address")
    full_name: str | None = Field(default=None, description="Full display name")
    is_active: bool = Field(..., description="Account active status")
    is_superuser: bool = Field(..., description="Global superuser flag")
    roles: list[str] = Field(default_factory=list, description="Assigned role names")
    permissions: list[str] = Field(
        default_factory=list, description="Derived granular action permissions"
    )
    created_at: datetime
    updated_at: datetime


class LogoutResponse(BaseModel):
    """Confirmation payload for session termination."""

    status: str = Field(default="logged_out", description="Session state")
    message: str = Field(default="Session successfully invalidated")

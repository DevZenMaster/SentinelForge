"""User Schemas for Operational Identity Directory and Administration (Phase 15)."""

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

USERNAME_REGEX = r"^[a-zA-Z0-9_\-\.]{3,64}$"
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
USERNAME_ERROR_MSG = (
    "Username must be 3-64 characters and contain only letters, "
    "numbers, underscores, dashes, or periods."
)


class UserListItemResponse(BaseModel):
    """Sanitized user profile for assignment and attribution."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    full_name: str | None = None
    is_active: bool
    roles: list[str] = []
    created_at: datetime | None = None
    last_login_at: datetime | None = None


class UserListResponse(BaseModel):
    """Collection of user accounts."""

    items: list[UserListItemResponse]
    total: int


class RoleListItemResponse(BaseModel):
    """System role definition."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None = None


class RoleListResponse(BaseModel):
    """Collection of system roles."""

    items: list[RoleListItemResponse]
    total: int


class UserDetailResponse(BaseModel):
    """Full operational profile for user management and settings."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str
    email: str
    full_name: str | None = None
    is_active: bool
    is_superuser: bool = False
    roles: list[str] = []
    permissions: list[str] = []
    created_at: datetime
    updated_at: datetime
    last_login_at: datetime | None = None


class UserProfileUpdateRequest(BaseModel):
    """Self-service profile update payload."""

    full_name: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, min_length=3, max_length=64)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if not re.match(USERNAME_REGEX, v):
                raise ValueError(USERNAME_ERROR_MSG)
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            return v if v else None
        return None


class PasswordChangeRequest(BaseModel):
    """Self-service password update payload."""

    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=12, max_length=128)
    confirm_password: str = Field(..., min_length=12, max_length=128)

    @model_validator(mode="after")
    def verify_passwords_match(self) -> "PasswordChangeRequest":
        if self.new_password != self.confirm_password:
            raise ValueError("New password and confirmation password do not match.")
        return self


class UserCreateRequest(BaseModel):
    """Administrator user creation payload."""

    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., max_length=255)
    full_name: str | None = Field(default=None, max_length=128)
    password: str = Field(..., min_length=12, max_length=128)
    roles: list[str] = Field(default_factory=list)
    is_active: bool = True

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not re.match(USERNAME_REGEX, v):
            raise ValueError(USERNAME_ERROR_MSG)
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.match(EMAIL_REGEX, v):
            raise ValueError("Invalid email address format.")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            return v if v else None
        return None


class UserAdminUpdateRequest(BaseModel):
    """Administrator user update payload."""

    username: str | None = Field(default=None, min_length=3, max_length=64)
    email: str | None = Field(default=None, max_length=255)
    full_name: str | None = Field(default=None, max_length=128)
    roles: list[str] | None = None
    is_active: bool | None = None

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if not re.match(USERNAME_REGEX, v):
                raise ValueError(USERNAME_ERROR_MSG)
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip().lower()
            if not re.match(EMAIL_REGEX, v):
                raise ValueError("Invalid email address format.")
            return v
        return None

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            return v if v else None
        return None


class UserStatusUpdateRequest(BaseModel):
    """Administrator user status toggle payload."""

    is_active: bool

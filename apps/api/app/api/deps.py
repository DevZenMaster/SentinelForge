"""Authentication and Authorization FastAPI Dependency Guards.

Enforces server-side authentication from secure HttpOnly cookies, resolves
server-side roles and permissions from PostgreSQL, and guards protected endpoints.
Never trusts client-supplied role or identity claims.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models import Session, User
from app.services.auth import get_active_session, resolve_user_capabilities

logger = logging.getLogger("sentinelforge.deps")


async def get_current_session_and_user(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> tuple[Session, User]:
    """Extract and validate server-managed session credential from cookie or Authorization header.

    Raises HTTP 401 Unauthorized if missing, expired, revoked, or invalid.
    """
    # 1. Primary authentication credential: secure HttpOnly session cookie
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)

    # 2. Fallback credential for automated scripts or API clients: Bearer token header
    if not raw_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()

    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    session_data = await get_active_session(db, raw_token)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, revoked, or expired session. Please log in again.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    session, user = session_data

    # Bind authenticated user ID into request state for correlation in logging and audit trails
    request.state.user_id = str(user.id)

    return session, user


async def get_current_user(
    session_user: Annotated[tuple[Session, User], Depends(get_current_session_and_user)],
) -> User:
    """Dependency returning the validated active User."""
    return session_user[1]


async def get_current_user_context(
    user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> tuple[User, list[str], list[str]]:
    """Dependency returning authenticated user along with their resolved roles and permissions."""
    roles, permissions = await resolve_user_capabilities(db, user.id)
    return user, roles, permissions


def require_permission(permission: str) -> Callable[..., Awaitable[User]]:
    """Dependency factory enforcing that authenticated user possesses a granular permission."""

    async def permission_dependency(
        context: Annotated[tuple[User, list[str], list[str]], Depends(get_current_user_context)],
    ) -> User:
        user, _roles, permissions = context

        # Superusers bypass granular permission checks
        if user.is_superuser or permission in permissions:
            return user

        logger.warning(
            f"Access denied for user {user.id} ({user.username}): missing '{permission}'",
            extra={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: You do not possess the required permission '{permission}'.",
        )

    return permission_dependency


def require_any_permission(*required_permissions: str) -> Callable[..., Awaitable[User]]:
    """Dependency factory enforcing that user possesses at least one permission."""

    async def permission_dependency(
        context: Annotated[tuple[User, list[str], list[str]], Depends(get_current_user_context)],
    ) -> User:
        user, _roles, permissions = context

        if user.is_superuser or any(p in permissions for p in required_permissions):
            return user

        logger.warning(
            f"Access denied for user {user.id} ({user.username}): missing {required_permissions}",
            extra={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Forbidden: You do not possess any of the required permissions: "
                f"{list(required_permissions)}."
            ),
        )

    return permission_dependency


def require_role(role_name: str) -> Callable[..., Awaitable[User]]:
    """Dependency factory enforcing that the authenticated user holds a specific role."""

    async def role_dependency(
        context: Annotated[tuple[User, list[str], list[str]], Depends(get_current_user_context)],
    ) -> User:
        user, roles, _permissions = context

        if user.is_superuser or role_name in roles:
            return user

        logger.warning(
            f"Access denied for user {user.id} ({user.username}): missing role '{role_name}'",
            extra={"user_id": str(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Action requires role '{role_name}'.",
        )

    return role_dependency

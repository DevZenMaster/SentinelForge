"""Authentication and Session Management Business Logic.

Manages credential verification with timing attack mitigations, opaque session token
issuance, SHA-256 token hashing, session revocation, and authorization resolution.
Never logs credentials or persists unhashed session tokens.
"""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import (
    generate_session_token,
    get_password_hash,
    hash_session_token,
    verify_password,
)
from app.models import AuditLog, Permission, Role, RolePermission, Session, User, UserRole

logger = logging.getLogger("sentinelforge.auth")

# Pre-computed dummy hash to run constant-time verification when user does not exist
_DUMMY_HASH = get_password_hash("dummy_timing_protection_value_0123456789")


async def authenticate_credentials(
    db: AsyncSession, username_or_email: str, password: str
) -> User | None:
    """Verify user credentials against database records with timing-attack equalization.

    Returns User instance if credentials and account are active, otherwise None.
    """
    clean_identifier = username_or_email.strip().lower()

    stmt = select(User).where(
        or_(
            User.username == clean_identifier,
            User.email == clean_identifier,
        )
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        # Perform constant-time verification against dummy hash to defeat account enumeration
        verify_password(password, _DUMMY_HASH)
        return None

    # Check account active state
    if not user.is_active:
        # Run dummy check to keep response time consistent
        verify_password(password, _DUMMY_HASH)
        logger.warning(
            f"Authentication failed: account deactivated for user {user.id}",
            extra={"user_id": str(user.id)},
        )
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


async def create_session(
    db: AsyncSession,
    user: User,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> tuple[Session, str]:
    """Create a new server-side session and return the record alongside the raw opaque token.

    The database stores strictly the SHA-256 hash of the token.
    """
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)

    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=settings.SESSION_EXPIRE_HOURS)

    session = Session(
        session_token_hash=token_hash,
        user_id=user.id,
        created_at=now,
        expires_at=expires_at,
        last_used_at=now,
        ip_address=client_ip,
        user_agent=user_agent[:512] if user_agent else None,
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)

    return session, raw_token


async def get_active_session(db: AsyncSession, raw_token: str) -> tuple[Session, User] | None:
    """Validate raw session token from cookie, return active session and associated user."""
    if not raw_token or len(raw_token) < 16:
        return None

    token_hash = hash_session_token(raw_token)
    now = datetime.now(UTC)

    stmt = (
        select(Session, User)
        .join(User, Session.user_id == User.id)
        .where(Session.session_token_hash == token_hash)
    )
    result = await db.execute(stmt)
    row = result.first()

    if not row:
        return None

    session, user = row

    # Check revocation
    if session.revoked_at is not None:
        return None

    # Check expiration (normalize tzinfo for cross-database UTC compatibility)
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at <= now:
        session.revoked_at = now
        await db.commit()
        return None

    # Check user active state
    if not user.is_active:
        return None

    # Update last_used_at timestamp
    session.last_used_at = now
    await db.commit()

    return session, user


async def revoke_session(db: AsyncSession, raw_token: str) -> tuple[bool, uuid.UUID | None]:
    """Invalidate session server-side by marking revoked_at timestamp.

    Safe and idempotent. Returns (True, user_id) if active session was revoked,
    or (False, None) otherwise.
    """
    if not raw_token:
        return False, None

    token_hash = hash_session_token(raw_token)
    stmt = select(Session).where(Session.session_token_hash == token_hash)
    result = await db.execute(stmt)
    session = result.scalar_one_or_none()

    if not session or session.revoked_at is not None:
        return False, None

    session.revoked_at = datetime.now(UTC)
    user_id = session.user_id
    await db.commit()
    return True, user_id


async def revoke_all_user_sessions(
    db: AsyncSession,
    user_id: uuid.UUID,
    except_token_hash: str | None = None,
) -> int:
    """Invalidate all active sessions for a user, optionally preserving a specific session.

    Used during password change (preserving current session) or account deactivation/deletion
    (revoking all sessions).
    """
    now = datetime.now(UTC)
    stmt = select(Session).where(
        Session.user_id == user_id,
        Session.revoked_at.is_(None),
    )
    if except_token_hash:
        stmt = stmt.where(Session.session_token_hash != except_token_hash)

    result = await db.execute(stmt)
    active_sessions = result.scalars().all()

    for s in active_sessions:
        s.revoked_at = now

    await db.commit()
    return len(active_sessions)


async def resolve_user_capabilities(
    db: AsyncSession, user_id: uuid.UUID
) -> tuple[list[str], list[str]]:
    """Resolve all active role names and associated granular permission names for a user."""
    # Query roles
    role_stmt = (
        select(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .where(UserRole.user_id == user_id)
    )
    role_results = (await db.execute(role_stmt)).scalars().all()
    roles = sorted(list(set(role_results)))

    # Query permissions through role_permissions
    perm_stmt = (
        select(Permission.name)
        .join(RolePermission, Permission.id == RolePermission.permission_id)
        .join(UserRole, RolePermission.role_id == UserRole.role_id)
        .where(UserRole.user_id == user_id)
    )
    perm_results = (await db.execute(perm_stmt)).scalars().all()
    permissions = sorted(list(set(perm_results)))

    return roles, permissions


async def record_audit_log(
    db: AsyncSession,
    action: str,
    actor_user_id: uuid.UUID | None,
    resource_type: str,
    resource_id: str,
    request_id: str | None = None,
    source_ip: str | None = None,
    user_agent: str | None = None,
    old_value: dict[str, Any] | None = None,
    new_value: dict[str, Any] | None = None,
) -> AuditLog:
    """Record an append-only security audit log entry.

    Ensures no passwords, session tokens, or raw credentials ever enter audit storage.
    """
    audit_entry = AuditLog(
        action=action,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        resource_id=resource_id,
        old_value=old_value,
        new_value=new_value,
        source_ip=source_ip,
        user_agent=user_agent[:512] if user_agent else None,
        request_id=request_id,
        timestamp=datetime.now(UTC),
    )
    db.add(audit_entry)
    await db.commit()
    await db.refresh(audit_entry)
    return audit_entry

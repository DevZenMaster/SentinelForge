"""Operational User Management and Account Service (Phase 15).

Implements business logic for:
- Self-service profile updates and password changes
- Administrative user lifecycle management (CRUD, activation/deactivation)
- Server-side last-administrator lockout protection
- Forensic integrity preservation (blocking deletion of users with notes)
- Complete, non-repudiable audit logging for all mutations
"""

import logging
import uuid
from datetime import datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import distinct, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.rbac import ROLE_ADMIN
from app.core.security import get_password_hash, verify_password
from app.models.alert import AlertNote
from app.models.auth import Role, Session, User, UserRole
from app.models.incident import IncidentNote
from app.schemas.user import (
    PasswordChangeRequest,
    UserAdminUpdateRequest,
    UserCreateRequest,
    UserProfileUpdateRequest,
)
from app.services.auth import (
    record_audit_log,
    resolve_user_capabilities,
    revoke_all_user_sessions,
)

logger = logging.getLogger("sentinelforge.services.user")


async def count_active_administrators(db: AsyncSession) -> int:
    """Return the authoritative count of currently active administrators.

    An active administrator is an active user who is either a superuser or assigned
    the system ROLE_ADMIN.
    """
    stmt = (
        select(func.count(distinct(User.id)))
        .select_from(User)
        .outerjoin(UserRole, User.id == UserRole.user_id)
        .outerjoin(Role, UserRole.role_id == Role.id)
        .where(
            User.is_active.is_(True),
            or_(User.is_superuser.is_(True), Role.name == ROLE_ADMIN),
        )
    )
    result = await db.execute(stmt)
    return result.scalar() or 0


async def is_user_active_admin(db: AsyncSession, user: User) -> bool:
    """Determine whether a specific user is currently an active administrator."""
    if not user.is_active:
        return False
    if user.is_superuser:
        return True
    roles, _ = await resolve_user_capabilities(db, user.id)
    return ROLE_ADMIN in roles


async def get_user_detail(
    db: AsyncSession, user_id: uuid.UUID
) -> tuple[User, list[str], list[str], datetime | None] | None:
    """Retrieve user with loaded roles, resolved permissions, and last login timestamp."""
    stmt = (
        select(User)
        .options(selectinload(User.roles))
        .where(User.id == user_id)
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        return None

    roles, permissions = await resolve_user_capabilities(db, user.id)

    # Resolve last active login from sessions table
    stmt_last_login = select(func.max(Session.created_at)).where(Session.user_id == user.id)
    result_last_login = await db.execute(stmt_last_login)
    last_login_at = result_last_login.scalar_one_or_none()

    return user, roles, permissions, last_login_at


async def update_self_profile(
    db: AsyncSession,
    user: User,
    payload: UserProfileUpdateRequest,
    request_meta: dict[str, Any],
) -> tuple[User, list[str], list[str], datetime | None]:
    """Update display name and/or username for the authenticated user."""
    old_value = {
        "full_name": user.full_name,
        "username": user.username,
    }

    if payload.username and payload.username.lower() != user.username.lower():
        # Check username uniqueness across existing accounts
        stmt = select(User).where(
            func.lower(User.username) == payload.username.lower(),
            User.id != user.id,
        )
        existing = (await db.execute(stmt)).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{payload.username}' is already taken.",
            )
        user.username = payload.username

    if payload.full_name is not None:
        user.full_name = payload.full_name

    new_value = {
        "full_name": user.full_name,
        "username": user.username,
    }

    await db.commit()
    await db.refresh(user)

    await record_audit_log(
        db=db,
        action="USER_PROFILE_UPDATED",
        actor_user_id=user.id,
        resource_type="user",
        resource_id=str(user.id),
        old_value=old_value,
        new_value=new_value,
        source_ip=request_meta.get("source_ip"),
        user_agent=request_meta.get("user_agent"),
        request_id=request_meta.get("request_id"),
    )

    detail = await get_user_detail(db, user.id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve updated profile.",
        )
    return detail


async def change_self_password(
    db: AsyncSession,
    user: User,
    payload: PasswordChangeRequest,
    current_session_token_hash: str | None,
    request_meta: dict[str, Any],
) -> bool:
    """Verify current password, hash new password with Argon2id, and revoke other sessions."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect.",
        )

    if verify_password(payload.new_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be identical to your current password.",
        )

    user.hashed_password = get_password_hash(payload.new_password)
    await db.commit()

    # Invalidate all OTHER sessions for this user, preserving active session
    revoked_count = await revoke_all_user_sessions(
        db, user_id=user.id, except_token_hash=current_session_token_hash
    )
    logger.info(
        f"Password updated for {user.username} ({user.id}); {revoked_count} sessions revoked."
    )

    await record_audit_log(
        db=db,
        action="USER_PASSWORD_CHANGED",
        actor_user_id=user.id,
        resource_type="user",
        resource_id=str(user.id),
        old_value={"sessions_revoked": revoked_count},
        new_value={"status": "password_updated"},
        source_ip=request_meta.get("source_ip"),
        user_agent=request_meta.get("user_agent"),
        request_id=request_meta.get("request_id"),
    )

    return True


async def list_available_roles(db: AsyncSession) -> list[Role]:
    """List all available system roles."""
    stmt = select(Role).order_by(Role.name.asc())
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def list_admin_users(
    db: AsyncSession,
    search: str | None = None,
    role: str | None = None,
    is_active: bool | None = None,
) -> list[dict[str, Any]]:
    """Retrieve users matching criteria with loaded roles and last login telemetry."""
    stmt = select(User).options(selectinload(User.roles)).order_by(User.created_at.desc())

    if is_active is not None:
        stmt = stmt.where(User.is_active == is_active)

    if search:
        search_pattern = f"%{search.strip().lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(User.username).like(search_pattern),
                func.lower(User.email).like(search_pattern),
                func.lower(User.full_name).like(search_pattern),
            )
        )

    result = await db.execute(stmt)
    users = result.scalars().all()

    # Query last login timestamps for all retrieved users in batch
    user_ids = [u.id for u in users]
    last_login_map: dict[uuid.UUID, datetime] = {}
    if user_ids:
        login_stmt = (
            select(Session.user_id, func.max(Session.created_at))
            .where(Session.user_id.in_(user_ids))
            .group_by(Session.user_id)
        )
        login_results = await db.execute(login_stmt)
        for uid, last_login in login_results.all():
            last_login_map[uid] = last_login

    items: list[dict[str, Any]] = []
    for u in users:
        role_names = [r.name for r in u.roles]
        if role and role.upper() not in [r.upper() for r in role_names]:
            continue

        items.append(
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "is_active": u.is_active,
                "is_superuser": u.is_superuser,
                "roles": role_names,
                "created_at": u.created_at,
                "last_login_at": last_login_map.get(u.id),
            }
        )

    return items


async def create_admin_user(
    db: AsyncSession,
    actor: User,
    payload: UserCreateRequest,
    request_meta: dict[str, Any],
) -> tuple[User, list[str], list[str], datetime | None]:
    """Create a new user account with assigned roles and emit an audit log."""
    # Check username uniqueness
    stmt = select(User).where(func.lower(User.username) == payload.username.lower())
    if (await db.execute(stmt)).scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{payload.username}' is already in use.",
        )

    # Check email uniqueness
    stmt_email = select(User).where(func.lower(User.email) == str(payload.email).lower())
    if (await db.execute(stmt_email)).scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Email '{payload.email}' is already in use.",
        )

    # Validate roles if specified
    assigned_roles: list[Role] = []
    if payload.roles:
        stmt_roles = select(Role).where(Role.name.in_(payload.roles))
        assigned_roles = list((await db.execute(stmt_roles)).scalars().all())
        found_names = {r.name for r in assigned_roles}
        missing = set(payload.roles) - found_names
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown role(s): {', '.join(missing)}.",
            )

    hashed_pw = get_password_hash(payload.password)
    new_user = User(
        username=payload.username,
        email=str(payload.email).lower(),
        hashed_password=hashed_pw,
        full_name=payload.full_name,
        is_active=payload.is_active,
        is_superuser=False,
    )
    db.add(new_user)
    await db.flush()  # Flush to generate new_user.id

    for r in assigned_roles:
        user_role = UserRole(user_id=new_user.id, role_id=r.id)
        db.add(user_role)

    await db.commit()
    await db.refresh(new_user)

    await record_audit_log(
        db=db,
        action="USER_CREATED",
        actor_user_id=actor.id,
        resource_type="user",
        resource_id=str(new_user.id),
        old_value=None,
        new_value={
            "username": new_user.username,
            "email": new_user.email,
            "full_name": new_user.full_name,
            "is_active": new_user.is_active,
            "roles": [r.name for r in assigned_roles],
        },
        source_ip=request_meta.get("source_ip"),
        user_agent=request_meta.get("user_agent"),
        request_id=request_meta.get("request_id"),
    )

    detail = await get_user_detail(db, new_user.id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve created user profile.",
        )
    return detail


async def update_admin_user(
    db: AsyncSession,
    actor: User,
    target_user_id: uuid.UUID,
    payload: UserAdminUpdateRequest,
    request_meta: dict[str, Any],
) -> tuple[User, list[str], list[str], datetime | None]:
    """Update attributes and roles of a user account under administrative control."""
    stmt = (
        select(User)
        .options(selectinload(User.roles))
        .where(User.id == target_user_id)
    )
    target_user = (await db.execute(stmt)).scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {target_user_id} was not found.",
        )

    old_roles = [r.name for r in target_user.roles]
    old_value = {
        "username": target_user.username,
        "email": target_user.email,
        "full_name": target_user.full_name,
        "is_active": target_user.is_active,
        "roles": old_roles,
    }

    # Check username uniqueness if changed
    if payload.username and payload.username.lower() != target_user.username.lower():
        stmt_u = select(User).where(
            func.lower(User.username) == payload.username.lower(),
            User.id != target_user.id,
        )
        if (await db.execute(stmt_u)).scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{payload.username}' is already in use.",
            )
        target_user.username = payload.username

    # Check email uniqueness if changed
    if payload.email and str(payload.email).lower() != target_user.email.lower():
        stmt_e = select(User).where(
            func.lower(User.email) == str(payload.email).lower(),
            User.id != target_user.id,
        )
        if (await db.execute(stmt_e)).scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email '{payload.email}' is already in use.",
            )
        target_user.email = str(payload.email).lower()

    if payload.full_name is not None:
        target_user.full_name = payload.full_name

    # Check Last Administrator Protection for deactivation or role demotion
    is_target_admin = await is_user_active_admin(db, target_user)

    if is_target_admin:
        is_being_deactivated = payload.is_active is False
        is_losing_admin_role = (
            payload.roles is not None
            and ROLE_ADMIN not in [r.upper() for r in payload.roles]
            and not target_user.is_superuser
        )

        if is_being_deactivated or is_losing_admin_role:
            active_admin_count = await count_active_administrators(db)
            if active_admin_count <= 1:
                action_desc = "deactivate" if is_being_deactivated else "demote"
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Cannot {action_desc} the last active administrator account. "
                        "Ensure another active administrator exists before performing this action."
                    ),
                )

    if payload.is_active is not None:
        target_user.is_active = payload.is_active
        if not payload.is_active:
            # If account is deactivated, immediately revoke all active sessions
            revoked = await revoke_all_user_sessions(db, target_user.id)
            logger.info(
                f"Account deactivated for {target_user.username}; {revoked} sessions revoked."
            )

    # Update role assignments if provided
    new_roles_list = old_roles
    if payload.roles is not None:
        stmt_roles = select(Role).where(Role.name.in_(payload.roles))
        new_role_objs = list((await db.execute(stmt_roles)).scalars().all())
        found_names = {r.name for r in new_role_objs}
        missing = set(payload.roles) - found_names
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown role(s): {', '.join(missing)}.",
            )

        # Clear existing UserRole records
        stmt_del = select(UserRole).where(UserRole.user_id == target_user.id)
        existing_urs = (await db.execute(stmt_del)).scalars().all()
        for ur in existing_urs:
            await db.delete(ur)

        # Add new UserRole associations
        for ro in new_role_objs:
            db.add(UserRole(user_id=target_user.id, role_id=ro.id))

        new_roles_list = [r.name for r in new_role_objs]

    await db.commit()
    await db.refresh(target_user)

    new_value = {
        "username": target_user.username,
        "email": target_user.email,
        "full_name": target_user.full_name,
        "is_active": target_user.is_active,
        "roles": new_roles_list,
    }

    await record_audit_log(
        db=db,
        action="USER_UPDATED",
        actor_user_id=actor.id,
        resource_type="user",
        resource_id=str(target_user.id),
        old_value=old_value,
        new_value=new_value,
        source_ip=request_meta.get("source_ip"),
        user_agent=request_meta.get("user_agent"),
        request_id=request_meta.get("request_id"),
    )

    detail = await get_user_detail(db, target_user.id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve updated user profile.",
        )
    return detail


async def set_user_status(
    db: AsyncSession,
    actor: User,
    target_user_id: uuid.UUID,
    is_active: bool,
    request_meta: dict[str, Any],
) -> tuple[User, list[str], list[str], datetime | None]:
    """Activate or deactivate a user account with session revocation on deactivation."""
    stmt = (
        select(User)
        .options(selectinload(User.roles))
        .where(User.id == target_user_id)
    )
    target_user = (await db.execute(stmt)).scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {target_user_id} was not found.",
        )

    if not is_active and target_user.is_active:
        # Check last active administrator protection
        if await is_user_active_admin(db, target_user):
            active_admin_count = await count_active_administrators(db)
            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Cannot deactivate the last active administrator account. "
                        "Ensure another active administrator exists before deactivating this user."
                    ),
                )

    old_status = target_user.is_active
    target_user.is_active = is_active

    revoked = 0
    if not is_active:
        revoked = await revoke_all_user_sessions(db, target_user.id)
        logger.info(
            f"Account deactivated for {target_user.username}; {revoked} active sessions revoked."
        )

    await db.commit()
    await db.refresh(target_user)

    await record_audit_log(
        db=db,
        action="USER_STATUS_CHANGED",
        actor_user_id=actor.id,
        resource_type="user",
        resource_id=str(target_user.id),
        old_value={"is_active": old_status},
        new_value={"is_active": is_active, "sessions_revoked": revoked},
        source_ip=request_meta.get("source_ip"),
        user_agent=request_meta.get("user_agent"),
        request_id=request_meta.get("request_id"),
    )

    detail = await get_user_detail(db, target_user.id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve modified user profile.",
        )
    return detail


async def delete_admin_user(
    db: AsyncSession,
    actor: User,
    target_user_id: uuid.UUID,
    request_meta: dict[str, Any],
) -> bool:
    """Safely delete a user account, enforcing last-admin protection and forensic integrity."""
    stmt = (
        select(User)
        .options(selectinload(User.roles))
        .where(User.id == target_user_id)
    )
    target_user = (await db.execute(stmt)).scalar_one_or_none()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {target_user_id} was not found.",
        )

    # Prevent self-deletion
    if target_user.id == actor.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Administrators cannot delete their own account. "
                "Please request another administrator to perform this action."
            ),
        )

    # Enforce Last Administrator Protection
    if await is_user_active_admin(db, target_user):
        active_admin_count = await count_active_administrators(db)
        if active_admin_count <= 1:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete the last active administrator account.",
            )

    # Forensic integrity check: Alert notes
    stmt_alert_notes = select(func.count(AlertNote.id)).where(
        AlertNote.author_user_id == target_user_id
    )
    alert_notes_count = (await db.execute(stmt_alert_notes)).scalar() or 0

    # Forensic integrity check: Incident notes
    stmt_incident_notes = select(func.count(IncidentNote.id)).where(
        IncidentNote.author_user_id == target_user_id
    )
    incident_notes_count = (await db.execute(stmt_incident_notes)).scalar() or 0

    if alert_notes_count > 0 or incident_notes_count > 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"User cannot be deleted because they have authored "
                f"{alert_notes_count} alert note(s) and {incident_notes_count} incident note(s) "
                "that are preserved for forensic integrity. Please deactivate the account instead."
            ),
        )

    # Revoke all sessions prior to deletion
    await revoke_all_user_sessions(db, target_user.id)

    deleted_username = target_user.username
    deleted_email = target_user.email
    deleted_roles = [r.name for r in target_user.roles]

    await db.delete(target_user)
    await db.commit()

    await record_audit_log(
        db=db,
        action="USER_DELETED",
        actor_user_id=actor.id,
        resource_type="user",
        resource_id=str(target_user_id),
        old_value={
            "username": deleted_username,
            "email": deleted_email,
            "roles": deleted_roles,
        },
        new_value=None,
        source_ip=request_meta.get("source_ip"),
        user_agent=request_meta.get("user_agent"),
        request_id=request_meta.get("request_id"),
    )

    return True

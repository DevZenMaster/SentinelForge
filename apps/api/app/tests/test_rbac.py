"""Comprehensive tests for SentinelForge RBAC (Role-Based Access Control) Subsystem.

Validates:
- RBAC seeding script idempotency and complete permission/role catalog initialization
- Default administrative user bootstrapping
- Capability resolution (merging multiple roles into a deduplicated permission list)
- Endpoint authorization guards: require_permission and require_role
- Granular authorization enforcement across ADMIN, ANALYST, and VIEWER personas
- Superuser authorization override
- 401 (unauthenticated) vs 403 (unauthorized) distinction
"""

import pytest
from fastapi import APIRouter, Depends
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission, require_role
from app.core.config import settings
from app.core.rbac import (
    ALL_PERMISSIONS,
    DEFAULT_ROLE_PERMISSIONS,
    PERMISSION_ALERTS_READ,
    PERMISSION_ALERTS_UPDATE,
    PERMISSION_USERS_CREATE,
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    SYSTEM_ROLES,
)
from app.core.security import hash_password
from app.main import app
from app.models import Permission, Role, RolePermission, User, UserRole
from app.services.auth import create_session, resolve_user_capabilities
from app.services.seed import seed_rbac_and_admin

# Mount a dedicated test router to test RBAC dependencies in realistic HTTP conditions
rbac_test_router = APIRouter(prefix="/test-rbac", tags=["RBAC Test"])


@rbac_test_router.get("/viewer-action")
async def viewer_action_route(
    user: User = Depends(require_permission(PERMISSION_ALERTS_READ)),
) -> dict[str, str]:
    return {"status": "ok", "action": PERMISSION_ALERTS_READ, "user": user.username}


@rbac_test_router.get("/analyst-action")
async def analyst_action_route(
    user: User = Depends(require_permission(PERMISSION_ALERTS_UPDATE)),
) -> dict[str, str]:
    return {"status": "ok", "action": PERMISSION_ALERTS_UPDATE, "user": user.username}


@rbac_test_router.get("/admin-action")
async def admin_action_route(
    user: User = Depends(require_permission(PERMISSION_USERS_CREATE)),
) -> dict[str, str]:
    return {"status": "ok", "action": PERMISSION_USERS_CREATE, "user": user.username}


@rbac_test_router.get("/admin-role-only")
async def admin_role_route(
    user: User = Depends(require_role(ROLE_ADMIN)),
) -> dict[str, str]:
    return {"status": "ok", "role": ROLE_ADMIN, "user": user.username}


# Include test router in FastAPI app for testing
app.include_router(rbac_test_router)


# ==============================================================================
# 1. Seeding and Catalog Initialization Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_seed_rbac_and_admin_initial_and_idempotent(
    test_db_session: AsyncSession,
) -> None:
    """Verify initial seed populates roles, permissions, admin user and is fully idempotent."""
    # First seed run
    seeded = await seed_rbac_and_admin(test_db_session)
    assert seeded is True

    # 1. Check all permissions exist
    perm_count = await test_db_session.scalar(select(func.count(Permission.id)))
    assert perm_count == len(ALL_PERMISSIONS)

    # 2. Check all roles exist
    role_count = await test_db_session.scalar(select(func.count(Role.id)))
    assert role_count == len(SYSTEM_ROLES)

    # 3. Check role-permission mappings
    for role_name, expected_perms in DEFAULT_ROLE_PERMISSIONS.items():
        stmt = (
            select(Permission.name)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .join(Role, RolePermission.role_id == Role.id)
            .where(Role.name == role_name)
        )
        mapped = (await test_db_session.execute(stmt)).scalars().all()
        assert set(mapped) == set(expected_perms)

    # 4. Check initial admin user
    admin_stmt = select(User).where(User.username == "admin")
    admin_user = (await test_db_session.execute(admin_stmt)).scalar_one_or_none()
    assert admin_user is not None
    assert admin_user.is_superuser is True

    # Check admin role assignment
    admin_roles_stmt = (
        select(Role.name)
        .join(UserRole, Role.id == UserRole.role_id)
        .where(UserRole.user_id == admin_user.id)
    )
    admin_roles = (await test_db_session.execute(admin_roles_stmt)).scalars().all()
    assert ROLE_ADMIN in admin_roles

    # Second seed run must be idempotent (no duplicate key errors, no changes)
    second_run = await seed_rbac_and_admin(test_db_session)
    assert second_run is True

    perm_count_after = await test_db_session.scalar(select(func.count(Permission.id)))
    role_count_after = await test_db_session.scalar(select(func.count(Role.id)))
    assert perm_count_after == perm_count
    assert role_count_after == role_count


# ==============================================================================
# 2. Capability Resolution Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_resolve_user_capabilities(test_db_session: AsyncSession) -> None:
    """Verify resolve_user_capabilities combines permissions across multiple assigned roles."""
    await seed_rbac_and_admin(test_db_session)

    # Create a user with both VIEWER and ANALYST roles
    user = User(
        username="multi_role_user",
        email="multi@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.flush()

    viewer_role = (
        await test_db_session.execute(select(Role).where(Role.name == ROLE_VIEWER))
    ).scalar_one()
    analyst_role = (
        await test_db_session.execute(select(Role).where(Role.name == ROLE_ANALYST))
    ).scalar_one()

    test_db_session.add(UserRole(user_id=user.id, role_id=viewer_role.id))
    test_db_session.add(UserRole(user_id=user.id, role_id=analyst_role.id))
    await test_db_session.commit()

    roles, permissions = await resolve_user_capabilities(test_db_session, user.id)
    assert sorted(roles) == ["ANALYST", "VIEWER"]
    # ANALYST permissions encompass VIEWER permissions
    assert "events.read" in permissions
    assert "alerts.update" in permissions
    assert "users.create" not in permissions  # Admin only


# ==============================================================================
# 3. HTTP RBAC Enforcement (401 vs 403 and Persona Separation)
# ==============================================================================


@pytest.mark.asyncio
async def test_rbac_unauthenticated_request_rejected(async_client: AsyncClient) -> None:
    """Verify unauthenticated request without session cookie returns 401 UNAUTHORIZED."""
    resp = await async_client.get("/test-rbac/viewer-action")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_rbac_viewer_persona_boundaries(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify VIEWER can read events, but is blocked with 403 on mutate/admin actions."""
    await seed_rbac_and_admin(test_db_session)

    viewer = User(
        username="viewer_persona",
        email="viewer@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(viewer)
    await test_db_session.flush()

    viewer_role = (
        await test_db_session.execute(select(Role).where(Role.name == ROLE_VIEWER))
    ).scalar_one()
    test_db_session.add(UserRole(user_id=viewer.id, role_id=viewer_role.id))
    await test_db_session.commit()

    _, raw_token = await create_session(test_db_session, viewer)
    headers = {"Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}"}

    # 1. Allowed action (events.read)
    resp = await async_client.get("/test-rbac/viewer-action", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["user"] == "viewer_persona"

    # 2. Denied analyst action (alerts.update) -> 403 FORBIDDEN
    resp = await async_client.get("/test-rbac/analyst-action", headers=headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"
    assert "alerts.update" in resp.json()["error"]["message"]

    # 3. Denied admin action (users.create) -> 403 FORBIDDEN
    resp = await async_client.get("/test-rbac/admin-action", headers=headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_rbac_analyst_persona_boundaries(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify ANALYST can read and triage alerts, but is blocked with 403 on admin actions."""
    await seed_rbac_and_admin(test_db_session)

    analyst = User(
        username="analyst_persona",
        email="analyst@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(analyst)
    await test_db_session.flush()

    analyst_role = (
        await test_db_session.execute(select(Role).where(Role.name == ROLE_ANALYST))
    ).scalar_one()
    test_db_session.add(UserRole(user_id=analyst.id, role_id=analyst_role.id))
    await test_db_session.commit()

    _, raw_token = await create_session(test_db_session, analyst)
    headers = {"Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}"}

    # 1. Allowed viewer action
    resp = await async_client.get("/test-rbac/viewer-action", headers=headers)
    assert resp.status_code == 200

    # 2. Allowed analyst action
    resp = await async_client.get("/test-rbac/analyst-action", headers=headers)
    assert resp.status_code == 200

    # 3. Denied admin permission (users.create) -> 403 FORBIDDEN
    resp = await async_client.get("/test-rbac/admin-action", headers=headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"

    # 4. Denied admin role requirement -> 403 FORBIDDEN
    resp = await async_client.get("/test-rbac/admin-role-only", headers=headers)
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "FORBIDDEN"


@pytest.mark.asyncio
async def test_rbac_admin_persona_access(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify ADMIN persona has full access to viewer, analyst, and admin protected routes."""
    await seed_rbac_and_admin(test_db_session)

    admin = User(
        username="sec_admin",
        email="secadmin@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(admin)
    await test_db_session.flush()

    admin_role = (
        await test_db_session.execute(select(Role).where(Role.name == ROLE_ADMIN))
    ).scalar_one()
    test_db_session.add(UserRole(user_id=admin.id, role_id=admin_role.id))
    await test_db_session.commit()

    _, raw_token = await create_session(test_db_session, admin)
    headers = {"Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}"}

    res_viewer = await async_client.get("/test-rbac/viewer-action", headers=headers)
    res_analyst = await async_client.get("/test-rbac/analyst-action", headers=headers)
    res_admin = await async_client.get("/test-rbac/admin-action", headers=headers)
    res_role = await async_client.get("/test-rbac/admin-role-only", headers=headers)
    assert res_viewer.status_code == 200
    assert res_analyst.status_code == 200
    assert res_admin.status_code == 200
    assert res_role.status_code == 200


@pytest.mark.asyncio
async def test_rbac_superuser_override(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify is_superuser=True bypasses all permission and role checks."""
    superuser = User(
        username="global_root",
        email="root@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
        is_superuser=True,
    )
    test_db_session.add(superuser)
    await test_db_session.commit()

    _, raw_token = await create_session(test_db_session, superuser)
    headers = {"Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}"}

    res_viewer = await async_client.get("/test-rbac/viewer-action", headers=headers)
    res_analyst = await async_client.get("/test-rbac/analyst-action", headers=headers)
    res_admin = await async_client.get("/test-rbac/admin-action", headers=headers)
    res_role = await async_client.get("/test-rbac/admin-role-only", headers=headers)
    assert res_viewer.status_code == 200
    assert res_analyst.status_code == 200
    assert res_admin.status_code == 200
    assert res_role.status_code == 200

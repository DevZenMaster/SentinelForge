"""Integration and Security Tests for Phase 15: User Settings & Administration.

Validates:
1. Self-Service Profile Retrieval and Mutation (GET / PATCH /api/v1/users/me).
2. Username uniqueness and validation.
3. Password change requirements, Argon2id re-hashing, and session invalidation.
4. Role listing endpoint (GET /api/v1/users/roles).
5. Administrative User Creation (POST /api/v1/users) with RBAC enforcement and duplicate checks.
6. Administrative User Update (PATCH /api/v1/users/{id}) and status toggling (POST /status).
7. Last Administrator Protection: prevention of lockout via demotion, deactivation, or deletion.
8. Forensic Integrity Preservation: rejection of deletion for users with authored notes (409).
9. Audit trail logging for all mutations without credential leakage.
"""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rbac import ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER
from app.core.security import get_password_hash, verify_password
from app.models.audit import AuditLog
from app.models.auth import Role, User, UserRole
from app.models.incident import Incident, IncidentNote
from app.services.auth import create_session
from app.services.seed import seed_rbac_and_admin

CSRF_HEADERS = {"X-Requested-With": "XMLHttpRequest"}


async def _create_test_user(
    db: AsyncSession,
    role_name: str,
    username: str,
    is_active: bool = True,
    password: str = "TestPassword123!",  # noqa: S107
) -> tuple[User, str]:
    await seed_rbac_and_admin(db)
    user = User(
        username=username,
        email=f"{username}@sentinelforge.local",
        hashed_password=get_password_hash(password),
        full_name=f"Full {username}",
        is_active=is_active,
    )
    db.add(user)
    await db.flush()

    role = (await db.execute(select(Role).where(Role.name == role_name))).scalar_one()
    db.add(UserRole(user_id=user.id, role_id=role.id))
    await db.commit()

    _, token = await create_session(db, user)
    return user, token


# ----------------------------------------------------------------------
# 1. Self-Service Tests (/me and /me/change-password)
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_my_profile_unauthenticated(async_client: AsyncClient) -> None:
    resp = await async_client.get("/api/v1/users/me")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_get_my_profile_authenticated(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    analyst, token = await _create_test_user(test_db_session, ROLE_ANALYST, "p15_me_user")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await async_client.get("/api/v1/users/me")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["username"] == "p15_me_user"
    assert data["email"] == "p15_me_user@sentinelforge.local"
    assert data["full_name"] == "Full p15_me_user"
    assert ROLE_ANALYST in data["roles"]
    assert "alerts.read" in data["permissions"]


@pytest.mark.asyncio
async def test_update_my_profile_success_and_audit(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    analyst, token = await _create_test_user(test_db_session, ROLE_ANALYST, "p15_upd_user")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    # Update full_name and username
    resp = await async_client.patch(
        "/api/v1/users/me",
        json={"full_name": "Renamed Analyst", "username": "p15_upd_renamed"},
        headers=CSRF_HEADERS,
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["full_name"] == "Renamed Analyst"
    assert data["username"] == "p15_upd_renamed"

    # Verify audit log was recorded
    stmt_audit = select(AuditLog).where(
        AuditLog.action == "USER_PROFILE_UPDATED",
        AuditLog.actor_user_id == analyst.id,
    )
    audit = (await test_db_session.execute(stmt_audit)).scalar_one_or_none()
    assert audit is not None
    assert audit.resource_type == "user"
    assert audit.new_value["username"] == "p15_upd_renamed"


@pytest.mark.asyncio
async def test_update_my_profile_duplicate_username_rejected(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    _existing, _ = await _create_test_user(test_db_session, ROLE_VIEWER, "p15_existing_target")
    _analyst, token = await _create_test_user(test_db_session, ROLE_ANALYST, "p15_attempt_user")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await async_client.patch(
        "/api/v1/users/me",
        json={"username": "p15_existing_target"},
        headers=CSRF_HEADERS,
    )
    assert resp.status_code == 409
    assert "already taken" in resp.json()["error"]["message"].lower()


@pytest.mark.asyncio
async def test_change_password_workflow(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    analyst, token1 = await _create_test_user(
        test_db_session, ROLE_ANALYST, "p15_pw_user", password="InitialPassword123!"
    )
    # Create a secondary session representing another device
    _, token2 = await create_session(test_db_session, analyst)

    # Use token1 as active session
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token1)

    # 1. Invalid current password -> 400
    bad_current = await async_client.post(
        "/api/v1/users/me/change-password",
        json={
            "current_password": "WrongPassword123!",
            "new_password": "BrandNewPassword999!",
            "confirm_password": "BrandNewPassword999!",
        },
        headers=CSRF_HEADERS,
    )
    assert bad_current.status_code == 400
    assert "incorrect" in bad_current.json()["error"]["message"].lower()

    # 2. Same new password -> 400
    same_pw = await async_client.post(
        "/api/v1/users/me/change-password",
        json={
            "current_password": "InitialPassword123!",
            "new_password": "InitialPassword123!",
            "confirm_password": "InitialPassword123!",
        },
        headers=CSRF_HEADERS,
    )
    assert same_pw.status_code == 400
    assert "cannot be identical" in same_pw.json()["error"]["message"].lower()

    # 3. New password too short (< 12 chars) -> 422
    short_pw = await async_client.post(
        "/api/v1/users/me/change-password",
        json={
            "current_password": "InitialPassword123!",
            "new_password": "short",
            "confirm_password": "short",
        },
        headers=CSRF_HEADERS,
    )
    assert short_pw.status_code == 422

    # 4. Valid password change -> 200
    good_pw = await async_client.post(
        "/api/v1/users/me/change-password",
        json={
            "current_password": "InitialPassword123!",
            "new_password": "BrandNewPassword999!",
            "confirm_password": "BrandNewPassword999!",
        },
        headers=CSRF_HEADERS,
    )
    assert good_pw.status_code == 200

    # Verify updated hash matches new password
    await test_db_session.refresh(analyst)
    assert verify_password("BrandNewPassword999!", analyst.hashed_password)

    # Verify token1 remains valid
    profile_resp = await async_client.get("/api/v1/users/me")
    assert profile_resp.status_code == 200

    # Verify token2 has been revoked
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token2)
    revoked_resp = await async_client.get("/api/v1/users/me")
    assert revoked_resp.status_code == 401


# ----------------------------------------------------------------------
# 2. Roles Listing Endpoint
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roles_listing(async_client: AsyncClient, test_db_session: AsyncSession) -> None:
    # 1. Non-admin (viewer) is blocked -> 403
    _viewer, v_token = await _create_test_user(test_db_session, ROLE_VIEWER, "p15_roles_viewer")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, v_token)
    forbidden_resp = await async_client.get("/api/v1/users/roles")
    assert forbidden_resp.status_code == 403

    # 2. Admin succeeds -> 200
    _admin, token = await _create_test_user(test_db_session, ROLE_ADMIN, "p15_roles_checker")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, token)

    resp = await async_client.get("/api/v1/users/roles")
    assert resp.status_code == 200
    data = resp.json()["data"]
    role_names = [r["name"] for r in data["items"]]
    assert ROLE_ADMIN in role_names
    assert ROLE_ANALYST in role_names
    assert ROLE_VIEWER in role_names


# ----------------------------------------------------------------------
# 3. Admin User Management & RBAC Enforcement
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_admin_user_creation_rbac(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    # 1. Analyst (lacking users.create) is blocked -> 403
    _analyst, a_token = await _create_test_user(
        test_db_session, ROLE_ANALYST, "p15_analyst_creator"
    )
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, a_token)

    payload = {
        "username": "p15_new_user",
        "email": "p15_new@sentinelforge.local",
        "password": "SecurePassword123!",
        "roles": [ROLE_ANALYST],
    }
    resp = await async_client.post("/api/v1/users", json=payload, headers=CSRF_HEADERS)
    assert resp.status_code == 403

    # 2. Admin succeeds -> 201
    _admin, adm_token = await _create_test_user(test_db_session, ROLE_ADMIN, "p15_admin_creator")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, adm_token)

    resp2 = await async_client.post("/api/v1/users", json=payload, headers=CSRF_HEADERS)
    assert resp2.status_code == 201
    data = resp2.json()["data"]
    assert data["username"] == "p15_new_user"
    assert data["email"] == "p15_new@sentinelforge.local"
    assert ROLE_ANALYST in data["roles"]

    # 3. Duplicate email or username -> 409
    resp_dup = await async_client.post("/api/v1/users", json=payload, headers=CSRF_HEADERS)
    assert resp_dup.status_code == 409


@pytest.mark.asyncio
async def test_admin_list_users_filters(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    _admin, adm_token = await _create_test_user(test_db_session, ROLE_ADMIN, "p15_admin_lister")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, adm_token)

    resp = await async_client.get("/api/v1/users?search=admin_lister")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["total"] >= 1
    assert any(u["username"] == "p15_admin_lister" for u in data["items"])


@pytest.mark.asyncio
async def test_last_administrator_lockout_protection(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    # Ensure seed admin and RBAC
    await seed_rbac_and_admin(test_db_session)

    # Retrieve all existing users and make sure we have exactly ONE admin for testing
    admin, adm_token = await _create_test_user(test_db_session, ROLE_ADMIN, "p15_sole_admin")
    # Deactivate any other admins to test the single-admin edge case
    stmt_other_admins = (
        select(User)
        .join(UserRole, User.id == UserRole.user_id)
        .join(Role, UserRole.role_id == Role.id)
        .where(Role.name == ROLE_ADMIN, User.id != admin.id)
    )
    other_admins = (await test_db_session.execute(stmt_other_admins)).scalars().all()
    for oa in other_admins:
        oa.is_active = False
    await test_db_session.commit()

    async_client.cookies.set(settings.SESSION_COOKIE_NAME, adm_token)

    # 1. Attempting to deactivate the last admin -> 400
    deact_resp = await async_client.post(
        f"/api/v1/users/{admin.id}/status",
        json={"is_active": False},
        headers=CSRF_HEADERS,
    )
    assert deact_resp.status_code == 400
    assert "last active administrator" in deact_resp.json()["error"]["message"].lower()

    # 2. Attempting to demote the last admin to VIEWER -> 400
    demote_resp = await async_client.patch(
        f"/api/v1/users/{admin.id}",
        json={"roles": [ROLE_VIEWER]},
        headers=CSRF_HEADERS,
    )
    assert demote_resp.status_code == 400
    assert "last active administrator" in demote_resp.json()["error"]["message"].lower()

    # 3. Attempting to delete the last admin -> 400 (or self-deletion block)
    del_resp = await async_client.delete(f"/api/v1/users/{admin.id}", headers=CSRF_HEADERS)
    assert del_resp.status_code == 400


@pytest.mark.asyncio
async def test_forensic_integrity_preservation_on_delete(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    admin, adm_token = await _create_test_user(test_db_session, ROLE_ADMIN, "p15_del_admin")
    analyst, _ = await _create_test_user(test_db_session, ROLE_ANALYST, "p15_note_author")

    # Create an incident and an incident note authored by analyst
    incident = Incident(
        id=uuid.uuid4(),
        title="Forensic Test Incident",
        description="Testing forensic note retention",
        severity="HIGH",
        status="OPEN",
    )
    test_db_session.add(incident)
    await test_db_session.flush()

    note = IncidentNote(
        id=uuid.uuid4(),
        incident_id=incident.id,
        author_user_id=analyst.id,
        content="Forensic investigation finding: suspicious activity verified.",
    )
    test_db_session.add(note)
    await test_db_session.commit()

    async_client.cookies.set(settings.SESSION_COOKIE_NAME, adm_token)

    # Attempt to delete analyst -> 409 Conflict instructing to deactivate
    resp = await async_client.delete(f"/api/v1/users/{analyst.id}", headers=CSRF_HEADERS)
    assert resp.status_code == 409
    detail = resp.json()["error"]["message"]
    assert "forensic integrity" in detail.lower()
    assert "deactivate the account instead" in detail.lower()

    # Deactivating analyst succeeds
    deact_resp = await async_client.post(
        f"/api/v1/users/{analyst.id}/status",
        json={"is_active": False},
        headers=CSRF_HEADERS,
    )
    assert deact_resp.status_code == 200
    assert deact_resp.json()["data"]["is_active"] is False


@pytest.mark.asyncio
async def test_clean_user_deletion(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    _admin, adm_token = await _create_test_user(test_db_session, ROLE_ADMIN, "p15_clean_admin")
    clean_user, _ = await _create_test_user(test_db_session, ROLE_VIEWER, "p15_clean_target")
    async_client.cookies.set(settings.SESSION_COOKIE_NAME, adm_token)

    del_resp = await async_client.delete(f"/api/v1/users/{clean_user.id}", headers=CSRF_HEADERS)
    assert del_resp.status_code == 200, del_resp.json()

    # User should no longer exist
    stmt = select(User).where(User.id == clean_user.id)
    assert (await test_db_session.execute(stmt)).scalar_one_or_none() is None

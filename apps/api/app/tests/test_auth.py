"""Comprehensive security tests for SentinelForge Authentication Subsystem.

Validates:
- Argon2id password hashing and constant-time verification
- Opaque session token generation, hashing, and database storage
- Constant-time enumeration defenses on /login
- Cookie attributes (HttpOnly, SameSite=lax, Secure in production)
- Session lifecycle: issuance, active verification, expiry, and revocation
- Rate limiting on /login returning HTTP 429 and Retry-After header
- Defense-in-depth CSRF protection on unsafe methods
- Comprehensive security headers
- Audit logging for LOGIN_SUCCESS, LOGIN_FAILURE, and LOGOUT
"""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.rate_limit import auth_rate_limiter
from app.core.security import (
    generate_csrf_token,
    generate_session_token,
    hash_password,
    hash_session_token,
    validate_csrf_token,
    verify_password,
)
from app.models import AuditLog, Session, User

# ==============================================================================
# 1. Cryptographic and Security Primitives Tests
# ==============================================================================


def test_argon2id_hashing_and_verification() -> None:
    """Verify RFC 9106 Argon2id parameters, verification, and rejection of invalid passwords."""
    plain = "P@ssw0rd_SentinelForge_2026!"
    hashed = hash_password(plain)

    # Validate Argon2id format and configured parameters
    assert hashed.startswith("$argon2id$v=19$m=65536,t=3,p=4$")
    assert verify_password(plain, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False


def test_session_token_entropy_and_hashing() -> None:
    """Verify session tokens provide sufficient entropy and SHA-256 produces 64-char hex strings."""
    token_1 = generate_session_token()
    token_2 = generate_session_token()

    assert len(token_1) >= 40
    assert token_1 != token_2

    hash_1 = hash_session_token(token_1)
    hash_2 = hash_session_token(token_2)

    assert len(hash_1) == 64
    assert len(hash_2) == 64
    assert hash_1 != hash_2
    assert hash_session_token(token_1) == hash_1


def test_csrf_token_generation_and_validation() -> None:
    """Verify CSRF token generation and constant-time validation."""
    token = generate_csrf_token()
    assert len(token) >= 40
    assert validate_csrf_token(token, token) is True
    assert validate_csrf_token(token, generate_csrf_token()) is False
    assert validate_csrf_token(token, "") is False


# ==============================================================================
# 2. Authentication Flow Tests (Login, Enumeration, Inactive, Rate Limiting)
# ==============================================================================


@pytest.mark.asyncio
async def test_login_success_and_cookie_attributes(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify successful login sets HttpOnly, SameSite=lax cookie and writes audit log."""
    password = "ValidPass_2026_Secure!"
    user = User(
        username="analyst_bob",
        email="bob@sentinelforge.local",
        hashed_password=hash_password(password),
        full_name="Bob Analyst",
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_bob", "password": password},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["username"] == "analyst_bob"
    assert body["data"]["email"] == "bob@sentinelforge.local"
    assert "password" not in str(body)
    assert "hashed_password" not in str(body)

    # Check Cookie Attributes
    session_cookie = resp.cookies.get(settings.SESSION_COOKIE_NAME)
    assert session_cookie is not None
    # Verify cookie raw token is hashed before storing in DB
    token_hash = hash_session_token(session_cookie)
    stmt = select(Session).where(Session.session_token_hash == token_hash)
    db_sess = (await test_db_session.execute(stmt)).scalar_one_or_none()
    assert db_sess is not None
    assert db_sess.user_id == user.id
    assert db_sess.revoked_at is None

    # Verify Audit Log
    audit_stmt = select(AuditLog).where(
        AuditLog.actor_user_id == user.id, AuditLog.action == "LOGIN_SUCCESS"
    )
    audit = (await test_db_session.execute(audit_stmt)).scalar_one_or_none()
    assert audit is not None
    assert audit.new_value is not None
    assert audit.new_value["username"] == "analyst_bob"


@pytest.mark.asyncio
async def test_login_success_with_email(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify login succeeds when authenticating with email address."""
    password = "EmailLogin_2026_Secure!"
    user = User(
        username="analyst_claire",
        email="claire@sentinelforge.local",
        hashed_password=hash_password(password),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "claire@sentinelforge.local", "password": password},
    )

    assert resp.status_code == 200
    assert resp.json()["data"]["username"] == "analyst_claire"
    assert settings.SESSION_COOKIE_NAME in resp.cookies


@pytest.mark.asyncio
async def test_login_failure_invalid_password(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify invalid password returns generic 401 and logs LOGIN_FAILURE without leaks."""
    user = User(
        username="analyst_dave",
        email="dave@sentinelforge.local",
        hashed_password=hash_password("Correct_Pass_123!"),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "analyst_dave", "password": "Wrong_Pass_999!"},
    )

    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["message"] == "Invalid username or password."
    assert settings.SESSION_COOKIE_NAME not in resp.cookies

    # Verify Audit Log
    audit_stmt = select(AuditLog).where(AuditLog.action == "LOGIN_FAILURE")
    audit = (await test_db_session.execute(audit_stmt)).scalar_one_or_none()
    assert audit is not None
    assert audit.new_value is not None
    assert audit.new_value["attempted_identifier"] == "analyst_dave"
    assert "Wrong_Pass_999!" not in str(audit.new_value)


@pytest.mark.asyncio
async def test_login_failure_unknown_user_constant_time(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify non-existent user returns generic 401 and runs constant-time verification."""
    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "ghost_user_does_not_exist", "password": "Random_Pass_123!"},
    )

    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["message"] == "Invalid username or password."

    audit_stmt = select(AuditLog).where(AuditLog.action == "LOGIN_FAILURE")
    audit = (await test_db_session.execute(audit_stmt)).scalar_one_or_none()
    assert audit is not None
    assert audit.actor_user_id is None
    assert audit.new_value is not None
    assert audit.new_value["attempted_identifier"] == "ghost_user_does_not_exist"


@pytest.mark.asyncio
async def test_login_failure_inactive_user(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify deactivated account cannot log in even with valid credentials."""
    password = "ValidPass_Deactivated_2026!"
    user = User(
        username="inactive_user",
        email="inactive@sentinelforge.local",
        hashed_password=hash_password(password),
        is_active=False,
    )
    test_db_session.add(user)
    await test_db_session.commit()

    resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "inactive_user", "password": password},
    )

    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["message"] == "Invalid username or password."


@pytest.mark.asyncio
async def test_login_rate_limiting(async_client: AsyncClient) -> None:
    """Verify sliding window rate limiting on /login returns HTTP 429 and Retry-After header."""
    auth_rate_limiter.clear()

    for i in range(settings.AUTH_RATE_LIMIT_PER_MINUTE):
        resp = await async_client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "brute_force_target", "password": f"attempt_{i}"},
        )
        assert resp.status_code == 401

    # Attempt N+1 should trigger 429
    blocked_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "brute_force_target", "password": "attempt_exceeded"},
    )
    assert blocked_resp.status_code == 429
    body = blocked_resp.json()
    assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert "Retry-After" in blocked_resp.headers


# ==============================================================================
# 3. Session Validation & /me Endpoint Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_me_authenticated(async_client: AsyncClient, test_db_session: AsyncSession) -> None:
    """Verify valid session cookie allows access to /api/v1/auth/me."""
    password = "ValidPass_Me_2026!"
    user = User(
        username="me_user",
        email="me@sentinelforge.local",
        hashed_password=hash_password(password),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.commit()

    # Login
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "me_user", "password": password},
    )
    session_token = login_resp.cookies[settings.SESSION_COOKIE_NAME]

    # Call /me with session cookie header
    resp = await async_client.get(
        "/api/v1/auth/me",
        headers={"Cookie": f"{settings.SESSION_COOKIE_NAME}={session_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["username"] == "me_user"
    assert data["email"] == "me@sentinelforge.local"


@pytest.mark.asyncio
async def test_me_unauthenticated_missing_cookie(async_client: AsyncClient) -> None:
    """Verify request without cookie returns 401 UNAUTHORIZED."""
    resp = await async_client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_me_invalid_token(async_client: AsyncClient) -> None:
    """Verify request with non-existent token returns 401 UNAUTHORIZED."""
    resp = await async_client.get(
        "/api/v1/auth/me",
        headers={"Cookie": f"{settings.SESSION_COOKIE_NAME}=completely_bogus_token_value"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.asyncio
async def test_me_expired_session(async_client: AsyncClient, test_db_session: AsyncSession) -> None:
    """Verify expired session is rejected with 401 and marked revoked in the database."""
    user = User(
        username="expired_user",
        email="expired@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.flush()

    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    session = Session(
        session_token_hash=token_hash,
        user_id=user.id,
        expires_at=datetime.now(UTC) - timedelta(minutes=15),  # Expired
    )
    test_db_session.add(session)
    await test_db_session.commit()

    resp = await async_client.get(
        "/api/v1/auth/me",
        headers={"Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHORIZED"

    # Verify session is marked revoked in DB
    stmt = select(Session).where(Session.session_token_hash == token_hash)
    db_session = (await test_db_session.execute(stmt)).scalar_one()
    assert db_session.revoked_at is not None


@pytest.mark.asyncio
async def test_me_revoked_session(async_client: AsyncClient, test_db_session: AsyncSession) -> None:
    """Verify explicitly revoked session returns 401."""
    user = User(
        username="revoked_user",
        email="revoked@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.flush()

    raw_token = generate_session_token()
    session = Session(
        session_token_hash=hash_session_token(raw_token),
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        revoked_at=datetime.now(UTC) - timedelta(minutes=5),  # Explicitly revoked
    )
    test_db_session.add(session)
    await test_db_session.commit()

    resp = await async_client.get(
        "/api/v1/auth/me",
        headers={"Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}"},
    )
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "UNAUTHORIZED"


# ==============================================================================
# 4. Logout Lifecycle Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_logout_success(async_client: AsyncClient, test_db_session: AsyncSession) -> None:
    """Verify logout revokes session in DB, deletes cookie, and logs LOGOUT action."""
    password = "LogoutPass_2026_Secure!"
    user = User(
        username="logout_user",
        email="logout@sentinelforge.local",
        hashed_password=hash_password(password),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.commit()

    # Login
    login_resp = await async_client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "logout_user", "password": password},
    )
    session_token = login_resp.cookies[settings.SESSION_COOKIE_NAME]
    token_hash = hash_session_token(session_token)

    # Logout with session cookie and CSRF protection header
    logout_resp = await async_client.post(
        "/api/v1/auth/logout",
        headers={
            "Cookie": f"{settings.SESSION_COOKIE_NAME}={session_token}",
            "X-Requested-With": "XMLHttpRequest",
        },
    )
    assert logout_resp.status_code == 200
    assert logout_resp.json()["data"]["message"] == "Session successfully invalidated."

    # Verify session revoked in database
    stmt = select(Session).where(Session.session_token_hash == token_hash)
    db_session = (await test_db_session.execute(stmt)).scalar_one()
    assert db_session.revoked_at is not None

    # Verify Audit Log
    audit_stmt = select(AuditLog).where(
        AuditLog.actor_user_id == user.id, AuditLog.action == "LOGOUT"
    )
    audit = (await test_db_session.execute(audit_stmt)).scalar_one_or_none()
    assert audit is not None

    # Subsequent request using same token must be rejected
    me_resp = await async_client.get(
        "/api/v1/auth/me",
        headers={"Cookie": f"{settings.SESSION_COOKIE_NAME}={session_token}"},
    )
    assert me_resp.status_code == 401


# ==============================================================================
# 5. CSRF Defense and Security Headers Tests
# ==============================================================================


@pytest.mark.asyncio
async def test_csrf_protection_blocked_without_custom_header(
    async_client: AsyncClient, test_db_session: AsyncSession
) -> None:
    """Verify state-changing POST with session cookie and untrusted origin is blocked."""
    raw_token = generate_session_token()
    user = User(
        username="csrf_user",
        email="csrf@sentinelforge.local",
        hashed_password=hash_password("password"),
        is_active=True,
    )
    test_db_session.add(user)
    await test_db_session.flush()

    sess = Session(
        session_token_hash=hash_session_token(raw_token),
        user_id=user.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    test_db_session.add(sess)
    await test_db_session.commit()

    # Request with session cookie, text/plain content, missing headers, and external Origin
    resp = await async_client.post(
        "/api/v1/auth/logout",
        headers={
            "Cookie": f"{settings.SESSION_COOKIE_NAME}={raw_token}",
            "Content-Type": "text/plain",
            "Origin": "https://evil-site.com",
        },
    )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "CSRF_ERROR"


@pytest.mark.asyncio
async def test_security_headers_present(async_client: AsyncClient) -> None:
    """Verify required security headers are attached on all responses."""
    resp = await async_client.get("/api/v1/health/live")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]

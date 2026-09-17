"""Authentication Router for SentinelForge.

Provides endpoints for login, session revocation (logout), and current user profile inspection.
Enforces generic error responses, rate limiting, secure cookie issuance, and immutable audit logs.
"""

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user_context
from app.core.config import settings
from app.core.rate_limit import enforce_login_rate_limit
from app.db.session import get_db
from app.models import User
from app.schemas.auth import LoginRequest, LogoutResponse, UserResponse
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.auth import (
    authenticate_credentials,
    create_session,
    record_audit_log,
    resolve_user_capabilities,
    revoke_session,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


@router.post(
    "/login",
    response_model=APIResponse[UserResponse],
    summary="User Authentication and Session Establishment",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserResponse]:
    """Authenticate user credentials, establish a session, and set an HttpOnly cookie."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    # 1. Enforce authentication rate limiting
    enforce_login_rate_limit(request, identifier=payload.username_or_email)

    # 2. Verify credentials
    user = await authenticate_credentials(db, payload.username_or_email, payload.password)

    if not user:
        # Audit failed login attempt without storing password
        await record_audit_log(
            db=db,
            action="LOGIN_FAILURE",
            actor_user_id=None,
            resource_type="auth",
            resource_id=payload.username_or_email[:64],
            request_id=request_id,
            source_ip=client_ip,
            user_agent=user_agent,
            new_value={"attempted_identifier": payload.username_or_email[:64]},
        )
        # Generic error message defeats account enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Cookie"},
        )

    # 3. Create server-side session
    _session, raw_token = await create_session(
        db=db,
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # 4. Set secure HttpOnly session cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.SESSION_EXPIRE_HOURS * 3600,
        httponly=settings.SESSION_COOKIE_HTTPONLY,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        path="/",
    )

    # 5. Resolve user capabilities
    roles, permissions = await resolve_user_capabilities(db, user.id)

    # 6. Audit successful login
    await record_audit_log(
        db=db,
        action="LOGIN_SUCCESS",
        actor_user_id=user.id,
        resource_type="auth",
        resource_id=str(user.id),
        request_id=request_id,
        source_ip=client_ip,
        user_agent=user_agent,
        new_value={"username": user.username},
    )

    user_data = UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        roles=roles,
        permissions=permissions,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )

    return APIResponse[UserResponse](
        data=user_data,
        meta=_build_metadata(request),
        error=None,
    )


@router.post(
    "/logout",
    response_model=APIResponse[LogoutResponse],
    summary="Session Revocation and Invalidation",
)
async def logout(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[LogoutResponse]:
    """Revoke active session in database and purge the session cookie.

    Idempotent and safe to call even if already logged out.
    """
    raw_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not raw_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()

    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    if raw_token:
        revoked, user_id = await revoke_session(db, raw_token)
        if revoked:
            await record_audit_log(
                db=db,
                action="LOGOUT",
                actor_user_id=user_id,
                resource_type="auth",
                resource_id=str(user_id) if user_id else "session",
                request_id=request_id,
                source_ip=client_ip,
                user_agent=user_agent,
            )

    # Purge cookie from browser
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        httponly=settings.SESSION_COOKIE_HTTPONLY,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )

    return APIResponse[LogoutResponse](
        data=LogoutResponse(status="logged_out", message="Session successfully invalidated."),
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/me",
    response_model=APIResponse[UserResponse],
    summary="Current Authenticated User Profile",
)
async def get_current_user_profile(
    request: Request,
    context: Annotated[tuple[User, list[str], list[str]], Depends(get_current_user_context)],
) -> APIResponse[UserResponse]:
    """Retrieve sanitized profile, roles, and permissions for the currently authenticated user."""
    user, roles, permissions = context

    user_data = UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        is_active=user.is_active,
        is_superuser=user.is_superuser,
        roles=roles,
        permissions=permissions,
        created_at=user.created_at,
        updated_at=user.updated_at,
    )

    return APIResponse[UserResponse](
        data=user_data,
        meta=_build_metadata(request),
        error=None,
    )

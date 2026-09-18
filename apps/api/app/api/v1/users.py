"""User Directory and Administration Endpoints for SentinelForge (Phase 11 & Phase 15).

Provides:
- GET /api/v1/users/me: Self-service profile retrieval.
- PATCH /api/v1/users/me: Self-service profile update (display name, username).
- POST /api/v1/users/me/change-password: Self-service password change with session revocation.
- GET /api/v1/users/roles: Available system roles for administration.
- GET /api/v1/users: Sanitized user account listing with search and filters.
- POST /api/v1/users: Create new user account (admin).
- GET /api/v1/users/{user_id}: Retrieve user details (admin).
- PATCH /api/v1/users/{user_id}: Update user attributes and roles (admin).
- POST /api/v1/users/{user_id}/status: Activate or deactivate user (admin).
- DELETE /api/v1/users/{user_id}: Delete user account with forensic protection (admin).
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    get_current_session_and_user,
    get_current_user,
    require_any_permission,
    require_permission,
)
from app.core.rbac import (
    PERMISSION_ALERTS_ASSIGN,
    PERMISSION_ALERTS_READ,
    PERMISSION_INCIDENTS_UPDATE,
    PERMISSION_USERS_CREATE,
    PERMISSION_USERS_DELETE,
    PERMISSION_USERS_READ,
    PERMISSION_USERS_UPDATE,
)
from app.db.session import get_db
from app.models.auth import Session, User
from app.schemas.response import APIResponse, ResponseMetadata
from app.schemas.user import (
    PasswordChangeRequest,
    RoleListItemResponse,
    RoleListResponse,
    UserAdminUpdateRequest,
    UserCreateRequest,
    UserDetailResponse,
    UserListItemResponse,
    UserListResponse,
    UserProfileUpdateRequest,
    UserStatusUpdateRequest,
)
from app.services.user import (
    change_self_password,
    create_admin_user,
    delete_admin_user,
    get_user_detail,
    list_admin_users,
    list_available_roles,
    set_user_status,
    update_admin_user,
    update_self_profile,
)

router = APIRouter(prefix="/users", tags=["Users"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def _extract_meta(request: Request) -> dict[str, Any]:
    return {
        "source_ip": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
        "request_id": getattr(request.state, "request_id", None),
    }


def _to_detail_response(
    user: User, roles: list[str], permissions: list[str], last_login_at: datetime | None
) -> UserDetailResponse:
    return UserDetailResponse(
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
        last_login_at=last_login_at,
    )


# ----------------------------------------------------------------------
# Self-Service Endpoints (/me)
# ----------------------------------------------------------------------


@router.get(
    "/me",
    response_model=APIResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Current User Profile",
)
async def get_my_profile(
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserDetailResponse]:
    """Retrieve the authenticated user's profile, roles, and derived capabilities."""
    detail = await get_user_detail(db, current_user.id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User profile not found.",
        )
    user, roles, perms, last_login = detail
    return APIResponse[UserDetailResponse](
        data=_to_detail_response(user, roles, perms, last_login),
        meta=_build_metadata(request),
        error=None,
    )


@router.patch(
    "/me",
    response_model=APIResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Current User Profile",
)
async def update_my_profile(
    request: Request,
    payload: UserProfileUpdateRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserDetailResponse]:
    """Update self profile details (display name or username)."""
    user, roles, perms, last_login = await update_self_profile(
        db=db,
        user=current_user,
        payload=payload,
        request_meta=_extract_meta(request),
    )
    return APIResponse[UserDetailResponse](
        data=_to_detail_response(user, roles, perms, last_login),
        meta=_build_metadata(request),
        error=None,
    )


@router.post(
    "/me/change-password",
    response_model=APIResponse[dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Change Current User Password",
)
async def change_my_password(
    request: Request,
    payload: PasswordChangeRequest,
    session_user: Annotated[tuple[Session, User], Depends(get_current_session_and_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict[str, str]]:
    """Change current password, requiring verification and invalidating other sessions."""
    session, user = session_user
    await change_self_password(
        db=db,
        user=user,
        payload=payload,
        current_session_token_hash=session.session_token_hash,
        request_meta=_extract_meta(request),
    )
    return APIResponse[dict[str, str]](
        data={
            "message": (
                "Password successfully changed. "
                "Other active sessions have been invalidated."
            )
        },
        meta=_build_metadata(request),
        error=None,
    )


# ----------------------------------------------------------------------
# Roles Listing (Admin/Analyst creation)
# ----------------------------------------------------------------------


@router.get(
    "/roles",
    response_model=APIResponse[RoleListResponse],
    status_code=status.HTTP_200_OK,
    summary="List Available System Roles",
)
async def list_roles_endpoint(
    request: Request,
    _current_user: Annotated[
        User,
        Depends(
            require_any_permission(
                PERMISSION_USERS_READ,
                PERMISSION_USERS_CREATE,
                PERMISSION_USERS_UPDATE,
            )
        ),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[RoleListResponse]:
    """List system roles available for user assignment."""
    roles = await list_available_roles(db)
    items = [
        RoleListItemResponse(id=r.id, name=r.name, description=r.description)
        for r in roles
    ]
    return APIResponse[RoleListResponse](
        data=RoleListResponse(items=items, total=len(items)),
        meta=_build_metadata(request),
        error=None,
    )


# ----------------------------------------------------------------------
# User Directory & Administration Endpoints
# ----------------------------------------------------------------------


@router.get(
    "",
    response_model=APIResponse[UserListResponse],
    status_code=status.HTTP_200_OK,
    summary="List User Accounts",
)
async def list_users_endpoint(
    request: Request,
    _current_user: Annotated[
        User,
        Depends(
            require_any_permission(
                PERMISSION_USERS_READ,
                PERMISSION_ALERTS_ASSIGN,
                PERMISSION_INCIDENTS_UPDATE,
                PERMISSION_ALERTS_READ,
            )
        ),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    search: str | None = Query(default=None, description="Search by username, email, or full name"),
    is_active: bool | None = Query(default=None, description="Filter by active status"),
    role: str | None = Query(default=None, description="Filter by role name"),
) -> APIResponse[UserListResponse]:
    """Retrieve user accounts with filtering by search term, active status, and role."""
    user_dicts = await list_admin_users(
        db=db,
        search=search,
        role=role,
        is_active=is_active,
    )

    items = [
        UserListItemResponse(
            id=u["id"],
            username=u["username"],
            email=u["email"],
            full_name=u["full_name"],
            is_active=u["is_active"],
            roles=u["roles"],
            created_at=u["created_at"],
            last_login_at=u["last_login_at"],
        )
        for u in user_dicts
    ]

    return APIResponse[UserListResponse](
        data=UserListResponse(
            items=items,
            total=len(items),
        ),
        meta=_build_metadata(request),
        error=None,
    )


@router.post(
    "",
    response_model=APIResponse[UserDetailResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create New User Account",
)
async def create_user_endpoint(
    request: Request,
    payload: UserCreateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_USERS_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserDetailResponse]:
    """Create a new user account with specified roles and initial password."""
    user, roles, perms, last_login = await create_admin_user(
        db=db,
        actor=current_user,
        payload=payload,
        request_meta=_extract_meta(request),
    )
    return APIResponse[UserDetailResponse](
        data=_to_detail_response(user, roles, perms, last_login),
        meta=_build_metadata(request),
        error=None,
    )


@router.get(
    "/{user_id}",
    response_model=APIResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get User Account Details",
)
async def get_user_endpoint(
    request: Request,
    user_id: uuid.UUID,
    _current_user: Annotated[User, Depends(require_permission(PERMISSION_USERS_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserDetailResponse]:
    """Retrieve detailed user account information including roles and permissions."""
    detail = await get_user_detail(db, user_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} was not found.",
        )
    user, roles, perms, last_login = detail
    return APIResponse[UserDetailResponse](
        data=_to_detail_response(user, roles, perms, last_login),
        meta=_build_metadata(request),
        error=None,
    )


@router.patch(
    "/{user_id}",
    response_model=APIResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Update User Account",
)
async def update_user_endpoint(
    request: Request,
    user_id: uuid.UUID,
    payload: UserAdminUpdateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_USERS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserDetailResponse]:
    """Update user account attributes and role assignments under administrative control."""
    user, roles, perms, last_login = await update_admin_user(
        db=db,
        actor=current_user,
        target_user_id=user_id,
        payload=payload,
        request_meta=_extract_meta(request),
    )
    return APIResponse[UserDetailResponse](
        data=_to_detail_response(user, roles, perms, last_login),
        meta=_build_metadata(request),
        error=None,
    )


@router.post(
    "/{user_id}/status",
    response_model=APIResponse[UserDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Set User Active Status",
)
async def set_user_status_endpoint(
    request: Request,
    user_id: uuid.UUID,
    payload: UserStatusUpdateRequest,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_USERS_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[UserDetailResponse]:
    """Activate or deactivate a user account. Deactivation immediately revokes active sessions."""
    user, roles, perms, last_login = await set_user_status(
        db=db,
        actor=current_user,
        target_user_id=user_id,
        is_active=payload.is_active,
        request_meta=_extract_meta(request),
    )
    return APIResponse[UserDetailResponse](
        data=_to_detail_response(user, roles, perms, last_login),
        meta=_build_metadata(request),
        error=None,
    )


@router.delete(
    "/{user_id}",
    response_model=APIResponse[dict[str, str]],
    status_code=status.HTTP_200_OK,
    summary="Delete User Account",
)
async def delete_user_endpoint(
    request: Request,
    user_id: uuid.UUID,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_USERS_DELETE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[dict[str, str]]:
    """Delete a user account, enforcing last-admin and forensic preservation."""
    await delete_admin_user(
        db=db,
        actor=current_user,
        target_user_id=user_id,
        request_meta=_extract_meta(request),
    )
    return APIResponse[dict[str, str]](
        data={"message": "User account successfully deleted."},
        meta=_build_metadata(request),
        error=None,
    )

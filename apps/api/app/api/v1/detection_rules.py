"""Detection Rules Management API Endpoints (Phase 9).

Provides:
- GET /api/v1/detection-rules: List detection rules with bounded pagination
- POST /api/v1/detection-rules: Author a new detection rule
- POST /api/v1/detection-rules/validate: Dry-run validation endpoint
- GET /api/v1/detection-rules/{rule_id}: Get active or latest rule definition
- GET /api/v1/detection-rules/{rule_id}/versions: Get version history
- POST /api/v1/detection-rules/{rule_id}/versions: Author new version draft
- GET /api/v1/detection-rules/{rule_id}/versions/{version}: Get specific version definition
- PUT /api/v1/detection-rules/{rule_id}/versions/{version}: Edit DRAFT version definition
- POST /api/v1/detection-rules/{rule_id}/versions/{version}/activate: Activate version
- POST /api/v1/detection-rules/{rule_id}/versions/{version}/disable: Disable active version
- POST /api/v1/detection-rules/{rule_id}/versions/{version}/deprecate: Deprecate version
"""

import math
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_permission
from app.core.rbac import (
    PERMISSION_DETECTION_RULES_ACTIVATE,
    PERMISSION_DETECTION_RULES_CREATE,
    PERMISSION_DETECTION_RULES_DEPRECATE,
    PERMISSION_DETECTION_RULES_DISABLE,
    PERMISSION_DETECTION_RULES_READ,
    PERMISSION_DETECTION_RULES_UPDATE,
)
from app.db.session import get_db
from app.detection.validator import RuleValidationError, validate_detection_rule
from app.models.auth import User
from app.models.detection import DetectionRule
from app.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleDetailResponse,
    DetectionRuleListResponse,
    DetectionRuleUpdate,
    DetectionRuleValidationRequest,
    DetectionRuleValidationResponse,
    DetectionRuleVersionCreate,
    DetectionRuleVersionSummary,
)
from app.schemas.response import APIResponse, ResponseMetadata
from app.services.detection_rule import (
    RuleConflictError,
    RuleImmutabilityError,
    RuleLifecycleError,
    RuleNotFoundError,
    RuleVersionNotFoundError,
    activate_rule_version,
    create_detection_rule,
    create_rule_version,
    deprecate_rule_version,
    disable_rule_version,
    get_active_or_latest_rule,
    get_rule_by_id_and_version,
    get_rule_versions,
    list_detection_rules,
    update_draft_rule,
)

router = APIRouter(prefix="/detection-rules", tags=["Detection Rules"])


def _build_metadata(request: Request) -> ResponseMetadata:
    request_id = getattr(request.state, "request_id", "unknown")
    return ResponseMetadata(
        timestamp=datetime.now(UTC).isoformat(),
        request_id=str(request_id),
    )


def _ensure_timezone(rule: DetectionRule) -> None:
    """Ensure all datetime fields on a DetectionRule are timezone-aware UTC."""
    if rule.created_at.tzinfo is None:
        rule.created_at = rule.created_at.replace(tzinfo=UTC)
    if rule.updated_at.tzinfo is None:
        rule.updated_at = rule.updated_at.replace(tzinfo=UTC)
    if rule.activated_at and rule.activated_at.tzinfo is None:
        rule.activated_at = rule.activated_at.replace(tzinfo=UTC)


@router.get(
    "",
    response_model=APIResponse[DetectionRuleListResponse],
    status_code=status.HTTP_200_OK,
    summary="List Detection Rules",
)
async def get_detection_rules(
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
    page: int = Query(default=1, ge=1, description="Page number"),
    limit: int = Query(default=50, ge=1, le=500, description="Items per page (max 500)"),
    rule_id: str | None = Query(default=None, description="Filter by stable rule ID"),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        description="Filter by rule status (DRAFT, ACTIVE, DISABLED, DEPRECATED)",
    ),
    severity: str | None = Query(default=None, description="Filter by rule severity"),
    category: str | None = Query(default=None, description="Filter by rule category"),
    event_type: str | None = Query(default=None, description="Filter by canonical event type"),
    active_only: bool = Query(default=False, description="Filter for ACTIVE rules only"),
) -> APIResponse[DetectionRuleListResponse]:
    """Retrieve paginated detection rules with deterministic sorting."""
    rules, total = await list_detection_rules(
        db=db,
        page=page,
        limit=limit,
        rule_id=rule_id,
        status=status_filter,
        severity=severity,
        category=category,
        event_type=event_type,
        active_only=active_only,
    )

    for r in rules:
        _ensure_timezone(r)

    total_pages = math.ceil(total / limit) if total > 0 else 1
    return APIResponse(
        data=DetectionRuleListResponse(
            items=[DetectionRuleDetailResponse.model_validate(r) for r in rules],
            total=total,
            page=page,
            limit=limit,
            total_pages=total_pages,
        ),
        meta=_build_metadata(request),
    )


@router.post(
    "",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create Detection Rule",
)
async def post_detection_rule(
    payload: DetectionRuleCreate,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Author a new detection rule. Always initializes as version 1 in DRAFT status."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    try:
        rule = await create_detection_rule(
            db=db,
            payload=payload,
            creator_id=current_user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        _ensure_timezone(rule)
        return APIResponse(
            data=DetectionRuleDetailResponse.model_validate(rule),
            meta=_build_metadata(request),
        )
    except RuleConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation failed: {'; '.join(exc.errors)}",
        ) from exc


@router.post(
    "/validate",
    response_model=APIResponse[DetectionRuleValidationResponse],
    status_code=status.HTTP_200_OK,
    summary="Validate Detection Rule Configuration",
)
async def validate_rule_dry_run(
    payload: DetectionRuleValidationRequest,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_READ))],
) -> APIResponse[DetectionRuleValidationResponse]:
    """Dry-run validation of a detection rule definition without database persistence."""
    data = payload.model_dump(exclude_unset=True)
    is_valid, errors = validate_detection_rule(data)
    return APIResponse(
        data=DetectionRuleValidationResponse(valid=is_valid, errors=errors),
        meta=_build_metadata(request),
    )


@router.get(
    "/{rule_id}",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Detection Rule",
)
async def get_detection_rule(
    rule_id: str,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Retrieve active version of a rule if available, otherwise highest version."""
    rule = await get_active_or_latest_rule(db, rule_id)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with identifier '{rule_id}' not found.",
        )
    _ensure_timezone(rule)
    return APIResponse(
        data=DetectionRuleDetailResponse.model_validate(rule),
        meta=_build_metadata(request),
    )


@router.get(
    "/{rule_id}/versions",
    response_model=APIResponse[list[DetectionRuleVersionSummary]],
    status_code=status.HTTP_200_OK,
    summary="Get Rule Version History",
)
async def get_rule_version_history(
    rule_id: str,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[list[DetectionRuleVersionSummary]]:
    """Retrieve chronological version history for a stable rule identifier."""
    versions = await get_rule_versions(db, rule_id)
    if not versions:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule with identifier '{rule_id}' not found.",
        )
    for v in versions:
        _ensure_timezone(v)
    return APIResponse(
        data=[DetectionRuleVersionSummary.model_validate(v) for v in versions],
        meta=_build_metadata(request),
    )


@router.post(
    "/{rule_id}/versions",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create New Rule Version",
)
async def post_rule_version(
    rule_id: str,
    payload: DetectionRuleVersionCreate,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_CREATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Create a new version draft for an existing rule, incrementing from the highest version."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    try:
        new_version = await create_rule_version(
            db=db,
            rule_id=rule_id,
            payload=payload,
            creator_id=current_user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        _ensure_timezone(new_version)
        return APIResponse(
            data=DetectionRuleDetailResponse.model_validate(new_version),
            meta=_build_metadata(request),
        )
    except RuleNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation failed: {'; '.join(exc.errors)}",
        ) from exc


@router.get(
    "/{rule_id}/versions/{version}",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Specific Rule Version",
)
async def get_specific_rule_version(
    rule_id: str,
    version: int,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_READ))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Fetch exact rule definition for stable rule_id and version integer."""
    rule = await get_rule_by_id_and_version(db, rule_id, version)
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' version {version} not found.",
        )
    _ensure_timezone(rule)
    return APIResponse(
        data=DetectionRuleDetailResponse.model_validate(rule),
        meta=_build_metadata(request),
    )


@router.put(
    "/{rule_id}/versions/{version}",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Update Draft Rule Version",
)
async def put_draft_rule(
    rule_id: str,
    version: int,
    payload: DetectionRuleUpdate,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_UPDATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Modify an existing DRAFT version.

    Strictly rejected if rule is ACTIVE, DISABLED, or DEPRECATED.
    """
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    try:
        updated = await update_draft_rule(
            db=db,
            rule_id=rule_id,
            version=version,
            payload=payload,
            updater_id=current_user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        _ensure_timezone(updated)
        return APIResponse(
            data=DetectionRuleDetailResponse.model_validate(updated),
            meta=_build_metadata(request),
        )
    except RuleVersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuleImmutabilityError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation failed: {'; '.join(exc.errors)}",
        ) from exc


@router.post(
    "/{rule_id}/versions/{version}/activate",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Activate Rule Version",
)
async def post_activate_rule(
    rule_id: str,
    version: int,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_ACTIVATE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Promote rule version to ACTIVE status. Atomically deactivates any existing active version."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    try:
        activated = await activate_rule_version(
            db=db,
            rule_id=rule_id,
            version=version,
            activator_id=current_user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        _ensure_timezone(activated)
        return APIResponse(
            data=DetectionRuleDetailResponse.model_validate(activated),
            meta=_build_metadata(request),
        )
    except RuleVersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuleLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except RuleValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Validation failed: {'; '.join(exc.errors)}",
        ) from exc


@router.post(
    "/{rule_id}/versions/{version}/disable",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Disable Rule Version",
)
async def post_disable_rule(
    rule_id: str,
    version: int,
    request: Request,
    current_user: Annotated[User, Depends(require_permission(PERMISSION_DETECTION_RULES_DISABLE))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Transition ACTIVE rule version to DISABLED."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    try:
        disabled = await disable_rule_version(
            db=db,
            rule_id=rule_id,
            version=version,
            user_id=current_user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        _ensure_timezone(disabled)
        return APIResponse(
            data=DetectionRuleDetailResponse.model_validate(disabled),
            meta=_build_metadata(request),
        )
    except RuleVersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuleLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post(
    "/{rule_id}/versions/{version}/deprecate",
    response_model=APIResponse[DetectionRuleDetailResponse],
    status_code=status.HTTP_200_OK,
    summary="Deprecate Rule Version",
)
async def post_deprecate_rule(
    rule_id: str,
    version: int,
    request: Request,
    current_user: Annotated[
        User, Depends(require_permission(PERMISSION_DETECTION_RULES_DEPRECATE))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> APIResponse[DetectionRuleDetailResponse]:
    """Permanently retire a rule version to DEPRECATED terminal status."""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("User-Agent")
    request_id = getattr(request.state, "request_id", None)

    try:
        deprecated = await deprecate_rule_version(
            db=db,
            rule_id=rule_id,
            version=version,
            user_id=current_user.id,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
        )
        _ensure_timezone(deprecated)
        return APIResponse(
            data=DetectionRuleDetailResponse.model_validate(deprecated),
            meta=_build_metadata(request),
        )
    except RuleVersionNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RuleLifecycleError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

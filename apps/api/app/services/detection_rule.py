"""Detection Rule Management & Lifecycle Service (Phase 9).

Coordinates:
- Structured rule creation and versioning
- Strict immutability of published rules (only DRAFT can be modified)
- Deterministic lifecycle state machine (DRAFT -> ACTIVE -> DISABLED -> DEPRECATED)
- Single active version per rule_id transaction invariant
- Deep server-side validation against injection and resource exhaustion
- Append-only audit logging of all state mutations
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detection.validator import RuleValidationError, validate_detection_rule
from app.models.detection import DetectionRule
from app.schemas.detection_rule import (
    DetectionRuleCreate,
    DetectionRuleUpdate,
    DetectionRuleVersionCreate,
)
from app.services.auth import record_audit_log

# Lifecycle Status Constants
STATUS_DRAFT = "DRAFT"
STATUS_ACTIVE = "ACTIVE"
STATUS_DISABLED = "DISABLED"
STATUS_DEPRECATED = "DEPRECATED"

VALID_STATUSES = {STATUS_DRAFT, STATUS_ACTIVE, STATUS_DISABLED, STATUS_DEPRECATED}

VALID_TRANSITIONS: dict[str, set[str]] = {
    STATUS_DRAFT: {STATUS_ACTIVE, STATUS_DEPRECATED},
    STATUS_ACTIVE: {STATUS_DISABLED, STATUS_DEPRECATED},
    STATUS_DISABLED: {STATUS_ACTIVE, STATUS_DEPRECATED},
    STATUS_DEPRECATED: set(),  # Terminal state
}


class RuleNotFoundError(Exception):
    """Raised when stable rule identifier is not found."""


class RuleVersionNotFoundError(Exception):
    """Raised when specific rule version is not found."""


class RuleConflictError(Exception):
    """Raised when attempting to create a duplicate rule identifier or version."""


class RuleLifecycleError(Exception):
    """Raised when an invalid state transition is requested."""


class RuleImmutabilityError(Exception):
    """Raised when attempting to modify a published (non-DRAFT) rule version."""


async def list_detection_rules(
    db: AsyncSession,
    *,
    page: int = 1,
    limit: int = 50,
    rule_id: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    event_type: str | None = None,
    active_only: bool = False,
) -> tuple[list[DetectionRule], int]:
    """Return paginated detection rules matching query filters with deterministic sorting."""
    stmt = select(DetectionRule)

    if rule_id:
        stmt = stmt.where(DetectionRule.rule_id == rule_id)
    if status:
        stmt = stmt.where(DetectionRule.status == status)
    elif active_only:
        stmt = stmt.where(DetectionRule.status == STATUS_ACTIVE)
    if severity:
        stmt = stmt.where(DetectionRule.severity == severity.upper())
    if category:
        stmt = stmt.where(DetectionRule.category == category)
    if event_type:
        stmt = stmt.where(DetectionRule.event_type == event_type)

    count_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(count_stmt)).scalar() or 0

    offset = (page - 1) * limit
    stmt = (
        stmt.order_by(DetectionRule.rule_id.asc(), DetectionRule.version.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(stmt)
    rules = list(result.scalars().all())

    return rules, total


async def get_rule_by_id_and_version(
    db: AsyncSession, rule_id: str, version: int
) -> DetectionRule | None:
    """Fetch exact rule version by stable rule_id and version integer."""
    stmt = select(DetectionRule).where(
        DetectionRule.rule_id == rule_id,
        DetectionRule.version == version,
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def get_active_or_latest_rule(db: AsyncSession, rule_id: str) -> DetectionRule | None:
    """Fetch active version for rule_id if one exists, otherwise highest version."""
    # 1. Prefer ACTIVE version
    active_stmt = select(DetectionRule).where(
        DetectionRule.rule_id == rule_id,
        DetectionRule.status == STATUS_ACTIVE,
    )
    active = (await db.execute(active_stmt)).scalar_one_or_none()
    if active is not None:
        return active

    # 2. Fall back to highest version
    latest_stmt = (
        select(DetectionRule)
        .where(DetectionRule.rule_id == rule_id)
        .order_by(DetectionRule.version.desc())
        .limit(1)
    )
    return (await db.execute(latest_stmt)).scalar_one_or_none()


async def get_rule_versions(db: AsyncSession, rule_id: str) -> list[DetectionRule]:
    """Fetch all version records for a stable rule identifier, ordered newest first."""
    stmt = (
        select(DetectionRule)
        .where(DetectionRule.rule_id == rule_id)
        .order_by(DetectionRule.version.desc())
    )
    return list((await db.execute(stmt)).scalars().all())


async def create_detection_rule(
    db: AsyncSession,
    payload: DetectionRuleCreate,
    creator_id: uuid.UUID,
    *,
    client_ip: str = "unknown",
    user_agent: str | None = None,
    request_id: str | None = None,
) -> DetectionRule:
    """Author a new detection rule. Always initializes as version 1 in DRAFT status."""
    # 1. Check for identifier collision
    existing = await get_active_or_latest_rule(db, payload.rule_id)
    if existing is not None:
        raise RuleConflictError(
            f"Rule with ID '{payload.rule_id}' already exists. "
            "Use the versions endpoint to author subsequent versions."
        )

    # 2. Validate structured payload
    rule_dict = payload.model_dump()
    rule_dict["version"] = 1
    is_valid, errors = validate_detection_rule(rule_dict)
    if not is_valid:
        raise RuleValidationError(errors)

    # 3. Instantiate model
    rule = DetectionRule(
        rule_id=payload.rule_id,
        version=1,
        name=payload.name,
        description=payload.description,
        severity=payload.severity.upper(),
        category=payload.category,
        status=STATUS_DRAFT,
        enabled=False,
        event_type=payload.event_type,
        threshold=payload.threshold,
        time_window_seconds=payload.time_window_seconds,
        conditions=payload.conditions,
        created_by=creator_id,
        updated_by=creator_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # 4. Audit
    await record_audit_log(
        db=db,
        action="RULE_CREATED",
        actor_user_id=creator_id,
        resource_type="detection_rule",
        resource_id=f"{rule.rule_id}:v1",
        new_value={
            "rule_id": rule.rule_id,
            "version": 1,
            "name": rule.name,
            "status": STATUS_DRAFT,
            "severity": rule.severity,
            "threshold": rule.threshold,
            "time_window_seconds": rule.time_window_seconds,
        },
        source_ip=client_ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    return rule


async def create_rule_version(
    db: AsyncSession,
    rule_id: str,
    payload: DetectionRuleVersionCreate,
    creator_id: uuid.UUID,
    *,
    client_ip: str = "unknown",
    user_agent: str | None = None,
    request_id: str | None = None,
) -> DetectionRule:
    """Create a new version draft for an existing rule, incrementing from the highest version."""
    # 1. Fetch current latest version to inherit defaults
    latest = await get_active_or_latest_rule(db, rule_id)
    if latest is None:
        raise RuleNotFoundError(f"Rule with identifier '{rule_id}' was not found.")

    versions = await get_rule_versions(db, rule_id)
    next_version = max(v.version for v in versions) + 1

    # 2. Merge attributes
    name = payload.name if payload.name is not None else latest.name
    description = payload.description if payload.description is not None else latest.description
    severity = payload.severity.upper() if payload.severity is not None else latest.severity
    category = payload.category if payload.category is not None else latest.category
    event_type = payload.event_type if payload.event_type is not None else latest.event_type
    threshold = payload.threshold if payload.threshold is not None else latest.threshold
    time_window = (
        payload.time_window_seconds
        if payload.time_window_seconds is not None
        else latest.time_window_seconds
    )
    conditions = payload.conditions if payload.conditions is not None else dict(latest.conditions)

    candidate = {
        "rule_id": rule_id,
        "version": next_version,
        "name": name,
        "description": description,
        "severity": severity,
        "category": category,
        "event_type": event_type,
        "threshold": threshold,
        "time_window_seconds": time_window,
        "conditions": conditions,
    }

    # 3. Validate
    is_valid, errors = validate_detection_rule(candidate)
    if not is_valid:
        raise RuleValidationError(errors)

    # 4. Instantiate new version in DRAFT
    new_rule = DetectionRule(
        rule_id=rule_id,
        version=next_version,
        name=name,
        description=description,
        severity=severity,
        category=category,
        status=STATUS_DRAFT,
        enabled=False,
        event_type=event_type,
        threshold=threshold,
        time_window_seconds=time_window,
        conditions=conditions,
        created_by=creator_id,
        updated_by=creator_id,
    )
    db.add(new_rule)
    await db.commit()
    await db.refresh(new_rule)

    # 5. Audit
    await record_audit_log(
        db=db,
        action="RULE_VERSION_CREATED",
        actor_user_id=creator_id,
        resource_type="detection_rule",
        resource_id=f"{new_rule.rule_id}:v{next_version}",
        new_value={
            "rule_id": new_rule.rule_id,
            "version": next_version,
            "name": new_rule.name,
            "status": STATUS_DRAFT,
            "threshold": new_rule.threshold,
            "time_window_seconds": new_rule.time_window_seconds,
        },
        source_ip=client_ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    return new_rule


async def update_draft_rule(
    db: AsyncSession,
    rule_id: str,
    version: int,
    payload: DetectionRuleUpdate,
    updater_id: uuid.UUID,
    *,
    client_ip: str = "unknown",
    user_agent: str | None = None,
    request_id: str | None = None,
) -> DetectionRule:
    """Modify a DRAFT rule version. Strictly rejected if rule is ACTIVE, DISABLED, or DEPRECATED."""
    rule = await get_rule_by_id_and_version(db, rule_id, version)
    if rule is None:
        raise RuleVersionNotFoundError(f"Detection rule '{rule_id}' version {version} not found.")

    # Enforce Immutability: only DRAFT may be modified
    if rule.status != STATUS_DRAFT:
        raise RuleImmutabilityError(
            f"Cannot modify rule in '{rule.status}' status. "
            "Published rules are strictly immutable; author a new version to modify logic."
        )

    old_dict = {
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "threshold": rule.threshold,
        "time_window_seconds": rule.time_window_seconds,
        "conditions": dict(rule.conditions),
    }

    # Apply updates
    if payload.name is not None:
        rule.name = payload.name
    if payload.description is not None:
        rule.description = payload.description
    if payload.severity is not None:
        rule.severity = payload.severity.upper()
    if payload.category is not None:
        rule.category = payload.category
    if payload.event_type is not None:
        rule.event_type = payload.event_type
    if payload.threshold is not None:
        rule.threshold = payload.threshold
    if payload.time_window_seconds is not None:
        rule.time_window_seconds = payload.time_window_seconds
    if payload.conditions is not None:
        rule.conditions = payload.conditions

    # Validate updated definition
    candidate = {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "category": rule.category,
        "event_type": rule.event_type,
        "threshold": rule.threshold,
        "time_window_seconds": rule.time_window_seconds,
        "conditions": rule.conditions,
    }
    is_valid, errors = validate_detection_rule(candidate)
    if not is_valid:
        raise RuleValidationError(errors)

    rule.updated_at = datetime.now(UTC)
    rule.updated_by = updater_id
    await db.commit()
    await db.refresh(rule)

    await record_audit_log(
        db=db,
        action="RULE_UPDATED",
        actor_user_id=updater_id,
        resource_type="detection_rule",
        resource_id=f"{rule.rule_id}:v{rule.version}",
        old_value=old_dict,
        new_value={
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity,
            "threshold": rule.threshold,
            "time_window_seconds": rule.time_window_seconds,
            "conditions": rule.conditions,
        },
        source_ip=client_ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    return rule


async def activate_rule_version(
    db: AsyncSession,
    rule_id: str,
    version: int,
    activator_id: uuid.UUID,
    *,
    client_ip: str = "unknown",
    user_agent: str | None = None,
    request_id: str | None = None,
) -> DetectionRule:
    """Activate a rule version.

    Validates state transition, re-validates rule logic, atomically displaces/disables
    any currently active version of this rule_id, and activates the target version.
    """
    rule = await get_rule_by_id_and_version(db, rule_id, version)
    if rule is None:
        raise RuleVersionNotFoundError(f"Detection rule '{rule_id}' version {version} not found.")

    # 1. Validate State Machine Transition
    if rule.status == STATUS_ACTIVE:
        raise RuleLifecycleError(f"Rule '{rule_id}' version {version} is already in ACTIVE status.")
    if STATUS_ACTIVE not in VALID_TRANSITIONS.get(rule.status, set()):
        raise RuleLifecycleError(
            f"Invalid state transition: cannot activate rule in '{rule.status}' status."
        )

    # 2. Validate Rule Configuration Prior to Activation
    candidate = {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "category": rule.category,
        "event_type": rule.event_type,
        "threshold": rule.threshold,
        "time_window_seconds": rule.time_window_seconds,
        "conditions": rule.conditions,
    }
    is_valid, errors = validate_detection_rule(candidate)
    if not is_valid:
        raise RuleValidationError(errors)

    now = datetime.now(UTC)
    displaced_version: int | None = None

    # 3. Atomic Single Active Version Invariant Enforcement
    async with db.begin_nested():
        # Find any existing active version for this rule_id
        active_stmt = select(DetectionRule).where(
            DetectionRule.rule_id == rule_id,
            DetectionRule.status == STATUS_ACTIVE,
        )
        current_active = (await db.execute(active_stmt)).scalar_one_or_none()
        if current_active is not None and current_active.id != rule.id:
            displaced_version = current_active.version
            current_active.status = STATUS_DISABLED
            current_active.enabled = False
            current_active.updated_at = now
            current_active.updated_by = activator_id
            await db.flush()

        # Promote target rule to ACTIVE
        rule.status = STATUS_ACTIVE
        rule.enabled = True
        rule.activated_at = now
        rule.activated_by = activator_id
        rule.updated_at = now
        rule.updated_by = activator_id

    await db.commit()
    await db.refresh(rule)

    # 4. Audit
    audit_meta: dict[str, Any] = {
        "rule_id": rule.rule_id,
        "version": rule.version,
        "status": STATUS_ACTIVE,
    }
    if displaced_version is not None:
        audit_meta["displaced_version"] = displaced_version

    await record_audit_log(
        db=db,
        action="RULE_ACTIVATED",
        actor_user_id=activator_id,
        resource_type="detection_rule",
        resource_id=f"{rule.rule_id}:v{rule.version}",
        new_value=audit_meta,
        source_ip=client_ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    return rule


async def disable_rule_version(
    db: AsyncSession,
    rule_id: str,
    version: int,
    user_id: uuid.UUID,
    *,
    client_ip: str = "unknown",
    user_agent: str | None = None,
    request_id: str | None = None,
) -> DetectionRule:
    """Transition an ACTIVE rule version to DISABLED."""
    rule = await get_rule_by_id_and_version(db, rule_id, version)
    if rule is None:
        raise RuleVersionNotFoundError(f"Detection rule '{rule_id}' version {version} not found.")

    if rule.status == STATUS_DISABLED:
        raise RuleLifecycleError(
            f"Rule '{rule_id}' version {version} is already in DISABLED status."
        )
    if STATUS_DISABLED not in VALID_TRANSITIONS.get(rule.status, set()):
        raise RuleLifecycleError(
            f"Invalid state transition: cannot disable rule in '{rule.status}' status."
        )

    now = datetime.now(UTC)
    rule.status = STATUS_DISABLED
    rule.enabled = False
    rule.updated_at = now
    rule.updated_by = user_id
    await db.commit()
    await db.refresh(rule)

    await record_audit_log(
        db=db,
        action="RULE_DISABLED",
        actor_user_id=user_id,
        resource_type="detection_rule",
        resource_id=f"{rule.rule_id}:v{rule.version}",
        new_value={"status": STATUS_DISABLED, "enabled": False},
        source_ip=client_ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    return rule


async def deprecate_rule_version(
    db: AsyncSession,
    rule_id: str,
    version: int,
    user_id: uuid.UUID,
    *,
    client_ip: str = "unknown",
    user_agent: str | None = None,
    request_id: str | None = None,
) -> DetectionRule:
    """Permanently retire a rule version to DEPRECATED terminal status."""
    rule = await get_rule_by_id_and_version(db, rule_id, version)
    if rule is None:
        raise RuleVersionNotFoundError(f"Detection rule '{rule_id}' version {version} not found.")

    if rule.status == STATUS_DEPRECATED:
        raise RuleLifecycleError(
            f"Rule '{rule_id}' version {version} is already in DEPRECATED status."
        )
    if STATUS_DEPRECATED not in VALID_TRANSITIONS.get(rule.status, set()):
        raise RuleLifecycleError(
            f"Invalid state transition: cannot deprecate rule in '{rule.status}' status."
        )

    now = datetime.now(UTC)
    rule.status = STATUS_DEPRECATED
    rule.enabled = False
    rule.updated_at = now
    rule.updated_by = user_id
    await db.commit()
    await db.refresh(rule)

    await record_audit_log(
        db=db,
        action="RULE_DEPRECATED",
        actor_user_id=user_id,
        resource_type="detection_rule",
        resource_id=f"{rule.rule_id}:v{rule.version}",
        new_value={"status": STATUS_DEPRECATED, "enabled": False},
        source_ip=client_ip,
        user_agent=user_agent,
        request_id=request_id,
    )

    return rule

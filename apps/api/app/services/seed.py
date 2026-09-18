"""Deterministic Database Seed Service for RBAC and Initial Admin Provisioning.

Ensures idempotent bootstrapping of roles, permissions, role-permission mappings,
and an initial administrative account without creating duplicate rows or exposing
public registration routes.
"""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rbac import DEFAULT_PERMISSIONS, DEFAULT_ROLE_PERMISSIONS, ROLE_ADMIN, SYSTEM_ROLES
from app.core.security import get_password_hash
from app.models import DetectionRule, Permission, Role, RolePermission, User, UserRole

logger = logging.getLogger("sentinelforge.seed")


async def seed_roles_and_permissions(db: AsyncSession) -> dict[str, int]:
    """Bootstrap system roles and permissions idempotently."""
    created_permissions = 0
    created_roles = 0
    created_mappings = 0

    # 1. Seed Permissions
    permissions_map: dict[str, Permission] = {}
    for perm_name, perm_desc in DEFAULT_PERMISSIONS.items():
        perm_stmt = select(Permission).where(Permission.name == perm_name)
        existing = (await db.execute(perm_stmt)).scalar_one_or_none()
        if not existing:
            perm = Permission(name=perm_name, description=perm_desc)
            db.add(perm)
            await db.flush()
            permissions_map[perm_name] = perm
            created_permissions += 1
        else:
            permissions_map[perm_name] = existing

    # 2. Seed Roles
    roles_map: dict[str, Role] = {}
    for role_name in SYSTEM_ROLES:
        role_stmt = select(Role).where(Role.name == role_name)
        existing_role = (await db.execute(role_stmt)).scalar_one_or_none()
        if not existing_role:
            role = Role(name=role_name, description=f"Default system {role_name} role")
            db.add(role)
            await db.flush()
            roles_map[role_name] = role
            created_roles += 1
        else:
            roles_map[role_name] = existing_role

    # 3. Seed Role-Permission Associations
    for role_name, perm_names in DEFAULT_ROLE_PERMISSIONS.items():
        role = roles_map[role_name]
        for perm_name in perm_names:
            perm = permissions_map[perm_name]
            map_stmt = select(RolePermission).where(
                RolePermission.role_id == role.id,
                RolePermission.permission_id == perm.id,
            )
            existing_mapping = (await db.execute(map_stmt)).scalar_one_or_none()
            if not existing_mapping:
                mapping = RolePermission(role_id=role.id, permission_id=perm.id)
                db.add(mapping)
                created_mappings += 1

    await db.commit()
    logger.info(
        f"Seeded RBAC baseline: {created_permissions} new permissions, "
        f"{created_roles} new roles, {created_mappings} new role-permission bindings."
    )
    return {
        "permissions": created_permissions,
        "roles": created_roles,
        "mappings": created_mappings,
    }


async def seed_initial_admin(
    db: AsyncSession,
    username: str = "admin",
    email: str = "admin@sentinelforge.local",
    password: str = "AdminSentinel_2026_Secure!",  # noqa: S107
) -> User:
    """Bootstrap the initial administrative account if no admin exists.

    Uses Argon2id password hashing and binds the ADMIN role.
    """
    await seed_roles_and_permissions(db)

    stmt = select(User).where(User.username == username)
    existing_user = (await db.execute(stmt)).scalar_one_or_none()
    if existing_user:
        return existing_user

    # Create new administrator
    admin_user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        full_name="Default SentinelForge Administrator",
        is_active=True,
        is_superuser=True,
    )
    db.add(admin_user)
    await db.flush()

    # Assign ADMIN role
    role_stmt = select(Role).where(Role.name == ROLE_ADMIN)
    admin_role = (await db.execute(role_stmt)).scalar_one()

    user_role = UserRole(user_id=admin_user.id, role_id=admin_role.id)
    db.add(user_role)
    await db.commit()

    logger.info(f"Initialized administrative user: {username}")
    return admin_user


DEFAULT_DETECTION_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "RULE-001",
        "version": 1,
        "name": "Brute Force Login",
        "description": (
            "Detects repeated authentication failures originating from a single source IP address "
            "within a compressed time window, indicating an automated password guessing or "
            "credential brute-force attack."
        ),
        "severity": "HIGH",
        "category": "authentication",
        "status": "ACTIVE",
        "enabled": True,
        "event_type": "authentication",
        "threshold": 5,
        "time_window_seconds": 300,
        "conditions": {"action": "login_failed", "group_by": "source_ip"},
    },
    {
        "rule_id": "RULE-002",
        "version": 1,
        "name": "Targeted Account Password Spray",
        "description": (
            "Detects a high volume of failed authentication attempts against a specific username "
            "regardless of source IP variation, indicating targeted credential stuffing or "
            "account lock attack."
        ),
        "severity": "HIGH",
        "category": "authentication",
        "status": "ACTIVE",
        "enabled": True,
        "event_type": "authentication",
        "threshold": 10,
        "time_window_seconds": 600,
        "conditions": {"action": "login_failed", "group_by": "username"},
    },
    {
        "rule_id": "RULE-003",
        "version": 1,
        "name": "Suspicious Login Following Failures",
        "description": (
            "Detects an authentication success preceded by multiple authentication failures "
            "from the same source IP within a short sliding window, signaling a potentially "
            "successful brute-force or credential compromise."
        ),
        "severity": "HIGH",
        "category": "authentication",
        "status": "ACTIVE",
        "enabled": True,
        "event_type": "authentication",
        "threshold": 3,
        "time_window_seconds": 600,
        "conditions": {
            "triggering_action": "login_success",
            "preceding_action": "login_failed",
            "group_by": "source_ip",
        },
    },
    {
        "rule_id": "RULE-004",
        "version": 1,
        "name": "HTTP Authentication Abuse",
        "description": (
            "Detects repeated HTTP 401 Unauthorized responses emitted by web application logs "
            "from a single client IP, indicating API token brute-force or unauthorized web "
            "endpoint enumeration."
        ),
        "severity": "MEDIUM",
        "category": "web",
        "status": "ACTIVE",
        "enabled": True,
        "event_type": "web",
        "threshold": 15,
        "time_window_seconds": 300,
        "conditions": {"action": "http_401", "group_by": "source_ip"},
    },
    {
        "rule_id": "RULE-005",
        "version": 1,
        "name": "Network Port Scan Pattern",
        "description": (
            "Detects connection attempts from a single source IP targeting multiple distinct "
            "destination ports within a short period, characteristic of reconnaissance and "
            "port scanning tools (e.g. Nmap, Masscan)."
        ),
        "severity": "HIGH",
        "category": "network",
        "status": "ACTIVE",
        "enabled": True,
        "event_type": "network",
        "threshold": 10,
        "time_window_seconds": 120,
        "conditions": {
            "action": "connection_attempt",
            "group_by": "source_ip",
            "distinct_field": "destination_port",
        },
    },
]


async def seed_detection_rules(db: AsyncSession) -> int:
    """Bootstrap default detection rules idempotently into detection_rules table."""
    created_count = 0
    for rule_data in DEFAULT_DETECTION_RULES:
        rule_id = str(rule_data["rule_id"])
        version = int(rule_data["version"])
        stmt = select(DetectionRule).where(
            DetectionRule.rule_id == rule_id,
            DetectionRule.version == version,
        )
        existing = (await db.execute(stmt)).scalar_one_or_none()
        if not existing:
            rule = DetectionRule(
                rule_id=rule_id,
                version=version,
                name=str(rule_data["name"]),
                description=str(rule_data["description"]),
                severity=str(rule_data["severity"]),
                category=str(rule_data.get("category", "security")),
                status=str(rule_data.get("status", "ACTIVE")),
                enabled=bool(rule_data["enabled"]),
                event_type=str(rule_data["event_type"]),
                threshold=int(rule_data["threshold"]),
                time_window_seconds=int(rule_data["time_window_seconds"]),
                conditions=dict(rule_data["conditions"]),
            )
            db.add(rule)
            created_count += 1

    if created_count > 0:
        await db.commit()
        logger.info(f"Seeded {created_count} default detection rules.")
    return created_count


async def seed_rbac_and_admin(db: AsyncSession) -> bool:
    """Bootstrap full RBAC catalog, admin account, and default detection rules idempotently."""
    await seed_roles_and_permissions(db)
    await seed_initial_admin(db)
    await seed_detection_rules(db)
    return True

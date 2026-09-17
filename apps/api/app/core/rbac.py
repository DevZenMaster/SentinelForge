"""Role-Based Access Control (RBAC) Constants and Permissions Mapping.

Defines the system roles (ADMIN, ANALYST, VIEWER) and the granular permissions
governing security operations in SentinelForge.
"""

from typing import Final

# System Roles
ROLE_ADMIN: Final[str] = "ADMIN"
ROLE_ANALYST: Final[str] = "ANALYST"
ROLE_VIEWER: Final[str] = "VIEWER"

SYSTEM_ROLES: Final[list[str]] = [ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER]

# Granular System Permissions
PERMISSION_USERS_READ: Final[str] = "users.read"
PERMISSION_USERS_CREATE: Final[str] = "users.create"
PERMISSION_USERS_UPDATE: Final[str] = "users.update"
PERMISSION_USERS_DELETE: Final[str] = "users.delete"

PERMISSION_EVENTS_READ: Final[str] = "events.read"
PERMISSION_EVENTS_CREATE: Final[str] = "events.create"

PERMISSION_ALERTS_READ: Final[str] = "alerts.read"
PERMISSION_ALERTS_UPDATE: Final[str] = "alerts.update"

PERMISSION_INCIDENTS_READ: Final[str] = "incidents.read"
PERMISSION_INCIDENTS_CREATE: Final[str] = "incidents.create"
PERMISSION_INCIDENTS_UPDATE: Final[str] = "incidents.update"

PERMISSION_RULES_READ: Final[str] = "rules.read"
PERMISSION_RULES_CREATE: Final[str] = "rules.create"
PERMISSION_RULES_UPDATE: Final[str] = "rules.update"

PERMISSION_AUDIT_READ: Final[str] = "audit.read"

# Permission catalog with human-readable descriptions
DEFAULT_PERMISSIONS: Final[dict[str, str]] = {
    PERMISSION_USERS_READ: "Read user accounts and role assignments",
    PERMISSION_USERS_CREATE: "Create new user accounts",
    PERMISSION_USERS_UPDATE: "Update user accounts and role bindings",
    PERMISSION_USERS_DELETE: "Deactivate or remove user accounts",
    PERMISSION_EVENTS_READ: "Search and inspect normalized security events",
    PERMISSION_EVENTS_CREATE: "Ingest and submit security events to the SIEM pipeline",
    PERMISSION_ALERTS_READ: "View detection alerts and evidence links",
    PERMISSION_ALERTS_UPDATE: "Triage and update alert lifecycle status",
    PERMISSION_INCIDENTS_READ: "View security incident tickets and timelines",
    PERMISSION_INCIDENTS_CREATE: "Escalate alerts and create incident cases",
    PERMISSION_INCIDENTS_UPDATE: "Update incident status, containment, and notes",
    PERMISSION_RULES_READ: "Inspect detection rules and threshold configurations",
    PERMISSION_RULES_CREATE: "Author and deploy new detection rules",
    PERMISSION_RULES_UPDATE: "Tune thresholds and enable/disable detection rules",
    PERMISSION_AUDIT_READ: "Inspect append-only security audit logs",
}

ALL_PERMISSIONS: Final[list[str]] = list(DEFAULT_PERMISSIONS.keys())

# Role to Permission default matrices
DEFAULT_ROLE_PERMISSIONS: Final[dict[str, list[str]]] = {
    ROLE_ADMIN: [
        PERMISSION_USERS_READ,
        PERMISSION_USERS_CREATE,
        PERMISSION_USERS_UPDATE,
        PERMISSION_USERS_DELETE,
        PERMISSION_EVENTS_READ,
        PERMISSION_EVENTS_CREATE,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_UPDATE,
        PERMISSION_INCIDENTS_READ,
        PERMISSION_INCIDENTS_CREATE,
        PERMISSION_INCIDENTS_UPDATE,
        PERMISSION_RULES_READ,
        PERMISSION_RULES_CREATE,
        PERMISSION_RULES_UPDATE,
        PERMISSION_AUDIT_READ,
    ],
    ROLE_ANALYST: [
        PERMISSION_EVENTS_READ,
        PERMISSION_EVENTS_CREATE,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_UPDATE,
        PERMISSION_INCIDENTS_READ,
        PERMISSION_INCIDENTS_CREATE,
        PERMISSION_INCIDENTS_UPDATE,
        PERMISSION_RULES_READ,
        PERMISSION_RULES_UPDATE,
        PERMISSION_AUDIT_READ,
    ],
    ROLE_VIEWER: [
        PERMISSION_EVENTS_READ,
        PERMISSION_ALERTS_READ,
        PERMISSION_INCIDENTS_READ,
    ],
}

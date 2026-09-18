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
PERMISSION_EVENTS_NORMALIZE: Final[str] = "events.normalize"

PERMISSION_ALERTS_READ: Final[str] = "alerts.read"
PERMISSION_ALERTS_UPDATE: Final[str] = "alerts.update"
PERMISSION_ALERTS_ACKNOWLEDGE: Final[str] = "alerts.acknowledge"
PERMISSION_ALERTS_ASSIGN: Final[str] = "alerts.assign"
PERMISSION_ALERTS_TRIAGE: Final[str] = "alerts.triage"
PERMISSION_ALERTS_SUPPRESS: Final[str] = "alerts.suppress"
PERMISSION_ALERTS_RESOLVE: Final[str] = "alerts.resolve"
PERMISSION_ALERTS_CLOSE: Final[str] = "alerts.close"
PERMISSION_ALERTS_NOTES_READ: Final[str] = "alerts.notes.read"
PERMISSION_ALERTS_NOTES_CREATE: Final[str] = "alerts.notes.create"
PERMISSION_ALERTS_INVESTIGATIONS_READ: Final[str] = "alerts.investigations.read"
PERMISSION_ALERTS_INCIDENTS_READ: Final[str] = "alerts.incidents.read"

PERMISSION_INCIDENTS_READ: Final[str] = "incidents.read"
PERMISSION_INCIDENTS_CREATE: Final[str] = "incidents.create"
PERMISSION_INCIDENTS_UPDATE: Final[str] = "incidents.update"
PERMISSION_INCIDENTS_CLOSE: Final[str] = "incidents.close"

PERMISSION_RULES_READ: Final[str] = "rules.read"
PERMISSION_RULES_CREATE: Final[str] = "rules.create"
PERMISSION_RULES_UPDATE: Final[str] = "rules.update"

PERMISSION_DETECTION_RULES_READ: Final[str] = "detection_rules.read"
PERMISSION_DETECTION_RULES_CREATE: Final[str] = "detection_rules.create"
PERMISSION_DETECTION_RULES_UPDATE: Final[str] = "detection_rules.update"
PERMISSION_DETECTION_RULES_ACTIVATE: Final[str] = "detection_rules.activate"
PERMISSION_DETECTION_RULES_DISABLE: Final[str] = "detection_rules.disable"
PERMISSION_DETECTION_RULES_DEPRECATE: Final[str] = "detection_rules.deprecate"

PERMISSION_DETECTIONS_EVALUATE: Final[str] = "detections.evaluate"

PERMISSION_INTELLIGENCE_READ: Final[str] = "intelligence.read"
PERMISSION_INTELLIGENCE_CREATE: Final[str] = "intelligence.create"
PERMISSION_INTELLIGENCE_UPDATE: Final[str] = "intelligence.update"
PERMISSION_INTELLIGENCE_DELETE: Final[str] = "intelligence.delete"

PERMISSION_INVESTIGATIONS_READ: Final[str] = "investigations.read"

PERMISSION_AUDIT_READ: Final[str] = "audit.read"

PERMISSION_REPORTS_READ: Final[str] = "reports.read"
PERMISSION_REPORTS_EXPORT: Final[str] = "reports.export"
PERMISSION_REPORTS_AUDIT: Final[str] = "reports.audit"

PERMISSION_INTEGRATIONS_READ: Final[str] = "integrations.read"
PERMISSION_INTEGRATIONS_CREATE: Final[str] = "integrations.create"
PERMISSION_INTEGRATIONS_UPDATE: Final[str] = "integrations.update"
PERMISSION_INTEGRATIONS_ENABLE: Final[str] = "integrations.enable"
PERMISSION_INTEGRATIONS_DISABLE: Final[str] = "integrations.disable"
PERMISSION_INTEGRATIONS_DELETE: Final[str] = "integrations.delete"

PERMISSION_NOTIFICATION_POLICIES_READ: Final[str] = "notification_policies.read"
PERMISSION_NOTIFICATION_POLICIES_CREATE: Final[str] = "notification_policies.create"
PERMISSION_NOTIFICATION_POLICIES_UPDATE: Final[str] = "notification_policies.update"
PERMISSION_NOTIFICATION_POLICIES_ENABLE: Final[str] = "notification_policies.enable"
PERMISSION_NOTIFICATION_POLICIES_DISABLE: Final[str] = "notification_policies.disable"

PERMISSION_NOTIFICATIONS_READ: Final[str] = "notifications.read"
PERMISSION_NOTIFICATIONS_RETRY: Final[str] = "notifications.retry"
PERMISSION_NOTIFICATIONS_CANCEL: Final[str] = "notifications.cancel"

# Permission catalog with human-readable descriptions
DEFAULT_PERMISSIONS: Final[dict[str, str]] = {
    PERMISSION_USERS_READ: "Read user accounts and role assignments",
    PERMISSION_USERS_CREATE: "Create new user accounts",
    PERMISSION_USERS_UPDATE: "Update user accounts and role bindings",
    PERMISSION_USERS_DELETE: "Deactivate or remove user accounts",
    PERMISSION_EVENTS_READ: "Search and inspect normalized security events",
    PERMISSION_EVENTS_CREATE: "Ingest and submit security events to the SIEM pipeline",
    PERMISSION_EVENTS_NORMALIZE: "Reprocess event normalization and parser evaluation",
    PERMISSION_ALERTS_READ: "View detection alerts and evidence links",
    PERMISSION_ALERTS_UPDATE: "Triage and update alert lifecycle status",
    PERMISSION_ALERTS_ACKNOWLEDGE: "Acknowledge active detection alerts",
    PERMISSION_ALERTS_ASSIGN: "Assign, reassign, or unassign alerts to analysts",
    PERMISSION_ALERTS_TRIAGE: "Perform alert triage and status transitions",
    PERMISSION_ALERTS_SUPPRESS: "Suppress detection alerts with bounded reasons",
    PERMISSION_ALERTS_RESOLVE: "Resolve detection alerts with mandatory notes",
    PERMISSION_ALERTS_CLOSE: "Close or reopen detection alerts",
    PERMISSION_ALERTS_NOTES_READ: "Read analyst triage notes on alerts",
    PERMISSION_ALERTS_NOTES_CREATE: "Append analyst triage notes to alerts",
    PERMISSION_ALERTS_INVESTIGATIONS_READ: "Inspect correlated investigations for alerts",
    PERMISSION_ALERTS_INCIDENTS_READ: "View linked incidents and escalate alerts",
    PERMISSION_INCIDENTS_READ: "View security incident tickets and timelines",
    PERMISSION_INCIDENTS_CREATE: "Escalate alerts and create incident cases",
    PERMISSION_INCIDENTS_UPDATE: "Update incident status, containment, and notes",
    PERMISSION_INCIDENTS_CLOSE: "Close or reopen security incidents",
    PERMISSION_RULES_READ: "Inspect detection rules and threshold configurations",
    PERMISSION_RULES_CREATE: "Author and deploy new detection rules",
    PERMISSION_RULES_UPDATE: "Tune thresholds and enable/disable detection rules",
    PERMISSION_DETECTION_RULES_READ: "Inspect detection rules and version histories",
    PERMISSION_DETECTION_RULES_CREATE: "Author new detection rules and drafts",
    PERMISSION_DETECTION_RULES_UPDATE: "Modify draft detection rule definitions",
    PERMISSION_DETECTION_RULES_ACTIVATE: "Activate detection rule versions into production",
    PERMISSION_DETECTION_RULES_DISABLE: "Deactivate active detection rule versions",
    PERMISSION_DETECTION_RULES_DEPRECATE: "Permanently deprecate detection rule versions",
    PERMISSION_DETECTIONS_EVALUATE: "Manually trigger detection rule evaluation on security events",
    PERMISSION_INTELLIGENCE_READ: "Search and view threat indicators and intelligence records",
    PERMISSION_INTELLIGENCE_CREATE: "Submit threat indicators and intelligence records",
    PERMISSION_INTELLIGENCE_UPDATE: "Modify indicator status and intelligence records",
    PERMISSION_INTELLIGENCE_DELETE: "Deactivate or remove threat intelligence records",
    PERMISSION_INVESTIGATIONS_READ: (
        "Execute cross-entity correlation queries and view investigation analytics"
    ),
    PERMISSION_AUDIT_READ: "Inspect append-only security audit logs",
    PERMISSION_REPORTS_READ: (
        "View security operations reports, historical metrics, and compliance evidence"
    ),
    PERMISSION_REPORTS_EXPORT: "Export security reports to CSV and JSON formats",
    PERMISSION_REPORTS_AUDIT: (
        "Access sensitive security audit trails and analyst activity reports"
    ),
    PERMISSION_INTEGRATIONS_READ: "View external integration destinations and statuses",
    PERMISSION_INTEGRATIONS_CREATE: "Create new external integration destinations",
    PERMISSION_INTEGRATIONS_UPDATE: "Update external integration endpoints and configurations",
    PERMISSION_INTEGRATIONS_ENABLE: "Enable external integration delivery destinations",
    PERMISSION_INTEGRATIONS_DISABLE: "Disable external integration delivery destinations",
    PERMISSION_INTEGRATIONS_DELETE: "Remove external integration destinations",
    PERMISSION_NOTIFICATION_POLICIES_READ: (
        "View declarative notification policies and routing rules"
    ),
    PERMISSION_NOTIFICATION_POLICIES_CREATE: "Create new notification policies and rules",
    PERMISSION_NOTIFICATION_POLICIES_UPDATE: "Modify notification policies and filter criteria",
    PERMISSION_NOTIFICATION_POLICIES_ENABLE: "Enable notification policies",
    PERMISSION_NOTIFICATION_POLICIES_DISABLE: "Disable notification policies",
    PERMISSION_NOTIFICATIONS_READ: "Inspect notification delivery logs and attempt histories",
    PERMISSION_NOTIFICATIONS_RETRY: (
        "Manually re-dispatch failed or exhausted notification deliveries"
    ),
    PERMISSION_NOTIFICATIONS_CANCEL: "Cancel pending or retrying notification deliveries",
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
        PERMISSION_EVENTS_NORMALIZE,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_UPDATE,
        PERMISSION_ALERTS_ACKNOWLEDGE,
        PERMISSION_ALERTS_ASSIGN,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_ALERTS_SUPPRESS,
        PERMISSION_ALERTS_RESOLVE,
        PERMISSION_ALERTS_CLOSE,
        PERMISSION_ALERTS_NOTES_READ,
        PERMISSION_ALERTS_NOTES_CREATE,
        PERMISSION_ALERTS_INVESTIGATIONS_READ,
        PERMISSION_ALERTS_INCIDENTS_READ,
        PERMISSION_INCIDENTS_READ,
        PERMISSION_INCIDENTS_CREATE,
        PERMISSION_INCIDENTS_UPDATE,
        PERMISSION_INCIDENTS_CLOSE,
        PERMISSION_RULES_READ,
        PERMISSION_RULES_CREATE,
        PERMISSION_RULES_UPDATE,
        PERMISSION_DETECTION_RULES_READ,
        PERMISSION_DETECTION_RULES_CREATE,
        PERMISSION_DETECTION_RULES_UPDATE,
        PERMISSION_DETECTION_RULES_ACTIVATE,
        PERMISSION_DETECTION_RULES_DISABLE,
        PERMISSION_DETECTION_RULES_DEPRECATE,
        PERMISSION_DETECTIONS_EVALUATE,
        PERMISSION_INTELLIGENCE_READ,
        PERMISSION_INTELLIGENCE_CREATE,
        PERMISSION_INTELLIGENCE_UPDATE,
        PERMISSION_INTELLIGENCE_DELETE,
        PERMISSION_INVESTIGATIONS_READ,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
        PERMISSION_REPORTS_EXPORT,
        PERMISSION_REPORTS_AUDIT,
        PERMISSION_INTEGRATIONS_READ,
        PERMISSION_INTEGRATIONS_CREATE,
        PERMISSION_INTEGRATIONS_UPDATE,
        PERMISSION_INTEGRATIONS_ENABLE,
        PERMISSION_INTEGRATIONS_DISABLE,
        PERMISSION_INTEGRATIONS_DELETE,
        PERMISSION_NOTIFICATION_POLICIES_READ,
        PERMISSION_NOTIFICATION_POLICIES_CREATE,
        PERMISSION_NOTIFICATION_POLICIES_UPDATE,
        PERMISSION_NOTIFICATION_POLICIES_ENABLE,
        PERMISSION_NOTIFICATION_POLICIES_DISABLE,
        PERMISSION_NOTIFICATIONS_READ,
        PERMISSION_NOTIFICATIONS_RETRY,
        PERMISSION_NOTIFICATIONS_CANCEL,
    ],
    ROLE_ANALYST: [
        PERMISSION_EVENTS_READ,
        PERMISSION_EVENTS_CREATE,
        PERMISSION_EVENTS_NORMALIZE,
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_UPDATE,
        PERMISSION_ALERTS_ACKNOWLEDGE,
        PERMISSION_ALERTS_ASSIGN,
        PERMISSION_ALERTS_TRIAGE,
        PERMISSION_ALERTS_SUPPRESS,
        PERMISSION_ALERTS_RESOLVE,
        PERMISSION_ALERTS_CLOSE,
        PERMISSION_ALERTS_NOTES_READ,
        PERMISSION_ALERTS_NOTES_CREATE,
        PERMISSION_ALERTS_INVESTIGATIONS_READ,
        PERMISSION_ALERTS_INCIDENTS_READ,
        PERMISSION_INCIDENTS_READ,
        PERMISSION_INCIDENTS_CREATE,
        PERMISSION_INCIDENTS_UPDATE,
        PERMISSION_RULES_READ,
        PERMISSION_RULES_UPDATE,
        PERMISSION_DETECTION_RULES_READ,
        PERMISSION_DETECTION_RULES_CREATE,
        PERMISSION_DETECTION_RULES_UPDATE,
        PERMISSION_DETECTION_RULES_ACTIVATE,
        PERMISSION_DETECTION_RULES_DISABLE,
        PERMISSION_DETECTIONS_EVALUATE,
        PERMISSION_INTELLIGENCE_READ,
        PERMISSION_INTELLIGENCE_CREATE,
        PERMISSION_INTELLIGENCE_UPDATE,
        PERMISSION_INVESTIGATIONS_READ,
        PERMISSION_AUDIT_READ,
        PERMISSION_REPORTS_READ,
        PERMISSION_REPORTS_EXPORT,
        PERMISSION_REPORTS_AUDIT,
        PERMISSION_INTEGRATIONS_READ,
        PERMISSION_NOTIFICATION_POLICIES_READ,
        PERMISSION_NOTIFICATIONS_READ,
        PERMISSION_NOTIFICATIONS_RETRY,
        PERMISSION_NOTIFICATIONS_CANCEL,
    ],
    ROLE_VIEWER: [
        PERMISSION_ALERTS_READ,
        PERMISSION_ALERTS_NOTES_READ,
        PERMISSION_ALERTS_INVESTIGATIONS_READ,
        PERMISSION_ALERTS_INCIDENTS_READ,
        PERMISSION_INCIDENTS_READ,
        PERMISSION_DETECTION_RULES_READ,
        PERMISSION_INTELLIGENCE_READ,
        PERMISSION_INVESTIGATIONS_READ,
        PERMISSION_REPORTS_READ,
        PERMISSION_NOTIFICATIONS_READ,
    ],
}

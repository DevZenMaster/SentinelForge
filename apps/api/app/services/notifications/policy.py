"""Declarative Notification Policy Evaluation Engine (Phase 13).

Evaluates incoming authoritative security operations events against configured
notification policies using deterministic allowlists, strict severity hierarchies,
and declarative field matchers.
"""

import threading
import time
import uuid
from typing import Any

from app.models.notification import NotificationEvent, NotificationPolicy

SEVERITY_HIERARCHY: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}

# In-memory cooldown tracking: policy_id -> last_fired_epoch_seconds
_cooldown_lock = threading.Lock()
_policy_last_fired: dict[uuid.UUID, float] = {}


def clear_policy_cooldowns() -> None:
    """Clear cooldown cache (used in testing)."""
    with _cooldown_lock:
        _policy_last_fired.clear()


def evaluate_policy_match(
    event: NotificationEvent,
    policy: NotificationPolicy,
) -> bool:
    """Evaluate whether an authoritative event matches policy routing criteria.

    Returns True if the event matches all criteria and satisfies cooldown constraints.
    """
    if not policy.enabled:
        return False

    # 1. Event Type Matching
    if event.event_type not in policy.event_types:
        return False

    payload = event.payload or {}

    # 2. Minimum Severity Check (if specified)
    if policy.min_severity:
        min_level = SEVERITY_HIERARCHY.get(policy.min_severity.upper(), 0)
        event_sev = payload.get("severity")
        if isinstance(event_sev, str):
            event_level = SEVERITY_HIERARCHY.get(event_sev.upper(), 0)
            if event_level < min_level:
                return False
        else:
            # Event does not carry severity; fail-closed if policy mandates a min severity
            return False

    # 3. Declarative Filter Matching
    filters: dict[str, Any] = policy.filters or {}
    for key, expected in filters.items():
        actual = payload.get(key)
        if expected is None:
            continue

        if isinstance(expected, list):
            # IN condition
            if actual not in expected:
                return False
        elif actual != expected:
            return False

    # 4. Cooldown Enforcement
    if policy.cooldown_seconds > 0:
        now = time.time()
        with _cooldown_lock:
            last_fired = _policy_last_fired.get(policy.id, 0.0)
            if now - last_fired < policy.cooldown_seconds:
                return False
            # Record execution
            _policy_last_fired[policy.id] = now

    return True

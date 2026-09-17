"""Detection Rule Registry.

Maintains the runtime catalog of active detection rules. Provides lookup by
rule ID, filtering by target event type, and inspection capabilities.
"""

import logging

from app.detection.base import BaseDetectionRule
from app.detection.rules import (
    Rule001BruteForceLogin,
    Rule002AccountSpray,
    Rule003SuspiciousLoginFollowingFailures,
    Rule004HttpAuthAbuse,
    Rule005PortScan,
)

logger = logging.getLogger("sentinelforge.detection")


class RuleRegistry:
    """Registry maintaining active detection rules."""

    def __init__(self) -> None:
        self._rules: dict[str, BaseDetectionRule] = {}

    def register(self, rule: BaseDetectionRule) -> None:
        """Register a detection rule in the active catalog."""
        self._rules[rule.rule_id] = rule

    def get_rule(self, rule_id: str) -> BaseDetectionRule | None:
        """Look up a detection rule by its identifier."""
        return self._rules.get(rule_id)

    def get_rules_for_event(self, event_type: str) -> list[BaseDetectionRule]:
        """Return all rules applicable to the given canonical event type."""
        return [rule for rule in self._rules.values() if rule.event_type == event_type]

    def list_rules(self) -> list[BaseDetectionRule]:
        """Return all registered rules in insertion order."""
        return list(self._rules.values())


def build_default_rule_registry() -> RuleRegistry:
    """Instantiate and populate the default production rule catalog."""
    registry = RuleRegistry()
    registry.register(Rule001BruteForceLogin())
    registry.register(Rule002AccountSpray())
    registry.register(Rule003SuspiciousLoginFollowingFailures())
    registry.register(Rule004HttpAuthAbuse())
    registry.register(Rule005PortScan())
    return registry


default_rule_registry = build_default_rule_registry()

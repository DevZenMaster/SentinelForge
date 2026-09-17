"""Detection Rules Catalog.

Exports all built-in deterministic detection rules:
- RULE-001: Rule001BruteForceLogin
- RULE-002: Rule002AccountSpray
- RULE-003: Rule003SuspiciousLoginFollowingFailures
- RULE-004: Rule004HttpAuthAbuse
- RULE-005: Rule005PortScan
"""

from app.detection.rules.rule_001 import Rule001BruteForceLogin
from app.detection.rules.rule_002 import Rule002AccountSpray
from app.detection.rules.rule_003 import Rule003SuspiciousLoginFollowingFailures
from app.detection.rules.rule_004 import Rule004HttpAuthAbuse
from app.detection.rules.rule_005 import Rule005PortScan

__all__ = [
    "Rule001BruteForceLogin",
    "Rule002AccountSpray",
    "Rule003SuspiciousLoginFollowingFailures",
    "Rule004HttpAuthAbuse",
    "Rule005PortScan",
]

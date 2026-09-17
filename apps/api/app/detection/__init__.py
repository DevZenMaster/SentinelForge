"""Detection Engine Package.

Exports:
- DetectionEngine and default_detection_engine
- BaseDetectionRule
- RuleRegistry and default_rule_registry
- DetectionResult, DetectionContext, RuleEvaluationError
- calculate_dedup_key
"""

from app.detection.base import BaseDetectionRule
from app.detection.deduplication import calculate_dedup_key
from app.detection.engine import DetectionEngine, default_detection_engine
from app.detection.models import DetectionContext, DetectionResult, RuleEvaluationError
from app.detection.registry import RuleRegistry, default_rule_registry

__all__ = [
    "BaseDetectionRule",
    "DetectionContext",
    "DetectionEngine",
    "DetectionResult",
    "RuleEvaluationError",
    "RuleRegistry",
    "calculate_dedup_key",
    "default_detection_engine",
    "default_rule_registry",
]

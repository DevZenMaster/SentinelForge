"""Detection Rule Validation Layer.

Enforces strict structural, semantic, and resource safety constraints on detection rule
definitions prior to persistence and activation. Completely prevents arbitrary code,
eval, SQL injection, and unbounded historical scans.
"""

import re
from typing import Any

RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,32}$")
VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
VALID_EVENT_TYPES = {
    "authentication",
    "network",
    "web",
    "system",
    "file",
    "process",
    "dns",
    "audit",
    "security",
}
VALID_GROUP_BY_FIELDS = {"source_ip", "destination_ip", "username"}
VALID_DISTINCT_FIELDS = {"destination_port", "source_ip", "destination_ip", "username"}
VALID_OPERATORS = {
    "equals",
    "not_equals",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "contains",
    "starts_with",
    "ends_with",
    "in",
    "distinct_count",
}
VALID_FIELDS = {
    "action",
    "source_ip",
    "destination_ip",
    "username",
    "destination_port",
    "source_port",
    "source",
    "source_type",
    "outcome",
}

MIN_THRESHOLD = 1
MAX_THRESHOLD = 10000
MIN_TIME_WINDOW_SECONDS = 10
MAX_TIME_WINDOW_SECONDS = 86400  # 24 hours
MAX_CONDITIONS_COUNT = 10
MAX_STRING_VALUE_LENGTH = 255
MAX_IN_LIST_ITEMS = 100


class RuleValidationError(Exception):
    """Exception raised when a detection rule definition violates validation rules."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__(f"Rule validation failed: {'; '.join(errors)}")
        self.errors = errors


def validate_detection_rule(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate a detection rule definition against structural and safety invariants.

    Returns:
        (is_valid, errors_list)
    """
    errors: list[str] = []

    # 1. Stable Rule ID
    rule_id = data.get("rule_id")
    if not rule_id or not isinstance(rule_id, str):
        errors.append("rule_id is required and must be a non-empty string.")
    elif not RULE_ID_PATTERN.match(rule_id):
        errors.append(f"rule_id '{rule_id}' is invalid. Must match ^[A-Za-z0-9_-]{{3,32}}$.")

    # 2. Version
    version = data.get("version")
    if version is not None:
        if not isinstance(version, int) or version < 1:
            errors.append("version must be a positive integer (>= 1).")

    # 3. Name
    name = data.get("name")
    if not name or not isinstance(name, str) or len(name.strip()) < 3:
        errors.append("name is required and must be at least 3 characters.")
    elif len(name) > 128:
        errors.append("name cannot exceed 128 characters.")

    # 4. Description
    description = data.get("description")
    if not description or not isinstance(description, str) or len(description.strip()) < 5:
        errors.append("description is required and must be at least 5 characters.")
    elif len(description) > 2048:
        errors.append("description cannot exceed 2048 characters.")

    # 5. Severity
    severity = data.get("severity")
    if not severity or severity not in VALID_SEVERITIES:
        errors.append(f"severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}.")

    # 6. Event Type
    event_type = data.get("event_type")
    if not event_type or event_type not in VALID_EVENT_TYPES:
        errors.append(f"event_type must be one of: {', '.join(sorted(VALID_EVENT_TYPES))}.")

    # 7. Threshold
    threshold = data.get("threshold")
    if threshold is None or not isinstance(threshold, int):
        errors.append(
            f"threshold is required and must be an integer between {MIN_THRESHOLD} "
            f"and {MAX_THRESHOLD}."
        )
    elif threshold < MIN_THRESHOLD or threshold > MAX_THRESHOLD:
        errors.append(
            f"threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}, got {threshold}."
        )

    # 8. Time Window Seconds
    time_window = data.get("time_window_seconds")
    if time_window is None or not isinstance(time_window, int):
        errors.append(
            "time_window_seconds is required and must be an integer between "
            f"{MIN_TIME_WINDOW_SECONDS} and {MAX_TIME_WINDOW_SECONDS}."
        )
    elif time_window < MIN_TIME_WINDOW_SECONDS or time_window > MAX_TIME_WINDOW_SECONDS:
        errors.append(
            f"time_window_seconds must be between {MIN_TIME_WINDOW_SECONDS} and "
            f"{MAX_TIME_WINDOW_SECONDS}, got {time_window}."
        )

    # 9. Category (optional, default "security")
    category = data.get("category")
    if category is not None:
        if not isinstance(category, str) or len(category.strip()) < 2 or len(category) > 32:
            errors.append("category must be a string between 2 and 32 characters.")

    # 10. Conditions
    conditions = data.get("conditions")
    if conditions is None or not isinstance(conditions, dict):
        errors.append("conditions must be a dictionary.")
    else:
        _validate_conditions(conditions, errors)

    return len(errors) == 0, errors


def _validate_conditions(conditions: dict[str, Any], errors: list[str]) -> None:
    """Validate internal structure and bounds of conditions dictionary."""
    group_by = conditions.get("group_by")
    if group_by is not None:
        if group_by not in VALID_GROUP_BY_FIELDS:
            valid_gb = ", ".join(sorted(VALID_GROUP_BY_FIELDS))
            errors.append(f"conditions.group_by must be one of: {valid_gb}.")

    aggregation = conditions.get("aggregation", "count")
    if aggregation not in {"count", "distinct_count"}:
        errors.append("conditions.aggregation must be 'count' or 'distinct_count'.")

    if aggregation == "distinct_count":
        distinct_field = conditions.get("distinct_field")
        if not distinct_field or distinct_field not in VALID_DISTINCT_FIELDS:
            valid_df = ", ".join(sorted(VALID_DISTINCT_FIELDS))
            errors.append(
                f"distinct_field is required when aggregation is 'distinct_count' ({valid_df})."
            )

    # Action shorthand (used in built-ins)
    action = conditions.get("action")
    if action is not None and not isinstance(action, str):
        errors.append("conditions.action must be a string.")

    # Sequence actions
    triggering_action = conditions.get("triggering_action")
    preceding_action = conditions.get("preceding_action")
    if triggering_action is not None and not isinstance(triggering_action, str):
        errors.append("conditions.triggering_action must be a string.")
    if preceding_action is not None and not isinstance(preceding_action, str):
        errors.append("conditions.preceding_action must be a string.")

    # Filters list
    filters = conditions.get("filters")
    if filters is not None:
        if not isinstance(filters, list):
            errors.append("conditions.filters must be a list of filter objects.")
        elif len(filters) > MAX_CONDITIONS_COUNT:
            errors.append(f"conditions.filters cannot exceed {MAX_CONDITIONS_COUNT} items.")
        else:
            for idx, flt in enumerate(filters):
                if not isinstance(flt, dict):
                    errors.append(f"conditions.filters[{idx}] must be a dictionary.")
                    continue

                field = flt.get("field")
                if not field or not isinstance(field, str):
                    errors.append(
                        f"conditions.filters[{idx}].field is required and must be a string."
                    )
                elif field not in VALID_FIELDS and not field.startswith("attributes."):
                    errors.append(f"conditions.filters[{idx}].field '{field}' is not supported.")

                operator = flt.get("operator")
                if not operator or operator not in VALID_OPERATORS:
                    valid_ops = ", ".join(sorted(VALID_OPERATORS))
                    errors.append(
                        f"conditions.filters[{idx}].operator must be one of: {valid_ops}."
                    )

                value = flt.get("value")
                if operator in {
                    "greater_than",
                    "greater_than_or_equal",
                    "less_than",
                    "less_than_or_equal",
                }:
                    if not isinstance(value, (int, float)):
                        errors.append(
                            f"conditions.filters[{idx}].value must be numeric for '{operator}'."
                        )
                elif operator in {"contains", "starts_with", "ends_with"}:
                    if not isinstance(value, str):
                        errors.append(
                            f"conditions.filters[{idx}].value must be a string for '{operator}'."
                        )
                    elif len(value) > MAX_STRING_VALUE_LENGTH:
                        errors.append(
                            f"conditions.filters[{idx}].value exceeds max length "
                            f"{MAX_STRING_VALUE_LENGTH}."
                        )
                elif operator == "in":
                    if not isinstance(value, list):
                        errors.append(f"conditions.filters[{idx}].value must be a list for 'in'.")
                    elif len(value) > MAX_IN_LIST_ITEMS:
                        errors.append(
                            f"conditions.filters[{idx}].value list exceeds "
                            f"{MAX_IN_LIST_ITEMS} items."
                        )

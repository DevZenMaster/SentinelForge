"""Deduplication Key Calculation for Detection Engine.

Generates deterministic, collision-resistant deduplication keys to coalesce
repeated alerts triggered for the same entity within active sliding time windows.
"""

from datetime import UTC, datetime


def calculate_dedup_key(
    rule_id: str,
    correlation_key: str,
    timestamp: datetime,
    window_seconds: int,
) -> str:
    """Calculate a deterministic alert deduplication key.

    Formula: {rule_id}:{correlation_key}:{bucket}
    where bucket = int(timestamp.timestamp() // max(window_seconds, 1))

    Args:
        rule_id: The unique identifier of the detection rule (e.g. RULE-001).
        correlation_key: The target pivot entity (e.g. IP address or username).
        timestamp: The event timestamp triggering the evaluation.
        window_seconds: The duration of the rule's sliding correlation window.

    Returns:
        str: Deterministic deduplication key formatted as {rule_id}:{correlation_key}:{bucket}
    """
    if timestamp.tzinfo is None:
        ts_utc = timestamp.replace(tzinfo=UTC)
    else:
        ts_utc = timestamp.astimezone(UTC)

    window = max(window_seconds, 1)
    bucket = int(ts_utc.timestamp() // window)
    return f"{rule_id}:{correlation_key}:{bucket}"

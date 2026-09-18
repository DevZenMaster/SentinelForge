"""Shared utilities, math helpers, and CSV sanitization for security reports."""

import statistics
from datetime import UTC, datetime
from typing import Any, Final

from app.schemas.reports import DurationMetric

DEFAULT_SLA_THRESHOLD_HOURS: Final[int] = 24


def to_utc(dt: datetime | None) -> datetime | None:
    """Ensure datetime is timezone-aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def calculate_duration_metric(durations: list[float]) -> DurationMetric:
    """Calculate statistical distribution metrics for duration samples in seconds.

    Missing timestamps are omitted from the calculation and reported separately,
    never converted to zero seconds.
    """
    if not durations:
        return DurationMetric(
            mean_seconds=None,
            median_seconds=None,
            min_seconds=None,
            max_seconds=None,
            sample_count=0,
        )

    return DurationMetric(
        mean_seconds=round(sum(durations) / len(durations), 2),
        median_seconds=round(float(statistics.median(durations)), 2),
        min_seconds=round(min(durations), 2),
        max_seconds=round(max(durations), 2),
        sample_count=len(durations),
    )


def sanitize_csv_value(val: Any) -> str:
    """Sanitize cell value for CSV serialization in accordance with CWE-1236.

    Prepends a single quote to any value whose string representation begins
    with formula initiation tokens ('=', '+', '-', '@', '\t', '\r') to neutralize
    arbitrary command or macro execution in spreadsheet software.
    """
    if val is None:
        return ""
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=UTC)
        return str(val.isoformat())
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        # For numeric values that are strictly negative numbers
        s_val = str(val)
        if s_val.startswith(("-", "+")):
            return f"'{s_val}"
        return s_val

    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s

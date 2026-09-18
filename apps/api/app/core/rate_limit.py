"""Authentication and API Rate Limiting Subsystem for SentinelForge.

Implements an in-memory sliding-window rate limiter protecting sensitive authentication
endpoints against brute-force and credential-stuffing attacks.

Note on multi-instance deployment:
This implementation maintains an in-memory sliding window per application process.
For distributed multi-worker or containerized deployments across multiple nodes,
a centralized cache backend (e.g., Redis) can be integrated in later phases without
changing the dependency injection interface.
"""

import threading
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from fastapi import HTTPException, Request, status

from app.core.config import settings


class InMemorySlidingWindowLimiter:
    """Thread-safe sliding window rate limiter tracking timestamps per key."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = defaultdict(list)

    def is_rate_limited(self, key: str, max_requests: int, window_seconds: int) -> tuple[bool, int]:
        """Evaluate if the key exceeded the allowable request count within the temporal window.

        Returns (is_limited, retry_after_seconds).
        """
        now = datetime.now(UTC).timestamp()
        window_start = now - window_seconds

        with self._lock:
            # Purge timestamps outside current evaluation window
            timestamps = self._events[key]
            valid_timestamps = [t for t in timestamps if t > window_start]
            self._events[key] = valid_timestamps

            if len(valid_timestamps) >= max_requests:
                earliest = valid_timestamps[0]
                retry_after = max(1, int(earliest + window_seconds - now))
                return True, retry_after

            # Record current access
            self._events[key].append(now)
            return False, 0

    def clear(self) -> None:
        """Reset all rate limiter tracking state (used in testing)."""
        with self._lock:
            self._events.clear()


# Global rate limiter instances
auth_rate_limiter = InMemorySlidingWindowLimiter()
event_rate_limiter = InMemorySlidingWindowLimiter()
notification_rate_limiter = InMemorySlidingWindowLimiter()


def enforce_event_ingest_rate_limit(request: Request, user_id: uuid.UUID | None = None) -> None:
    """Enforce rate limits on event ingestion endpoints by client IP and authenticated user.

    Raises HTTP 429 Too Many Requests if either the source IP or the authenticated user
    exceeds the configured EVENTS_RATE_LIMIT_PER_MINUTE threshold.
    """
    client_ip = request.client.host if request.client else "unknown"
    max_requests = settings.EVENTS_RATE_LIMIT_PER_MINUTE
    window_seconds = 60

    # 1. IP-based rate limiting
    is_limited, retry_after = event_rate_limiter.is_rate_limited(
        f"event:ip:{client_ip}", max_requests=max_requests, window_seconds=window_seconds
    )
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Event ingestion rate limit exceeded for IP. Please try again in "
                f"{retry_after} seconds."
            ),
            headers={"Retry-After": str(retry_after)},
        )

    # 2. User-based rate limiting
    if user_id:
        is_limited, retry_after = event_rate_limiter.is_rate_limited(
            f"event:user:{user_id}", max_requests=max_requests, window_seconds=window_seconds
        )
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Event ingestion rate limit exceeded for user. Please try again in "
                    f"{retry_after} seconds."
                ),
                headers={"Retry-After": str(retry_after)},
            )


def enforce_login_rate_limit(request: Request, identifier: str | None = None) -> None:
    """Enforce rate limits on login requests by client IP and target username.

    Raises HTTP 429 Too Many Requests if either the source IP or the targeted
    account identifier exceeds the configured authentication limit.
    """
    client_ip = request.client.host if request.client else "unknown"
    max_requests = settings.AUTH_RATE_LIMIT_PER_MINUTE
    window_seconds = 60

    # 1. IP-based check
    is_limited, retry_after = auth_rate_limiter.is_rate_limited(
        f"auth:ip:{client_ip}", max_requests=max_requests, window_seconds=window_seconds
    )
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                "Too many authentication attempts from this IP. "
                f"Please try again in {retry_after} seconds."
            ),
            headers={"Retry-After": str(retry_after)},
        )

    # 2. Targeted identifier check (prevent spraying same account across proxies)
    if identifier:
        clean_identifier = identifier.strip().lower()
        # Allow slightly more margin per account to prevent intentional DoS lockout
        ident_limit = max_requests * 2
        is_limited, retry_after = auth_rate_limiter.is_rate_limited(
            f"auth:user:{clean_identifier}",
            max_requests=ident_limit,
            window_seconds=window_seconds,
        )
        if is_limited:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Too many authentication attempts for this account. "
                    f"Please try again in {retry_after} seconds."
                ),
                headers={"Retry-After": str(retry_after)},
            )


def enforce_notification_rate_limit(
    request: Request,
    action: str = "general",
    user_id: uuid.UUID | None = None,
    max_requests: int = 30,
    window_seconds: int = 60,
) -> None:
    """Enforce rate limits on notification dispatch, testing, and management actions."""
    client_ip = request.client.host if request.client else "unknown"
    key = f"notify:{action}:{user_id or client_ip}"
    is_limited, retry_after = notification_rate_limiter.is_rate_limited(
        key, max_requests=max_requests, window_seconds=window_seconds
    )
    if is_limited:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=(
                f"Rate limit exceeded for notification action '{action}'. "
                f"Please try again in {retry_after} seconds."
            ),
            headers={"Retry-After": str(retry_after)},
        )

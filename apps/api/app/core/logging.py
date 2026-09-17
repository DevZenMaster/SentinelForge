"""Structured JSON application logging for SentinelForge.

Formats application logs as structured JSON containing timestamp, severity level,
service name, and contextual correlation/request IDs.
Never logs credentials, session secrets, or sensitive tokens.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any


class JSONLogFormatter(logging.Formatter):
    """Custom JSON formatter producing structured telemetry records."""

    # Explicit list of keys to redact if ever passed in extra/context
    REDACTED_KEYS = {
        "password",
        "secret",
        "secret_key",
        "token",
        "session_id",
        "authorization",
        "cookie",
        "api_key",
        "credentials",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": "sentinelforge-api",
        }

        # Attach request_id if present on record
        request_id = getattr(record, "request_id", None)
        if request_id:
            log_payload["request_id"] = str(request_id)

        # Attach user_id if present on record
        user_id = getattr(record, "user_id", None)
        if user_id:
            log_payload["user_id"] = str(user_id)

        # Include custom extra fields while sanitizing sensitive keys
        if hasattr(record, "extra_fields") and isinstance(record.extra_fields, dict):
            for k, v in record.extra_fields.items():
                if k.lower() in self.REDACTED_KEYS:
                    log_payload[k] = "[REDACTED]"
                else:
                    log_payload[k] = v

        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_payload, default=str)


def setup_logging(debug: bool = False) -> logging.Logger:
    """Initialize root and application loggers with JSON structured handler."""
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if debug else logging.INFO)

    # Remove pre-existing handlers to prevent duplicated output
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONLogFormatter())
    root_logger.addHandler(handler)

    # Silence overly noisy third-party libraries
    logging.getLogger("uvicorn.access").handlers = [handler]
    logging.getLogger("uvicorn.error").handlers = [handler]
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    return logging.getLogger("sentinelforge")

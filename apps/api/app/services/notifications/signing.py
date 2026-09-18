"""HMAC Request Signing and Verification Engine (Phase 13).

Computes deterministic HMAC-SHA256 signatures over outgoing webhook payloads,
enabling external consumers to authenticate that payloads originated from SentinelForge.
"""

import hashlib
import hmac


def generate_hmac_signature(secret: str, timestamp: str, raw_payload: str | bytes) -> str:
    """Generate deterministic HMAC-SHA256 hex digest signature.

    Canonical message format:
    timestamp + "." + raw_payload
    """
    if isinstance(raw_payload, str):
        payload_bytes = raw_payload.encode("utf-8")
    else:
        payload_bytes = raw_payload

    canonical_message = timestamp.encode("utf-8") + b"." + payload_bytes
    secret_bytes = secret.encode("utf-8")

    mac = hmac.new(secret_bytes, canonical_message, hashlib.sha256)
    return mac.hexdigest()


def verify_hmac_signature(
    secret: str,
    timestamp: str,
    raw_payload: str | bytes,
    signature: str,
) -> bool:
    """Verify an HMAC-SHA256 signature using constant-time comparison."""
    if not signature or not secret:
        return False
    expected = generate_hmac_signature(secret, timestamp, raw_payload)
    return hmac.compare_digest(expected, signature)

"""Cryptographic Security and Password Hashing Services for SentinelForge.

Implements Argon2id password hashing according to RFC 9106, cryptographically random
opaque session tokens, SHA-256 session token hashing, and constant-time token comparison.
Never logs or serializes plaintext credentials.
"""

import hashlib
import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Argon2id password hasher tuned to RFC 9106 recommended parameters
# (memory-hard, resistant to GPU attacks)
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


def get_password_hash(password: str) -> str:
    """Generate a secure Argon2id password hash with random salt."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash using constant-time comparison.

    Returns False on mismatch or corrupted hash without raising exceptions.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def generate_session_token() -> str:
    """Generate a cryptographically secure, 256-bit URL-safe opaque session token.

    This raw token is delivered strictly via HttpOnly cookie to the client.
    """
    return secrets.token_urlsafe(32)


def hash_session_token(token: str) -> str:
    """Hash raw session token using SHA-256 for persistent database lookup.

    Database stores exclusively this hash, ensuring stolen database backups cannot
    be used to hijack active user sessions.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_csrf_token() -> str:
    """Generate a cryptographically random anti-CSRF token."""
    return secrets.token_urlsafe(32)


def verify_csrf_token(token_a: str, token_b: str) -> bool:
    """Perform constant-time string comparison to defeat timing attacks on CSRF tokens."""
    return hmac.compare_digest(token_a, token_b)


# Convenience aliases
hash_password = get_password_hash
validate_csrf_token = verify_csrf_token

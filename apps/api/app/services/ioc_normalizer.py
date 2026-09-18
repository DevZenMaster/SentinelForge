"""Indicator of Compromise (IOC) Normalizer and Extractor.

Provides deterministic validation, canonical normalization, type inference,
and event extraction for security indicators:
- IP addresses (IPv4 & IPv6 with RFC canonicalization)
- Domain names (lowercase, FQDN cleanup, RFC 1035 label validation)
- URLs (RFC 3986 parsing, credential and default port stripping)
- Email addresses (RFC 5322 validation, local/domain lowercasing)
- Cryptographic file hashes (MD5, SHA1, SHA256 hex string validation)
"""

import ipaddress
import re
import string
import urllib.parse
from dataclasses import dataclass
from typing import Any

from app.models.indicator import IndicatorType

MAX_IOC_VALUE_LENGTH = 2048
HEX_CHARS = set(string.hexdigits.lower())

# Domain label regex: 1 to 63 chars, alphanumeric with optional hyphens in between
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

# Standard email regex: local@domain
EMAIL_PATTERN = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class IOCValidationError(ValueError):
    """Raised when an indicator value does not conform to its declared type specification."""


@dataclass(frozen=True)
class ExtractedIOC:
    """Forensic container for an indicator extracted from a security event."""

    type: IndicatorType
    raw_value: str
    normalized_value: str
    extracted_from_field: str


def normalize_ip(value: str) -> str:
    """Normalize and validate IPv4 or IPv6 address.

    Returns the compressed canonical string representation.
    Raises IOCValidationError if invalid.
    """
    cleaned = value.strip()
    if not cleaned or len(cleaned) > 45:
        raise IOCValidationError(f"Invalid IP address length: '{value}'")
    try:
        ip = ipaddress.ip_address(cleaned)
        return str(ip)
    except ValueError as err:
        raise IOCValidationError(f"Invalid IP address format '{value}': {err}") from err


def normalize_domain(value: str) -> str:
    """Normalize and validate domain name.

    Returns lowercase canonical domain with trailing root dot stripped.
    Raises IOCValidationError if invalid.
    """
    cleaned = value.strip().rstrip(".").lower()
    if not cleaned or len(cleaned) > 253:
        raise IOCValidationError(f"Invalid domain length: '{value}'")

    # Pure numeric strings or strings looking like IP addresses are not domain names
    try:
        ipaddress.ip_address(cleaned)
        raise IOCValidationError(f"IP address '{value}' cannot be classified as a domain")
    except ValueError:
        pass

    labels = cleaned.split(".")
    if len(labels) < 2:
        raise IOCValidationError(f"Domain must contain at least two labels: '{value}'")

    for label in labels:
        if not label or len(label) > 63:
            raise IOCValidationError(f"Invalid domain label length in '{value}'")
        if not DOMAIN_LABEL_PATTERN.match(label):
            raise IOCValidationError(f"Invalid characters in domain label '{label}' of '{value}'")

    # TLD should not be purely numeric
    if labels[-1].isdigit():
        raise IOCValidationError(f"Top-level domain cannot be purely numeric: '{labels[-1]}'")

    return cleaned


def normalize_url(value: str) -> str:
    """Normalize and validate URL.

    - Requires http, https, ftp, or ftps scheme
    - Lowercases scheme and hostname
    - Strips userinfo credentials (username:password@) to prevent credential exposure
    - Strips default scheme ports (:80 for http, :443 for https)
    - Normalizes empty path to '/'
    Raises IOCValidationError if invalid.
    """
    cleaned = value.strip()
    if not cleaned or len(cleaned) > MAX_IOC_VALUE_LENGTH:
        raise IOCValidationError(f"Invalid URL length: {len(cleaned)}")

    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except Exception as err:
        raise IOCValidationError(f"Failed to parse URL '{value}': {err}") from err

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https", "ftp", "ftps"}:
        raise IOCValidationError(
            f"URL scheme '{scheme}' is not supported; must be http, https, ftp, or ftps"
        )

    if not parsed.hostname:
        raise IOCValidationError(f"URL is missing host component: '{value}'")

    hostname = parsed.hostname.lower()
    port = parsed.port

    if port:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = hostname
        else:
            netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    path = parsed.path if parsed.path else "/"

    normalized = urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    return normalized


def normalize_email(value: str) -> str:
    """Normalize and validate email address.

    Returns lowercase canonical email address.
    Raises IOCValidationError if invalid.
    """
    cleaned = value.strip().lower()
    if not cleaned or len(cleaned) > 254:
        raise IOCValidationError(f"Invalid email length: '{value}'")

    if not EMAIL_PATTERN.match(cleaned):
        raise IOCValidationError(f"Invalid email address format: '{value}'")

    parts = cleaned.split("@", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise IOCValidationError(f"Invalid email structure: '{value}'")

    # Validate the domain part
    normalize_domain(parts[1])

    return cleaned


def normalize_file_hash(value: str, expected_type: IndicatorType) -> str:
    """Normalize and validate cryptographic file hash (MD5, SHA1, SHA256).

    Returns lowercase hexadecimal string.
    Raises IOCValidationError if invalid.
    """
    cleaned = value.strip().lower()
    expected_lengths = {
        IndicatorType.HASH_MD5: 32,
        IndicatorType.HASH_SHA1: 40,
        IndicatorType.HASH_SHA256: 64,
    }

    expected_len = expected_lengths.get(expected_type)
    if not expected_len:
        raise IOCValidationError(f"Unsupported hash indicator type: {expected_type}")

    if len(cleaned) != expected_len:
        raise IOCValidationError(
            f"Invalid {expected_type.value} length: "
            f"expected {expected_len} hex characters, got {len(cleaned)}"
        )

    if not all(c in HEX_CHARS for c in cleaned):
        raise IOCValidationError(
            f"Invalid hexadecimal characters in {expected_type.value}: '{value}'"
        )

    return cleaned


def normalize_ioc(indicator_type: IndicatorType, value: str) -> str:
    """Dispatcher to normalize an IOC value according to its declared type.

    Raises IOCValidationError if the value is invalid for the type.
    """
    if not value or not isinstance(value, str):
        raise IOCValidationError("Indicator value must be a non-empty string")

    trimmed = value.strip()
    if len(trimmed) > MAX_IOC_VALUE_LENGTH:
        raise IOCValidationError(
            f"Indicator value exceeds maximum length of {MAX_IOC_VALUE_LENGTH}"
        )

    if indicator_type == IndicatorType.IP:
        return normalize_ip(trimmed)
    elif indicator_type == IndicatorType.DOMAIN:
        return normalize_domain(trimmed)
    elif indicator_type == IndicatorType.URL:
        return normalize_url(trimmed)
    elif indicator_type == IndicatorType.EMAIL:
        return normalize_email(trimmed)
    elif indicator_type in {
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    }:
        return normalize_file_hash(trimmed, indicator_type)
    else:
        raise IOCValidationError(f"Unknown indicator type: {indicator_type}")


def infer_indicator_type(value: str) -> tuple[IndicatorType, str] | None:
    """Attempt to infer the indicator type and return (IndicatorType, normalized_value).

    Returns None if the value does not match any recognized indicator format.
    """
    if not value or not isinstance(value, str):
        return None

    cleaned = value.strip()
    if len(cleaned) > MAX_IOC_VALUE_LENGTH or len(cleaned) == 0:
        return None

    # 1. Check IP address
    try:
        norm_ip = normalize_ip(cleaned)
        return IndicatorType.IP, norm_ip
    except IOCValidationError:
        pass

    # 2. Check Hashes by length and hex format
    lower = cleaned.lower()
    if all(c in HEX_CHARS for c in lower):
        if len(lower) == 32:
            return IndicatorType.HASH_MD5, lower
        elif len(lower) == 40:
            return IndicatorType.HASH_SHA1, lower
        elif len(lower) == 64:
            return IndicatorType.HASH_SHA256, lower

    # 3. Check URL
    if cleaned.lower().startswith(("http://", "https://", "ftp://", "ftps://")):
        try:
            norm_url = normalize_url(cleaned)
            return IndicatorType.URL, norm_url
        except IOCValidationError:
            pass

    # 4. Check Email
    if "@" in cleaned:
        try:
            norm_email = normalize_email(cleaned)
            return IndicatorType.EMAIL, norm_email
        except IOCValidationError:
            pass

    # 5. Check Domain
    try:
        norm_domain = normalize_domain(cleaned)
        return IndicatorType.DOMAIN, norm_domain
    except IOCValidationError:
        pass

    return None


def extract_iocs_from_event(event: Any) -> list[ExtractedIOC]:
    """Inspect a canonical security event and extract all valid indicators of compromise.

    Examines:
    - `source_ip` (IP)
    - `destination_ip` (IP)
    - `username` (EMAIL if format matches)
    - `attributes` dictionary (keys referencing domain, url, hash, ip, email, etc.,
      plus scanning string values)

    Preserves exact evidence origin field and raw string value.
    """
    extracted: list[ExtractedIOC] = []
    seen_keys: set[tuple[IndicatorType, str, str]] = set()

    def add_ioc(ioc_type: IndicatorType, raw_val: str, norm_val: str, field_path: str) -> None:
        dedup_key = (ioc_type, norm_val, field_path)
        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            extracted.append(
                ExtractedIOC(
                    type=ioc_type,
                    raw_value=raw_val,
                    normalized_value=norm_val,
                    extracted_from_field=field_path,
                )
            )

    # 1. Source IP
    source_ip = getattr(event, "source_ip", None)
    if source_ip and isinstance(source_ip, str):
        try:
            norm = normalize_ip(source_ip)
            add_ioc(IndicatorType.IP, source_ip, norm, "source_ip")
        except IOCValidationError:
            pass

    # 2. Destination IP
    dest_ip = getattr(event, "destination_ip", None)
    if dest_ip and isinstance(dest_ip, str):
        try:
            norm = normalize_ip(dest_ip)
            add_ioc(IndicatorType.IP, dest_ip, norm, "destination_ip")
        except IOCValidationError:
            pass

    # 3. Username if it is an email
    username = getattr(event, "username", None)
    if username and isinstance(username, str) and "@" in username:
        try:
            norm = normalize_email(username)
            add_ioc(IndicatorType.EMAIL, username, norm, "username")
        except IOCValidationError:
            pass

    # 4. Attributes dictionary inspection
    attributes = getattr(event, "attributes", None)
    if isinstance(attributes, dict):
        _extract_from_dict(attributes, prefix="attributes", add_ioc=add_ioc)

    return extracted


def _extract_from_dict(d: dict[str, Any], prefix: str, add_ioc: Any) -> None:
    """Recursively scan attributes dict for indicator values."""
    for key, val in d.items():
        field_path = f"{prefix}.{key}"
        if isinstance(val, dict):
            _extract_from_dict(val, field_path, add_ioc)
        elif isinstance(val, list):
            for i, item in enumerate(val):
                if isinstance(item, dict):
                    _extract_from_dict(item, f"{field_path}[{i}]", add_ioc)
                elif isinstance(item, str) and len(item) <= MAX_IOC_VALUE_LENGTH:
                    _check_and_add_value(item, f"{field_path}[{i}]", key.lower(), add_ioc)
        elif isinstance(val, str) and len(val) <= MAX_IOC_VALUE_LENGTH:
            _check_and_add_value(val, field_path, key.lower(), add_ioc)


def _check_and_add_value(raw_val: str, field_path: str, key_hint: str, add_ioc: Any) -> None:
    """Examine a string attribute value with key hint assistance."""
    trimmed = raw_val.strip()
    if not trimmed:
        return

    # Specific key hints take priority for targeted validation
    if any(k in key_hint for k in ("source_ip", "dest_ip", "dst_ip", "client_ip", "remote_ip")):
        try:
            norm = normalize_ip(trimmed)
            add_ioc(IndicatorType.IP, raw_val, norm, field_path)
            return
        except IOCValidationError:
            pass

    if any(k in key_hint for k in ("domain", "hostname", "fqdn", "dns_query")):
        try:
            norm = normalize_domain(trimmed)
            add_ioc(IndicatorType.DOMAIN, raw_val, norm, field_path)
            return
        except IOCValidationError:
            pass

    if any(k in key_hint for k in ("url", "uri")):
        try:
            norm = normalize_url(trimmed)
            add_ioc(IndicatorType.URL, raw_val, norm, field_path)
            return
        except IOCValidationError:
            pass

    if any(k in key_hint for k in ("sha256", "file_sha256", "sha256_hash")):
        try:
            norm = normalize_file_hash(trimmed, IndicatorType.HASH_SHA256)
            add_ioc(IndicatorType.HASH_SHA256, raw_val, norm, field_path)
            return
        except IOCValidationError:
            pass

    if any(k in key_hint for k in ("sha1", "file_sha1")):
        try:
            norm = normalize_file_hash(trimmed, IndicatorType.HASH_SHA1)
            add_ioc(IndicatorType.HASH_SHA1, raw_val, norm, field_path)
            return
        except IOCValidationError:
            pass

    if any(k in key_hint for k in ("md5", "file_md5")):
        try:
            norm = normalize_file_hash(trimmed, IndicatorType.HASH_MD5)
            add_ioc(IndicatorType.HASH_MD5, raw_val, norm, field_path)
            return
        except IOCValidationError:
            pass

    # Generic inference if no key hint matched
    inferred = infer_indicator_type(trimmed)
    if inferred:
        ioc_type, norm = inferred
        add_ioc(ioc_type, raw_val, norm, field_path)

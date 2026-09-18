"""SSRF Protection and URL Validation Engine (Phase 13).

Enforces strict outbound network defenses to prevent Server-Side Request Forgery:
- Requires HTTPS (unless explicitly configured for insecure dev HTTP)
- Restricts ports to 443 (or 80 in dev)
- Resolves DNS hostnames and verifies all resolved IP addresses against blocked CIDR ranges
- Blocks loopback, RFC 1918 private, link-local, multicast, and cloud metadata addresses
- Disallows user/password in URLs
"""

import ipaddress
import socket
from urllib.parse import urlparse

from app.core.config import settings


class SSRFValidationError(Exception):
    """Raised when an outbound URL violates SSRF safety constraints."""


# Denied IPv4 CIDR blocks
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("10.0.0.0/8"),  # Private RFC 1918
    ipaddress.ip_network("100.64.0.0/10"),  # Shared address / CGNAT (includes 100.100.100.200)
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / Cloud metadata (169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),  # Private RFC 1918
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.168.0.0/16"),  # Private RFC 1918
    ipaddress.ip_network("198.18.0.0/15"),  # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),  # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),  # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
]

# Denied IPv6 CIDR blocks
BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),  # Unspecified address
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("100::/64"),  # Discard prefix
    ipaddress.ip_network("2001:db8::/32"),  # Documentation
    ipaddress.ip_network("fc00::/7"),  # Unique local (ULA)
    ipaddress.ip_network("fe80::/10"),  # Link-local unicast
    ipaddress.ip_network("ff00::/8"),  # Multicast
]

# Explicit cloud metadata hostnames
BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "instance-data",
        "metadata.internal",
        "169.254.169.254",
    }
)


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP address belongs to any restricted or private network."""
    if isinstance(ip, ipaddress.IPv6Address):
        # Check IPv4-mapped IPv6 address (e.g. ::ffff:127.0.0.1)
        if ip.ipv4_mapped:
            return is_ip_blocked(ip.ipv4_mapped)
        return any(ip in net for net in BLOCKED_IPV6_NETWORKS)

    return any(ip in net for net in BLOCKED_IPV4_NETWORKS)


def validate_url_ssrf(
    url: str,
    allow_insecure_http: bool | None = None,
) -> tuple[str, str, int]:
    """Validate a destination URL against SSRF policy.

    Returns (normalized_url, hostname, port).
    Raises SSRFValidationError if the URL is dangerous or invalid.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Target URL cannot be empty.")

    allow_http = (
        allow_insecure_http
        if allow_insecure_http is not None
        else settings.WEBHOOK_ALLOW_INSECURE_HTTP
    )

    try:
        parsed = urlparse(url.strip())
    except Exception as exc:
        raise SSRFValidationError(f"Malformed URL: {exc}") from exc

    # 1. Validate Scheme
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        default_port = 443
    elif scheme == "http":
        if not allow_http:
            raise SSRFValidationError("Insecure HTTP scheme is rejected. Webhooks require HTTPS.")
        default_port = 80
    else:
        raise SSRFValidationError(f"Unsupported URL scheme '{scheme}'. Only HTTPS is permitted.")

    # 2. Reject credentials in URL
    if parsed.username or parsed.password:
        raise SSRFValidationError("Embedded user credentials in webhook URLs are forbidden.")

    # 3. Validate Hostname
    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        raise SSRFValidationError("Missing hostname in target URL.")

    if hostname in BLOCKED_HOSTNAMES:
        raise SSRFValidationError(f"Hostname '{hostname}' is blocked by SSRF policy.")

    # 4. Validate Port
    port = parsed.port or default_port
    allowed_ports = {443} if not allow_http else {443, 80}
    if port not in allowed_ports:
        raise SSRFValidationError(
            f"Port {port} is restricted. Only standard ports ({allowed_ports}) are allowed."
        )

    # 5. DNS Resolution and IP Validation
    try:
        addr_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        msg = f"Could not resolve destination hostname '{hostname}': {exc}"
        raise SSRFValidationError(msg) from exc

    if not addr_info:
        raise SSRFValidationError(f"No IP addresses resolved for hostname '{hostname}'.")

    for _family, _, _, _, sockaddr in addr_info:
        raw_ip = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise SSRFValidationError(f"Invalid resolved IP address '{raw_ip}': {exc}") from exc

        if is_ip_blocked(ip_obj):
            raise SSRFValidationError(
                f"Destination resolved to restricted IP '{raw_ip}', blocked by SSRF policy."
            )

    return url.strip(), hostname, port

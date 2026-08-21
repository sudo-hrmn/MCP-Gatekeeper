"""Security validation utilities for MCP-Gatekeeper."""
import socket
import ipaddress
from urllib.parse import urlparse

FORBIDDEN_HOSTNAMES = {
    "localhost", "0.0.0.0", "127.0.0.1", "::1",
    "169.254.169.254", "metadata.google.internal"
}

def validate_upstream_url(url: str) -> str:
    """
    Validates upstream URL to prevent Server-Side Request Forgery (SSRF).
    Ensures scheme is http/https and target IP is not private, loopback, or cloud metadata.
    """
    if not url or not isinstance(url, str):
        raise ValueError("Invalid URL: must be a non-empty string.")

    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{parsed.scheme}': only HTTP and HTTPS are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: missing hostname.")

    hostname_lower = hostname.lower()
    if hostname_lower in FORBIDDEN_HOSTNAMES:
        raise ValueError(f"SSRF Risk Blocked: Target hostname '{hostname}' is forbidden.")

    try:
        # Resolve domain to IP address
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        if (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_multicast or
            ip.is_reserved or
            ip.is_unspecified
        ):
            raise ValueError(f"SSRF Risk Blocked: Target IP '{ip_str}' resolves to a private/internal network.")
    except socket.gaierror:
        # Domain name resolution failed — allow or raise based on strict mode
        pass
    except ValueError as e:
        if "SSRF Risk Blocked" in str(e):
            raise e

    return url.strip()

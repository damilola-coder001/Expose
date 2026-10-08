"""Target validation, URL normalization, and SSRF safety guard.

Protects against unintended scanning of internal cloud metadata, RFC1918 networks,
and local loopback interfaces.
"""

import ipaddress
import socket
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import httpx
from httpcore._backends.anyio import AnyIOBackend

from .models import TargetScope


class SecurityScopeError(Exception):
    """Raised when target validation or safety guardrails are violated."""
    pass


PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Class A
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-Grade NAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Cloud Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Class B
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast (RFC 7526)
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Class C
    ipaddress.ip_network("198.18.0.0/15"),      # Network Benchmark (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast (RFC 919)

    # IPv6 Special/Private Ranges
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),            # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6 (RFC 4291)
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4-IPv6 Translation (RFC 6052)
    ipaddress.ip_network("100::/64"),           # Discard-Only (RFC 6666)
    ipaddress.ip_network("2001:db8::/32"),      # Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.google",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200",  # Alibaba Cloud metadata
}

BLOCKED_TLD_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".corp",
    ".home",
)


def is_restricted_hostname(host: str) -> bool:
    """Returns True if the hostname matches cloud metadata endpoints or internal TLDs."""
    clean = host.strip().lower()
    if clean in BLOCKED_HOSTNAMES:
        return True
    for blocked in BLOCKED_HOSTNAMES:
        if clean.endswith("." + blocked):
            return True
    return clean.endswith(BLOCKED_TLD_SUFFIXES)


def is_ip_private(ip_str: str) -> bool:
    """Returns True if the given IP address is in a private, loopback, link-local, or metadata range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        # Unmask IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        if str(ip_obj) == "100.100.100.200":
            return True
        return any(ip_obj in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def resolve_host_ips(host: str) -> List[str]:
    """Resolves DNS for a given host to all unique IPv4 and IPv6 addresses."""
    ips = set()
    try:
        addr_info = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            sockaddr = entry[4]
            ip = sockaddr[0]
            ips.add(ip)
    except socket.gaierror as e:
        raise SecurityScopeError(f"Failed to resolve DNS for host '{host}': {e}")
    return sorted(list(ips))


def parse_and_validate_target(raw_target: str, allow_private: bool = False) -> TargetScope:
    """Parses, normalizes, and applies SSRF safety constraints to a target.
    
    Args:
        raw_target: Target string (e.g. 'example.com', 'https://example.com:8443/app')
        allow_private: If True, allows scanning private/loopback/internal IPs.
        
    Returns:
        TargetScope populated with normalized details.
        
    Raises:
        SecurityScopeError: If input is invalid or violates SSRF guardrails.
    """
    cleaned = raw_target.strip()
    if not cleaned:
        raise SecurityScopeError("Target cannot be empty.")

    # Default to https if no scheme is provided
    if "://" in cleaned:
        url_to_parse = cleaned
    else:
        url_to_parse = f"https://{cleaned}"

    try:
        parsed = urlparse(url_to_parse)
    except Exception as e:
        raise SecurityScopeError(f"Invalid target URL format: {e}")

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SecurityScopeError(f"Unsupported scheme '{scheme}'. Only http and https are supported.")

    host = parsed.hostname
    if not host:
        raise SecurityScopeError("Target must contain a valid hostname or IP address.")

    if not allow_private and is_restricted_hostname(host):
        raise SecurityScopeError(
            f"SSRF Safety Guard: Target '{host}' is an internal or cloud metadata hostname. "
            "To permit scanning internal or local environments, pass --allow-private."
        )

    port = parsed.port or (443 if scheme == "https" else 80)
    normalized_url = f"{scheme}://{host}"
    if parsed.port:
        normalized_url += f":{parsed.port}"

    # Resolve IPs
    resolved_ips = resolve_host_ips(host)
    if not resolved_ips:
        raise SecurityScopeError(f"Could not resolve any IP addresses for host '{host}'.")

    # Check for private or loopback IPs
    has_private_ip = any(is_ip_private(ip) for ip in resolved_ips)

    if has_private_ip and not allow_private:
        private_list = [ip for ip in resolved_ips if is_ip_private(ip)]
        raise SecurityScopeError(
            f"SSRF Safety Guard: Target '{host}' resolves to restricted IP(s): {', '.join(private_list)}. "
            "To permit scanning internal or local environments, pass --allow-private."
        )


    return TargetScope(
        raw_target=raw_target,
        normalized_url=normalized_url,
        scheme=scheme,
        host=host,
        port=port,
        resolved_ips=resolved_ips,
        is_private=has_private_ip,
        allow_private=allow_private,
    )


def validate_redirect_target(location: str, allow_private: bool = False) -> str:
    """Validates that a redirect location does not jump to private networks or metadata services."""
    parsed = urlparse(location)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SecurityScopeError(f"Insecure redirect scheme '{scheme}': only http and https allowed.")
    
    host = parsed.hostname
    if not host:
        raise SecurityScopeError("Redirect target does not contain a valid hostname.")
    
    if not allow_private and is_restricted_hostname(host):
        raise SecurityScopeError(f"SSRF Safety Guard: Redirect target '{host}' is an internal/metadata hostname.")
    
    ips = resolve_host_ips(host)
    if not allow_private and any(is_ip_private(ip) for ip in ips):
        raise SecurityScopeError(f"SSRF Safety Guard: Redirect target '{host}' resolves to restricted IP.")
    
    return location


class SSRFSafeNetworkBackend(AnyIOBackend):
    """Network backend that performs socket-level inspection upon connection to prevent TOCTOU DNS rebinding."""

    def __init__(self, allow_private: bool = False):
        super().__init__()
        self.allow_private = allow_private

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ):
        if not self.allow_private and (is_restricted_hostname(host) or is_ip_private(host)):
            raise SecurityScopeError(f"SSRF Safety Guard: Blocked connection to restricted host or IP '{host}'")

        stream = await super().connect_tcp(host, port, timeout, local_address, socket_options)
        try:
            raw_socket = getattr(stream, "_raw_socket", None)
            if raw_socket:
                peer = raw_socket.getpeername()
                peer_ip = str(peer[0])
                if not self.allow_private and is_ip_private(peer_ip):
                    await stream.aclose()
                    raise SecurityScopeError(
                        f"SSRF / Anti-DNS-Rebinding Guard: Socket connected to restricted IP '{peer_ip}' for host '{host}'."
                    )
        except Exception:
            await stream.aclose()
            raise
        return stream


class SSRFSafeAsyncTransport(httpx.AsyncHTTPTransport):
    """HTTPX Async transport that enforces anti-DNS-rebinding and SSRF protection at the socket layer."""

    def __init__(self, allow_private: bool = False, **kwargs):
        super().__init__(**kwargs)
        self.allow_private = allow_private
        if hasattr(self, "_pool"):
            self._pool._network_backend = SSRFSafeNetworkBackend(allow_private=allow_private)


def create_safe_async_client(
    target: Optional[TargetScope] = None,
    allow_private: Optional[bool] = None,
    verify: bool = False,
    follow_redirects: bool = True,
    timeout: float = 8.0,
    **kwargs
) -> httpx.AsyncClient:
    """Factory creating an httpx.AsyncClient with socket-level anti-DNS-rebinding protection."""
    is_private_allowed = (
        allow_private if allow_private is not None else (target.allow_private if target else False)
    )
    transport = SSRFSafeAsyncTransport(allow_private=is_private_allowed, verify=verify)
    return httpx.AsyncClient(
        transport=transport,
        verify=verify,
        follow_redirects=follow_redirects,
        timeout=timeout,
        **kwargs
    )


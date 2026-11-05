"""Target URL validation, async DNS resolution, and SSRF defense."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from app.core.config import settings
from app.recon.exceptions import (
    DNSResolutionError,
    RedirectBlockedError,
    SSRFBlockedError,
    TargetValidationError,
)

# Blocked IPv4 address blocks
BLOCKED_IPV4_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("10.0.0.0/8"),         # Private network (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),      # Shared address space / CGNAT (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback (RFC 1122)
    ipaddress.ip_network("169.254.0.0/16"),     # Link-Local / Metadata (RFC 3927)
    ipaddress.ip_network("172.16.0.0/12"),      # Private network (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments (RFC 6890)
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("192.88.99.0/24"),     # 6to4 Relay Anycast (RFC 7526)
    ipaddress.ip_network("192.168.0.0/16"),     # Private network (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),      # Benchmarking (RFC 2544)
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"), # Limited Broadcast (RFC 919)
)

# Blocked IPv6 address blocks
BLOCKED_IPV6_NETWORKS: tuple[ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("::/128"),             # Unspecified (RFC 4291)
    ipaddress.ip_network("::1/128"),            # Loopback (RFC 4291)
    ipaddress.ip_network("100::/64"),           # Discard-Only (RFC 6666)
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (RFC 4193)
    ipaddress.ip_network("fe80::/10"),          # Link-Local Unicast (RFC 4291)
    ipaddress.ip_network("fec0::/10"),          # Site-Local (deprecated, RFC 3879)
    ipaddress.ip_network("ff00::/8"),           # Multicast (RFC 4291)
)

# Well-known cloud metadata endpoints that must never be accessed under any circumstance
CLOUD_METADATA_IPS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS, GCP, Azure, OpenStack, DigitalOcean
        "169.254.170.2",    # AWS ECS Task metadata
        "100.100.100.200",  # Alibaba Cloud metadata
        "fd00:ec2::254",    # AWS IPv6 IMDSv2
    }
)


@dataclass(frozen=True)
class TargetScope:
    """Represents a validated, resolved, and SSRF-checked target."""

    raw_url: str
    canonical_url: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    resolved_ips: tuple[str, ...]
    is_loopback: bool


def normalize_hostname(hostname: str) -> str:
    """Normalize hostname to lower-case, stripped, without surrounding brackets."""
    return hostname.strip().strip("[]").lower().rstrip(".")


def is_ip_address(host: str) -> bool:
    """Check whether a string represents a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def unwrap_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Unwrap IPv4-mapped or IPv4-compatible IPv6 addresses to standard IPv4."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        # Also check for 6to4 addresses (2002::/16)
        if ip in ipaddress.ip_network("2002::/16"):
            # The next 32 bits after 2002:: are the IPv4 address
            raw_v4 = int(ip) >> 80 & 0xFFFFFFFF
            return ipaddress.IPv4Address(raw_v4)
    return ip


def check_ip_ssrf(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_loopback: bool = False,
) -> None:
    """Verify that an IP address is safe to contact.

    Raises SSRFBlockedError if the IP is private, link-local, multicast,
    reserved, cloud metadata, or loopback (unless allow_loopback is true).
    """
    raw_str = str(ip)
    if raw_str in CLOUD_METADATA_IPS:
        raise SSRFBlockedError(
            f"Blocked access to cloud metadata IP address: {raw_str}",
            details={"ip": raw_str, "reason": "cloud_metadata"},
        )

    unwrapped = unwrap_ip(ip)
    unwrapped_str = str(unwrapped)

    if unwrapped_str in CLOUD_METADATA_IPS:
        raise SSRFBlockedError(
            f"Blocked access to cloud metadata IP address: {unwrapped_str}",
            details={"ip": unwrapped_str, "reason": "cloud_metadata"},
        )

    # Check loopback
    if unwrapped.is_loopback:
        if not allow_loopback:
            raise SSRFBlockedError(
                f"Blocked access to loopback IP address: {unwrapped_str}",
                details={"ip": unwrapped_str, "reason": "loopback"},
            )
        return

    # Check IPv4 networks
    if isinstance(unwrapped, ipaddress.IPv4Address):
        for net in BLOCKED_IPV4_NETWORKS:
            if unwrapped in net:
                if net == ipaddress.ip_network("127.0.0.0/8") and allow_loopback:
                    continue
                raise SSRFBlockedError(
                    f"Blocked access to restricted IP range ({net}): {unwrapped_str}",
                    details={"ip": unwrapped_str, "network": str(net)},
                )

    # Check IPv6 networks
    elif isinstance(unwrapped, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if unwrapped in net:
                if net == ipaddress.ip_network("::1/128") and allow_loopback:
                    continue
                raise SSRFBlockedError(
                    f"Blocked access to restricted IPv6 range ({net}): {unwrapped_str}",
                    details={"ip": unwrapped_str, "network": str(net)},
                )


async def resolve_hostname_safe(
    hostname: str,
    *,
    allow_loopback: bool = False,
) -> list[str]:
    """Perform async DNS resolution and validate all resolved IPs against SSRF filters.

    Returns the list of validated IP string representations.
    """
    clean_host = normalize_hostname(hostname)

    # If it is already a literal IP address
    if is_ip_address(clean_host):
        ip = ipaddress.ip_address(clean_host)
        check_ip_ssrf(ip, allow_loopback=allow_loopback)
        return [str(ip)]

    loop = asyncio.get_running_loop()
    try:
        addr_info = await loop.getaddrinfo(
            clean_host,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise DNSResolutionError(
            f"DNS resolution failed for '{clean_host}': {exc.strerror or 'host not found'}",
            details={"hostname": clean_host},
        ) from exc
    except Exception as exc:
        raise DNSResolutionError(
            f"Unexpected error during DNS resolution for '{clean_host}': {exc}",
            details={"hostname": clean_host},
        ) from exc

    if not addr_info:
        raise DNSResolutionError(
            f"DNS query returned no records for hostname '{clean_host}'.",
            details={"hostname": clean_host},
        )

    resolved_ips: list[str] = []
    seen: set[str] = set()
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)

        ip = ipaddress.ip_address(ip_str)
        # Validate against SSRF for every resolved IP record
        check_ip_ssrf(ip, allow_loopback=allow_loopback)
        resolved_ips.append(str(ip))

    if not resolved_ips:
        raise DNSResolutionError(
            f"No valid IP addresses available for '{clean_host}'.",
            details={"hostname": clean_host},
        )

    return resolved_ips


def validate_target_syntax(raw_url: str) -> SplitResult:
    """Validate target URL syntax and enforce security constraints.

    Rejects:
    - Empty or overly long URLs (> 2048 chars).
    - Control characters.
    - Non-HTTP/HTTPS schemes (e.g. file, gopher, dict, ftp, ldap).
    - Embedded credentials (user:pass@host).
    - Fragments (#...).
    - Queries on the base target URL (must be base URL for recon).
    - Missing or invalid ports outside 1-65535.
    """
    value = raw_url.strip()
    if not value:
        raise TargetValidationError("Target URL must not be blank.")
    if len(value) > 2048:
        raise TargetValidationError("Target URL is too long (maximum 2048 characters).")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise TargetValidationError("Target URL contains forbidden control characters.")

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise TargetValidationError(f"Invalid URL structure: {exc}") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError(
            f"Unsupported scheme '{scheme}'. Only http and https are permitted."
        )

    if parts.username or parts.password:
        raise TargetValidationError(
            "Embedded credentials in target URLs are forbidden for security."
        )

    if parts.fragment:
        raise TargetValidationError("Target base URL must not contain a URL fragment.")

    if parts.hostname is None or not parts.hostname.strip():
        raise TargetValidationError("Target URL must include a valid hostname.")

    try:
        port = parts.port
    except ValueError as exc:
        raise TargetValidationError(f"Target URL contains an invalid port: {exc}") from exc

    if port is not None and not 1 <= port <= 65535:
        raise TargetValidationError("Target URL port must be between 1 and 65535.")

    return parts


async def validate_recon_target(
    raw_url: str,
    *,
    enforce_scope: bool = True,
    override_allowed_hosts: set[str] | None = None,
) -> TargetScope:
    """Full target validation: syntax, authorization scope, DNS, and SSRF check.

    Returns a TargetScope with canonical URL and verified resolved IP addresses.
    """
    parts = validate_target_syntax(raw_url)
    hostname = normalize_hostname(parts.hostname or "")

    # Authorization scope check
    allowed_hosts = override_allowed_hosts or set(settings.allowed_target_hosts)
    if enforce_scope and hostname not in allowed_hosts:
        allowed_desc = ", ".join(sorted(allowed_hosts)) or "(none configured)"
        raise TargetValidationError(
            f"Target hostname '{hostname}' is not in the authorized scope. "
            f"Authorized hosts: {allowed_desc}.",
            details={"hostname": hostname, "allowed_hosts": sorted(allowed_hosts)},
        )

    # Determine if loopback is permitted for this target
    is_loopback_target = hostname in {"127.0.0.1", "localhost", "::1"} or (
        is_ip_address(hostname) and ipaddress.ip_address(hostname).is_loopback
    )
    allow_loopback = (
        is_loopback_target
        and settings.scan_allow_loopback_for_testing
        and (not enforce_scope or hostname in allowed_hosts)
    )

    # Asynchronous DNS resolution + SSRF validation
    resolved_ips = await resolve_hostname_safe(hostname, allow_loopback=allow_loopback)

    scheme = parts.scheme.lower()
    port = parts.port
    is_default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    display_port = None if is_default_port else port

    host_part = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host_part}:{display_port}" if display_port else host_part
    path = parts.path or "/"

    canonical_url = urlunsplit((scheme, netloc, path, parts.query, ""))

    return TargetScope(
        raw_url=raw_url,
        canonical_url=canonical_url,
        scheme=scheme,
        hostname=hostname,
        port=display_port,
        path=path,
        resolved_ips=tuple(resolved_ips),
        is_loopback=is_loopback_target,
    )


async def validate_redirect_target(
    current_url: str,
    location_header: str,
    *,
    initial_target_host: str,
    allowed_hosts: set[str] | None = None,
    allow_loopback: bool = False,
) -> str:
    """Validate an HTTP redirect Location header against scope and SSRF blocklists.

    Guards against:
    - Open redirects to arbitrary third-party or untrusted sites.
    - Redirecting to cloud metadata (169.254.169.254) or private IP ranges.
    - Scheme smuggling (e.g. javascript:, file:, data:, ftp:).

    Returns the absolute canonical redirect URL.
    """
    loc = location_header.strip()
    if not loc:
        raise RedirectBlockedError("Redirect Location header is empty.")

    # Reconstruct absolute URL
    target_url = urljoin(current_url, loc)
    parts = urlsplit(target_url)

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise RedirectBlockedError(
            f"Redirect scheme '{scheme}' is forbidden. Only http/https permitted."
        )

    if not parts.hostname:
        raise RedirectBlockedError("Redirect URL has no valid hostname.")

    dest_host = normalize_hostname(parts.hostname)

    # Enforce scope: redirect must stay on the same origin/host, or on an authorized host
    authorized = allowed_hosts or set(settings.allowed_target_hosts)
    authorized.add(normalize_hostname(initial_target_host))

    if dest_host not in authorized:
        raise RedirectBlockedError(
            f"Redirect to out-of-scope host '{dest_host}' blocked.",
            details={"destination_host": dest_host, "authorized": sorted(authorized)},
        )

    # Re-verify DNS and SSRF on redirect destination to prevent DNS rebinding SSRF
    await resolve_hostname_safe(dest_host, allow_loopback=allow_loopback)

    return target_url

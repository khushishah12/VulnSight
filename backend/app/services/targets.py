"""Target URL validation and allowlist enforcement.

This is intentionally strict. A vulnerability scanner can generate traffic, so
the operator must explicitly authorize every hostname. Wildcards are not
supported in the Lean MVP.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit, urlunsplit

from app.core.config import settings
from app.core.exceptions import BadRequestError


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    hostname: str
    port: int | None
    path: str


def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().strip("[]").lower().rstrip(".")


def _allowed_hosts() -> set[str]:
    return {
        _normalize_hostname(host)
        for host in settings.allowed_target_hosts
        if host.strip()
    }


def validate_target_url(raw_url: str) -> ValidatedTarget:
    """Validate one target URL and return a canonical form.

    Rules:
    - only ``http`` and ``https``;
    - no embedded username or password;
    - no fragment and no query string;
    - hostname must exactly match ``SCAN_ALLOWED_HOSTS``.
    """

    value = raw_url.strip()
    if not value:
        raise BadRequestError("Target URL must not be blank.")
    if len(value) > 2048:
        raise BadRequestError("Target URL is too long (maximum 2048 characters).")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise BadRequestError("Target URL contains control characters.")

    try:
        parts: SplitResult = urlsplit(value)
    except ValueError as exc:
        raise BadRequestError("Target URL is not valid.") from exc

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise BadRequestError("Target URL scheme must be http or https.")
    if parts.username or parts.password:
        raise BadRequestError(
            "Target URL must not contain embedded credentials."
        )
    if parts.fragment:
        raise BadRequestError("Target URL must not contain a fragment.")
    if parts.query:
        raise BadRequestError(
            "Target URL must not contain a query string. Use a base URL."
        )

    if parts.hostname is None:
        raise BadRequestError("Target URL must include a hostname.")

    hostname = _normalize_hostname(parts.hostname)
    if not hostname:
        raise BadRequestError("Target URL must include a hostname.")

    allowed = _allowed_hosts()
    if hostname not in allowed:
        allowed_text = ", ".join(sorted(allowed)) or "(none configured)"
        raise BadRequestError(
            "Target hostname is not in the authorized allowlist. "
            f"Allowed hosts: {allowed_text}.",
            details={"hostname": hostname, "allowed_hosts": sorted(allowed)},
        )

    try:
        port = parts.port
    except ValueError as exc:
        raise BadRequestError("Target URL contains an invalid port.") from exc

    if port is not None and not 1 <= port <= 65535:
        raise BadRequestError("Target URL port must be between 1 and 65535.")

    path = parts.path or "/"
    if len(path) > 1024:
        raise BadRequestError("Target path is too long (maximum 1024 characters).")

    display_port = None
    if port is not None:
        is_default = (scheme == "http" and port == 80) or (
            scheme == "https" and port == 443
        )
        display_port = None if is_default else port

    host_part = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host_part}:{display_port}" if display_port else host_part
    canonical_url = urlunsplit((scheme, netloc, path, "", ""))

    return ValidatedTarget(
        url=canonical_url,
        scheme=scheme,
        hostname=hostname,
        port=display_port,
        path=path,
    )

"""Safe HTTP client with SSRF-safe manual redirect following and rate limiting."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import certifi
import httpx

from app.core.config import settings
from app.recon.exceptions import ReconError, RedirectBlockedError
from app.recon.validator import normalize_hostname, validate_redirect_target


@dataclass
class RedirectHop:
    """Record of a single redirect transition."""

    from_url: str
    to_url: str
    status_code: int


@dataclass
class ReconResponse:
    """Safe representation of an HTTP response collected during reconnaissance."""

    url: str
    status_code: int
    reason_phrase: str
    headers: dict[str, str]
    content_type: str
    content_length: int | None
    body_text: str
    response_time_ms: float
    redirect_history: list[RedirectHop] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    is_tls: bool = False
    http_version: str = "HTTP/1.1"


class SafeReconClient:
    """HTTP client specialized for safe, polite, non-destructive reconnaissance."""

    def __init__(
        self,
        *,
        timeout_seconds: float | None = None,
        max_redirects: int | None = None,
        rate_limit_delay: float | None = None,
        user_agent: str | None = None,
        allow_loopback: bool = False,
    ) -> None:
        self.timeout = timeout_seconds or settings.recon_request_timeout
        self.max_redirects = (
            max_redirects
            if max_redirects is not None
            else settings.recon_max_redirects
        )
        self.rate_limit_delay = (
            rate_limit_delay
            if rate_limit_delay is not None
            else settings.recon_rate_limit_delay
        )
        self.user_agent = user_agent or settings.recon_user_agent
        self.allow_loopback = allow_loopback
        self._last_request_time: float = 0.0

    async def _throttle(self) -> None:
        """Apply polite rate limiting delay between consecutive requests."""
        if self.rate_limit_delay <= 0:
            return
        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < self.rate_limit_delay:
            await asyncio.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.monotonic()

    def _extract_cookies(self, response: httpx.Response) -> list[dict[str, Any]]:
        """Extract structured cookie attributes with values masked for security."""
        extracted: list[dict[str, Any]] = []
        for cookie in response.cookies.jar:
            # Mask value: indicate length and whether present, never store sensitive tokens in raw text
            val_len = len(cookie.value) if cookie.value else 0
            masked = f"[REDACTED len={val_len}]" if val_len > 0 else ""

            # Check standard and non-standard attributes
            is_httponly = (
                getattr(cookie, "has_nonstandard_attr", lambda _: False)("httponly")
                or "httponly" in getattr(cookie, "_rest", {})
            )
            samesite = getattr(
                cookie, "get_nonstandard_attr", lambda *_: None
            )("samesite")

            extracted.append(
                {
                    "name": cookie.name,
                    "masked_value": masked,
                    "domain": cookie.domain or "",
                    "path": cookie.path or "/",
                    "secure": bool(cookie.secure),
                    "httponly": bool(is_httponly),
                    "samesite": samesite,
                    "expires": cookie.expires,
                }
            )
        return extracted

    async def fetch(
        self,
        url: str,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        max_body_bytes: int = 2 * 1024 * 1024,  # 2MB max
    ) -> ReconResponse:
        """Fetch URL with manual redirect validation, SSRF checking per hop, and timing."""
        current_url = url
        initial_host = normalize_hostname(urlsplit(url).hostname or "")
        redirect_history: list[RedirectHop] = []

        request_headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            **(headers or {}),
        }

        # Create client with certifi verification and disabled automatic redirects
        timeout_config = httpx.Timeout(
            connect=3.0,
            read=5.0,
            write=3.0,
            pool=2.0,
        )

        async with httpx.AsyncClient(
            verify=certifi.where(),
            timeout=timeout_config,
            follow_redirects=False,  # CRITICAL: We handle redirects manually for SSRF defense
        ) as client:
            for _ in range(self.max_redirects + 1):
                await self._throttle()

                start_time = time.perf_counter()
                try:
                    response = await client.request(
                        method=method,
                        url=current_url,
                        headers=request_headers,
                    )
                except httpx.TimeoutException as exc:
                    raise ReconError(
                        f"Request to '{current_url}' timed out.",
                        code="request_timeout",
                        status_code=504,
                        details={"url": current_url, "timeout": self.timeout},
                    ) from exc
                except httpx.RequestError as exc:
                    raise ReconError(
                        f"Network connection error contacting '{current_url}': {exc}",
                        code="network_error",
                        status_code=502,
                        details={"url": current_url, "error": str(exc)},
                    ) from exc

                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

                # Check if it's a redirect status (301, 302, 303, 307, 308)
                if response.status_code in {301, 302, 303, 307, 308}:
                    location = response.headers.get("Location")
                    if not location:
                        # Redirect status without Location header: stop here
                        break

                    next_url = await validate_redirect_target(
                        current_url=current_url,
                        location_header=location,
                        initial_target_host=initial_host,
                        allow_loopback=self.allow_loopback,
                    )

                    redirect_history.append(
                        RedirectHop(
                            from_url=current_url,
                            to_url=next_url,
                            status_code=response.status_code,
                        )
                    )

                    current_url = next_url
                    # Use GET for 301, 302, 303 on redirect
                    if response.status_code in {301, 302, 303}:
                        method = "GET"
                    continue

                # Final response reached: stream or read content safely up to limit
                content_bytes = response.content[:max_body_bytes]
                try:
                    body_text = content_bytes.decode(
                        response.encoding or "utf-8",
                        errors="replace",
                    )
                except Exception:
                    body_text = content_bytes.decode("utf-8", errors="replace")

                normalized_headers = {
                    k.lower(): v for k, v in response.headers.items()
                }

                content_type = normalized_headers.get("content-type", "")
                content_length = None
                if "content-length" in normalized_headers:
                    try:
                        content_length = int(normalized_headers["content-length"])
                    except ValueError:
                        content_length = None

                is_tls = current_url.lower().startswith("https://")
                http_version = response.http_version

                cookies = self._extract_cookies(response)

                return ReconResponse(
                    url=current_url,
                    status_code=response.status_code,
                    reason_phrase=response.reason_phrase or "",
                    headers=normalized_headers,
                    content_type=content_type,
                    content_length=content_length,
                    body_text=body_text,
                    response_time_ms=elapsed_ms,
                    redirect_history=redirect_history,
                    cookies=cookies,
                    is_tls=is_tls,
                    http_version=http_version,
                )

        raise RedirectBlockedError(
            f"Exceeded maximum redirect limit ({self.max_redirects}) for '{url}'."
        )

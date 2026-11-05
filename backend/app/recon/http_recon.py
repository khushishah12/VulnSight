"""HTTP reconnaissance: headers, server signatures, HTTPS info, cookies, and timing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.recon.client import ReconResponse, SafeReconClient
from app.recon.validator import TargetScope


@dataclass
class SecurityHeadersCheck:
    """Status of standard defensive HTTP response headers."""

    strict_transport_security: str | None = None
    content_security_policy: str | None = None
    x_frame_options: str | None = None
    x_content_type_options: str | None = None
    referrer_policy: str | None = None
    permissions_policy: str | None = None
    missing_headers: list[str] = field(default_factory=list)


@dataclass
class HttpReconData:
    """Comprehensive HTTP reconnaissance output for one target."""

    url: str
    status_code: int
    reason_phrase: str
    response_time_ms: float
    content_type: str
    content_length: int | None
    headers: dict[str, str]
    server_banner: str | None
    header_technologies: list[str]
    is_https: bool
    https_hsts_enabled: bool
    redirect_chain: list[dict[str, Any]]
    cookies: list[dict[str, Any]]
    security_headers: SecurityHeadersCheck
    raw_body: str


def analyze_security_headers(headers: dict[str, str]) -> SecurityHeadersCheck:
    """Audit the presence of standard defensive security headers."""
    check = SecurityHeadersCheck(
        strict_transport_security=headers.get("strict-transport-security"),
        content_security_policy=headers.get("content-security-policy"),
        x_frame_options=headers.get("x-frame-options"),
        x_content_type_options=headers.get("x-content-type-options"),
        referrer_policy=headers.get("referrer-policy"),
        permissions_policy=headers.get("permissions-policy"),
    )
    missing: list[str] = []
    if not check.strict_transport_security:
        missing.append("Strict-Transport-Security")
    if not check.content_security_policy:
        missing.append("Content-Security-Policy")
    if not check.x_frame_options:
        missing.append("X-Frame-Options")
    if not check.x_content_type_options:
        missing.append("X-Content-Type-Options")
    if not check.referrer_policy:
        missing.append("Referrer-Policy")
    check.missing_headers = missing
    return check


def detect_header_technologies(headers: dict[str, str]) -> list[str]:
    """Identify software and frameworks revealed through response headers."""
    tech: list[str] = []

    # Server banner
    server = headers.get("server", "").strip()
    if server:
        tech.append(f"Server: {server}")

    # X-Powered-By
    powered_by = headers.get("x-powered-by", "").strip()
    if powered_by:
        tech.append(f"Framework/Runtime: {powered_by}")

    # ASP.NET specific
    if "x-aspnet-version" in headers:
        tech.append(f"ASP.NET: {headers['x-aspnet-version']}")
    if "x-aspnetmvc-version" in headers:
        tech.append(f"ASP.NET MVC: {headers['x-aspnetmvc-version']}")

    # Python / Ruby / PHP hints
    if "x-runtime" in headers:
        tech.append("Ruby / Rails (X-Runtime)")
    if "x-generator" in headers:
        tech.append(f"Generator: {headers['x-generator']}")

    # Reverse proxy / CDN / Cloud indicators
    if "cf-ray" in headers or "cf-cache-status" in headers:
        tech.append("CDN: Cloudflare")
    if "x-amz-cf-id" in headers or "x-amz-cf-pop" in headers:
        tech.append("CDN: AWS CloudFront")
    if "x-varnish" in headers:
        tech.append("Cache: Varnish")
    if "x-sucuri-id" in headers:
        tech.append("WAF: Sucuri")

    return tech


async def perform_http_recon(
    target: TargetScope,
    client: SafeReconClient,
) -> HttpReconData:
    """Execute HTTP reconnaissance against a validated target."""
    response: ReconResponse = await client.fetch(target.canonical_url)

    server_banner = response.headers.get("server")
    header_tech = detect_header_technologies(response.headers)
    sec_headers = analyze_security_headers(response.headers)

    hsts = bool(response.headers.get("strict-transport-security"))
    redirects = [
        {
            "from_url": hop.from_url,
            "to_url": hop.to_url,
            "status_code": hop.status_code,
        }
        for hop in response.redirect_history
    ]

    return HttpReconData(
        url=response.url,
        status_code=response.status_code,
        reason_phrase=response.reason_phrase,
        response_time_ms=response.response_time_ms,
        content_type=response.content_type,
        content_length=response.content_length,
        headers=response.headers,
        server_banner=server_banner,
        header_technologies=header_tech,
        is_https=response.is_tls,
        https_hsts_enabled=hsts,
        redirect_chain=redirects,
        cookies=response.cookies,
        security_headers=sec_headers,
        raw_body=response.body_text,
    )

"""Unit and integration tests for the VulnSight Reconnaissance Engine."""

from __future__ import annotations

import ipaddress
import uuid
from urllib.parse import urlsplit

import httpx
import pytest

from app.core.config import settings
from app.main import app
from app.recon.client import ReconResponse, SafeReconClient
from app.recon.discovery import (
    DiscoverySummary,
    RobotsTxtData,
    SecurityTxtData,
    SitemapData,
    detect_technologies,
    probe_robots_txt,
    probe_sitemap,
)
from app.recon.exceptions import (
    DNSResolutionError,
    RedirectBlockedError,
    SSRFBlockedError,
    TargetValidationError,
)
from app.recon.html_recon import (
    FormInput,
    HtmlForm,
    HtmlReconData,
    parse_html_recon,
)
from app.recon.http_recon import (
    HttpReconData,
    SecurityHeadersCheck,
    analyze_security_headers,
    detect_header_technologies,
)
from app.recon.storage import compute_url_hash, store_discovered_endpoints
from app.recon.validator import (
    CLOUD_METADATA_IPS,
    TargetScope,
    check_ip_ssrf,
    normalize_hostname,
    unwrap_ip,
    validate_recon_target,
    validate_redirect_target,
    validate_target_syntax,
)


# ===========================================================================
# Part 1: Target Validation & SSRF Defense Tests
# ===========================================================================


def test_target_syntax_validation() -> None:
    """Verify valid URLs pass syntax check and invalid schemes/formats fail."""
    # Valid
    p1 = validate_target_syntax("http://localhost:8000/test")
    assert p1.scheme == "http"
    assert p1.hostname == "localhost"
    assert p1.port == 8000
    assert p1.path == "/test"

    p2 = validate_target_syntax("https://example.com/")
    assert p2.scheme == "https"
    assert p2.hostname == "example.com"
    assert p2.port is None

    # Invalid schemes
    with pytest.raises(TargetValidationError, match="Unsupported scheme"):
        validate_target_syntax("ftp://127.0.0.1/")

    with pytest.raises(TargetValidationError, match="Unsupported scheme"):
        validate_target_syntax("file:///etc/passwd")

    with pytest.raises(TargetValidationError, match="Unsupported scheme"):
        validate_target_syntax("gopher://127.0.0.1:70/")

    # Embedded credentials
    with pytest.raises(TargetValidationError, match="Embedded credentials"):
        validate_target_syntax("http://admin:secret@127.0.0.1:8000/")

    # Fragments
    with pytest.raises(TargetValidationError, match="fragment"):
        validate_target_syntax("http://localhost/#section")

    # Invalid port
    with pytest.raises(TargetValidationError, match="invalid port"):
        validate_target_syntax("http://localhost:70000/")


def test_ssrf_blocks_private_and_reserved_ips() -> None:
    """Verify that RFC 1918, link-local, and reserved networks are blocked."""
    private_ips = [
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.100.50",
        "100.64.0.1",       # CGNAT
        "192.0.2.1",        # TEST-NET-1
        "198.51.100.1",     # TEST-NET-2
        "203.0.113.1",      # TEST-NET-3
        "224.0.0.1",        # Multicast
        "240.0.0.1",        # Reserved
    ]
    for ip_str in private_ips:
        ip = ipaddress.ip_address(ip_str)
        with pytest.raises(SSRFBlockedError, match="restricted IP range"):
            check_ip_ssrf(ip, allow_loopback=False)


def test_ssrf_blocks_cloud_metadata_ips() -> None:
    """Verify that cloud metadata IPs (AWS, GCP, Azure, Alibaba) are strictly blocked."""
    metadata_ips = [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
    ]
    for ip_str in metadata_ips:
        ip = ipaddress.ip_address(ip_str)
        with pytest.raises(SSRFBlockedError, match="cloud metadata"):
            check_ip_ssrf(ip, allow_loopback=True)  # Even if allow_loopback is True!


def test_ssrf_unwraps_ipv4_mapped_ipv6() -> None:
    """Verify that IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254) are unwrapped."""
    mapped_metadata = ipaddress.ip_address("::ffff:169.254.169.254")
    unwrapped = unwrap_ip(mapped_metadata)
    assert isinstance(unwrapped, ipaddress.IPv4Address)
    assert str(unwrapped) == "169.254.169.254"

    with pytest.raises(SSRFBlockedError, match="cloud metadata"):
        check_ip_ssrf(mapped_metadata, allow_loopback=True)

    mapped_private = ipaddress.ip_address("::ffff:10.0.0.5")
    with pytest.raises(SSRFBlockedError, match="restricted IP range"):
        check_ip_ssrf(mapped_private, allow_loopback=False)


def test_ssrf_loopback_handling() -> None:
    """Verify loopback is blocked by default, but permitted when allow_loopback=True for local testing."""
    loopback_v4 = ipaddress.ip_address("127.0.0.1")
    loopback_v6 = ipaddress.ip_address("::1")

    # Blocked by default
    with pytest.raises(SSRFBlockedError, match="loopback"):
        check_ip_ssrf(loopback_v4, allow_loopback=False)

    with pytest.raises(SSRFBlockedError, match="loopback"):
        check_ip_ssrf(loopback_v6, allow_loopback=False)

    # Allowed when explicitly authorized for local test lab
    check_ip_ssrf(loopback_v4, allow_loopback=True)
    check_ip_ssrf(loopback_v6, allow_loopback=True)


@pytest.mark.asyncio
async def test_redirect_validation_blocks_out_of_scope_and_ssrf() -> None:
    """Verify that redirect validation prevents open redirect and SSRF pivots."""
    current_url = "http://127.0.0.1:8000/login"

    # Out of scope domain
    with pytest.raises(RedirectBlockedError, match="out-of-scope"):
        await validate_redirect_target(
            current_url=current_url,
            location_header="http://attacker.com/evil",
            initial_target_host="127.0.0.1",
            allowed_hosts={"127.0.0.1"},
            allow_loopback=True,
        )

    # Scheme smuggling
    with pytest.raises(RedirectBlockedError, match="forbidden"):
        await validate_redirect_target(
            current_url=current_url,
            location_header="javascript:alert(1)",
            initial_target_host="127.0.0.1",
            allow_loopback=True,
        )

    # Valid internal redirect
    valid = await validate_redirect_target(
        current_url=current_url,
        location_header="/dashboard",
        initial_target_host="127.0.0.1",
        allowed_hosts={"127.0.0.1"},
        allow_loopback=True,
    )
    assert valid == "http://127.0.0.1:8000/dashboard"


# ===========================================================================
# Part 2: HTTP Reconnaissance Tests
# ===========================================================================


def test_security_headers_analysis() -> None:
    """Verify security headers analyzer flags missing defensive headers."""
    # Secure headers
    headers_secure = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    analysis = analyze_security_headers(headers_secure)
    assert len(analysis.missing_headers) == 0
    assert analysis.x_frame_options == "DENY"

    # Insecure headers
    headers_insecure = {
        "server": "nginx/1.18.0",
        "content-type": "text/html",
    }
    analysis_bad = analyze_security_headers(headers_insecure)
    assert "Strict-Transport-Security" in analysis_bad.missing_headers
    assert "Content-Security-Policy" in analysis_bad.missing_headers
    assert "X-Frame-Options" in analysis_bad.missing_headers
    assert "X-Content-Type-Options" in analysis_bad.missing_headers


def test_header_technologies_detection() -> None:
    """Verify technology banners and frameworks are identified from headers."""
    headers = {
        "server": "Apache/2.4.51 (Unix) OpenSSL/1.1.1l",
        "x-powered-by": "PHP/8.1.0",
        "cf-ray": "7e3b8a1c9d2f-SJC",
        "x-varnish": "1234567",
    }
    tech = detect_header_technologies(headers)
    assert any("Apache" in t for t in tech)
    assert any("PHP/8.1.0" in t for t in tech)
    assert any("Cloudflare" in t for t in tech)
    assert any("Varnish" in t for t in tech)


# ===========================================================================
# Part 3: HTML Reconnaissance Tests (BeautifulSoup)
# ===========================================================================


SAMPLE_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="generator" content="WordPress 6.4.2">
    <title>Juice Shop - Vulnerable Application</title>
    <link rel="stylesheet" href="/assets/style.css">
    <link rel="stylesheet" href="https://cdn.example.com/bootstrap.min.css">
    <script src="/static/app.js"></script>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
    <h1>Welcome to VulnSight Lab</h1>
    <!-- Remember to test /admin/internal-panel before release -->
    
    <nav>
        <a href="/products">Products</a>
        <a href="/contact.html">Contact Us</a>
        <a href="https://external-partner.com/partner">Partner</a>
    </nav>

    <form action="/api/v1/login" method="POST">
        <input type="text" name="username" required>
        <input type="password" name="password" required>
        <input type="hidden" name="csrf_token" value="abc123xyz">
        <button type="submit">Sign In</button>
    </form>

    <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="avatar">
        <input type="submit" value="Upload Avatar">
    </form>

    <div data-endpoint="/api/v1/user/profile">User Info</div>

    <script>
        const apiUrl = "/api/v1/search";
        const configPath = "/config.json";
    </script>
</body>
</html>
"""


def test_html_recon_parsing() -> None:
    """Verify BeautifulSoup extracts titles, forms, inputs, scripts, links, and endpoints."""
    base_url = "http://localhost:3000/"
    data: HtmlReconData = parse_html_recon(base_url, SAMPLE_HTML)

    # Title & Meta
    assert data.title == "Juice Shop - Vulnerable Application"
    assert data.meta_tags.get("generator") == "WordPress 6.4.2"

    # Internal & External Links
    assert "http://localhost:3000/products" in data.internal_links
    assert "http://localhost:3000/contact.html" in data.internal_links
    assert "https://external-partner.com/partner" in data.external_links

    # Forms
    assert len(data.forms) == 2
    login_form = next(f for f in data.forms if f.action.endswith("/api/v1/login"))
    assert login_form.method == "POST"
    assert login_form.has_password is True
    assert login_form.has_file_upload is False

    input_names = [inp.name for inp in login_form.inputs]
    assert "username" in input_names
    assert "password" in input_names
    assert "csrf_token" in input_names

    upload_form = next(f for f in data.forms if f.action.endswith("/upload"))
    assert upload_form.has_file_upload is True

    # Scripts and Stylesheets
    assert "http://localhost:3000/static/app.js" in data.scripts
    assert any("jquery" in s for s in data.external_scripts)
    assert any("style.css" in s for s in data.stylesheets)

    # HTML Comments & Inline Endpoints
    assert "/admin/internal-panel" in data.comments_with_paths
    assert "/api/v1/search" in data.interesting_endpoints
    assert "/config.json" in data.interesting_endpoints
    assert "/api/v1/user/profile" in data.interesting_endpoints


# ===========================================================================
# Part 4: Additional Discovery Tests (robots.txt, technologies)
# ===========================================================================


def test_technology_correlation() -> None:
    """Verify correlation across headers, meta tags, and HTML body."""
    sec = SecurityHeadersCheck()
    http_data = HttpReconData(
        url="http://localhost:3000/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=12.5,
        content_type="text/html",
        content_length=1500,
        headers={"server": "uvicorn", "x-powered-by": "Express"},
        server_banner="uvicorn",
        header_technologies=["Server: uvicorn", "Framework/Runtime: Express"],
        is_https=False,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[{"name": "connect.sid", "masked_value": "[REDACTED]"}],
        security_headers=sec,
        raw_body=SAMPLE_HTML,
    )

    html_data = parse_html_recon("http://localhost:3000/", SAMPLE_HTML)
    techs = detect_technologies(http_data, html_data)

    tech_names = [t.name for t in techs]
    assert "Uvicorn" in tech_names
    assert "Express.js" in tech_names
    assert "Node.js / Express" in tech_names
    assert "jQuery" in tech_names
    assert "OWASP Juice Shop" in tech_names  # Detected from branding/DOM
    assert "WordPress 6.4.2" in tech_names  # Detected from meta generator


# ===========================================================================
# Part 5: Storage Tests
# ===========================================================================


def test_url_hash_computation() -> None:
    """Verify SHA-256 computation for URL deduplication."""
    h1 = compute_url_hash("http://localhost:8000/api/v1/scans")
    h2 = compute_url_hash("http://localhost:8000/api/v1/scans")
    h3 = compute_url_hash("http://localhost:8000/api/v1/other")

    assert len(h1) == 64
    assert h1 == h2
    assert h1 != h3


# ===========================================================================
# Part 6: API Integration Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_api_validate_target_endpoint() -> None:
    """Test POST /api/v1/recon/validate-target."""
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        # Valid authorized local host
        resp = await client.post(
            "/api/v1/recon/validate-target",
            json={"url": "http://127.0.0.1:8000/"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["hostname"] == "127.0.0.1"
        assert body["is_authorized"] is True
        assert body["is_safe"] is True
        assert "127.0.0.1" in body["resolved_ips"]

        # Disallowed host
        resp_bad = await client.post(
            "/api/v1/recon/validate-target",
            json={"url": "http://evil-disallowed-host.com/"},
        )
        assert resp_bad.status_code == 400
        assert "authorized" in resp_bad.json()["error"]["message"].lower()

        # Malformed scheme
        resp_scheme = await client.post(
            "/api/v1/recon/validate-target",
            json={"url": "ftp://127.0.0.1:8000/"},
        )
        assert resp_scheme.status_code == 400


@pytest.mark.asyncio
async def test_robots_and_sitemap_parsing() -> None:
    """Test parsing logic for robots.txt and XML sitemaps."""
    # Test mock robots.txt
    robots_text = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private/api/
    Allow: /public/
    Sitemap: http://localhost:8000/sitemap_index.xml
    """
    target = TargetScope(
        raw_url="http://localhost:8000/",
        canonical_url="http://localhost:8000/",
        scheme="http",
        hostname="localhost",
        port=8000,
        path="/",
        resolved_ips=("127.0.0.1",),
        is_loopback=True,
    )

    class MockReconClient:
        async def fetch(self, url: str) -> ReconResponse:
            if "robots.txt" in url:
                return ReconResponse(
                    url=url,
                    status_code=200,
                    reason_phrase="OK",
                    headers={"content-type": "text/plain"},
                    content_type="text/plain",
                    content_length=len(robots_text),
                    body_text=robots_text,
                    response_time_ms=5.0,
                )
            if "sitemap" in url:
                xml_content = """<?xml version="1.0" encoding="UTF-8"?>
                <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
                    <url><loc>http://localhost:8000/products</loc></url>
                    <url><loc>http://localhost:8000/about</loc></url>
                </urlset>"""
                return ReconResponse(
                    url=url,
                    status_code=200,
                    reason_phrase="OK",
                    headers={"content-type": "application/xml"},
                    content_type="application/xml",
                    content_length=len(xml_content),
                    body_text=xml_content,
                    response_time_ms=5.0,
                )
            return ReconResponse(
                url=url,
                status_code=404,
                reason_phrase="Not Found",
                headers={},
                content_type="text/plain",
                content_length=0,
                body_text="",
                response_time_ms=5.0,
            )

    client = MockReconClient()
    robots_data = await probe_robots_txt(target, client)
    assert robots_data.found is True
    assert "/admin/" in robots_data.disallowed_paths
    assert "/private/api/" in robots_data.disallowed_paths
    assert "http://localhost:8000/sitemap_index.xml" in robots_data.sitemaps

    sitemap_data = await probe_sitemap(
        target,
        client,
        candidate_urls=robots_data.sitemaps,
    )
    assert sitemap_data.found is True
    assert "http://localhost:8000/products" in sitemap_data.urls
    assert "http://localhost:8000/about" in sitemap_data.urls


@pytest.mark.asyncio
async def test_endpoints_api_retrieval_and_filtering() -> None:
    """Test GET /api/v1/scans/{scan_id}/endpoints and /recon."""
    from app.db.engine import AsyncSessionLocal
    from app.models.endpoint import DiscoveredEndpoint
    from app.models.scan import ScanSession
    from app.models.target import ScanTarget
    from sqlalchemy import delete

    if AsyncSessionLocal is None:
        pytest.skip("Database not configured.")

    scan_id = uuid.uuid4()
    target_id = uuid.uuid4()

    async with AsyncSessionLocal() as session:
        scan = ScanSession(
            id=scan_id,
            name=f"Recon-Test-{scan_id.hex[:6]}",
            profile="lean_mvp",
            status="completed",
            status_message="Recon complete.",
        )
        target = ScanTarget(
            id=target_id,
            scan_id=scan_id,
            url="http://127.0.0.1:8000/",
            scheme="http",
            hostname="127.0.0.1",
            port=8000,
            path="/",
        )
        ep1 = DiscoveredEndpoint(
            scan_id=scan_id,
            target_id=target_id,
            method="GET",
            url="http://127.0.0.1:8000/api/v1/health",
            url_hash=compute_url_hash("http://127.0.0.1:8000/api/v1/health"),
            path="/api/v1/health",
            status_code=200,
            content_type="application/json",
        )
        ep2 = DiscoveredEndpoint(
            scan_id=scan_id,
            target_id=target_id,
            method="POST",
            url="http://127.0.0.1:8000/api/v1/scans",
            url_hash=compute_url_hash("http://127.0.0.1:8000/api/v1/scans"),
            path="/api/v1/scans",
            status_code=201,
            content_type="application/json",
        )
        session.add_all([scan, target, ep1, ep2])
        await session.commit()

    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            # 1. List all endpoints
            resp = await client.get(f"/api/v1/scans/{scan_id}/endpoints")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total"] == 2
            assert len(data["items"]) == 2

            # 2. Filter by method
            resp_filtered = await client.get(
                f"/api/v1/scans/{scan_id}/endpoints",
                params={"method": "POST"},
            )
            assert resp_filtered.status_code == 200
            data_filtered = resp_filtered.json()
            assert data_filtered["total"] == 1
            assert data_filtered["items"][0]["method"] == "POST"
            assert data_filtered["items"][0]["path"] == "/api/v1/scans"

            # 3. Get scan recon summary
            resp_recon = await client.get(f"/api/v1/scans/{scan_id}/recon")
            assert resp_recon.status_code == 200
            recon_body = resp_recon.json()
            assert recon_body["scan_id"] == str(scan_id)
            assert recon_body["total_endpoints"] == 2
    finally:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(DiscoveredEndpoint).where(DiscoveredEndpoint.scan_id == scan_id)
            )
            await session.execute(
                delete(ScanTarget).where(ScanTarget.scan_id == scan_id)
            )
            await session.execute(
                delete(ScanSession).where(ScanSession.id == scan_id)
            )
            await session.commit()


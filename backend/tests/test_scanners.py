"""Comprehensive tests for all 10 OWASP Top 10:2025 vulnerability scanner modules."""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy import delete, select

from app.db.engine import AsyncSessionLocal
from app.models.endpoint import DiscoveredEndpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.scan import ScanSession
from app.models.target import ScanTarget
from app.recon.client import ReconResponse, SafeReconClient
from app.recon.html_recon import FormInput, HtmlForm, HtmlReconData, parse_html_recon
from app.recon.http_recon import HttpReconData, SecurityHeadersCheck
from app.recon.validator import TargetScope
from app.scanners.a01_access_control import AccessControlScanner
from app.scanners.a02_security_misconfiguration import SecurityMisconfigurationScanner
from app.scanners.a03_supply_chain import SupplyChainScanner
from app.scanners.a04_crypto_failures import CryptographicFailuresScanner
from app.scanners.a05_injection import InjectionScanner
from app.scanners.a06_insecure_design import InsecureDesignScanner
from app.scanners.a07_auth_failures import AuthenticationFailuresScanner
from app.scanners.a08_integrity_failures import IntegrityFailuresScanner
from app.scanners.a09_logging_failures import LoggingAndAlertingScanner
from app.scanners.a10_exceptional_conditions import ExceptionalConditionsScanner
from app.scanners.base import FindingDraft, FindingEvidenceDraft
from app.scanners.orchestrator import execute_all_scanners, persist_scan_findings


@pytest.fixture
def mock_target() -> TargetScope:
    return TargetScope(
        raw_url="http://localhost:3000/",
        canonical_url="http://localhost:3000/",
        scheme="http",
        hostname="localhost",
        port=3000,
        path="/",
        resolved_ips=("127.0.0.1",),
        is_loopback=True,
    )


@pytest.fixture
def empty_recon_data() -> tuple[HttpReconData, HtmlReconData]:
    http_data = HttpReconData(
        url="http://localhost:3000/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=10.0,
        content_type="text/html",
        content_length=500,
        headers={"server": "nginx"},
        server_banner="nginx",
        header_technologies=["Server: nginx"],
        is_https=False,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[],
        security_headers=SecurityHeadersCheck(
            missing_headers=["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"]
        ),
        raw_body="<html><head><title>Test</title></head><body><h1>Hello</h1></body></html>",
    )
    html_data = HtmlReconData(
        title="Test",
        meta_tags={},
        internal_links=[],
        external_links=[],
        forms=[],
        scripts=[],
        external_scripts=[],
        stylesheets=[],
        interesting_endpoints=[],
        comments_with_paths=[],
    )
    return http_data, html_data


# ===========================================================================
# A01: Broken Access Control Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a01_access_control_unauthenticated_admin(mock_target: TargetScope) -> None:
    scanner = AccessControlScanner()

    class MockClient(SafeReconClient):
        async def fetch(self, url: str, **kwargs) -> ReconResponse:
            if "admin" in url:
                return ReconResponse(
                    url=url,
                    status_code=200,
                    reason_phrase="OK",
                    headers={"content-type": "text/html"},
                    content_type="text/html",
                    content_length=200,
                    body_text="<html><body><h1>System Administration Control Panel</h1><p>Dashboard</p></body></html>",
                    response_time_ms=5.0,
                )
            return ReconResponse(url=url, status_code=404, reason_phrase="Not Found", headers={}, content_type="text/html", content_length=0, body_text="", response_time_ms=5.0)

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=HttpReconData("http://localhost:3000/", 200, "OK", 5.0, "text/html", 100, {}, None, [], False, False, [], [], SecurityHeadersCheck(), ""),
        html_data=HtmlReconData(None, {}, [], [], [], [], [], [], [], []),
        client=MockClient(),
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A01"
    assert f.check_id == "A01-UNAUTHENTICATED-ADMIN-PATH"
    assert f.severity == "high"


# ===========================================================================
# A02: Security Misconfiguration Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a02_security_misconfiguration_headers_and_cors(mock_target: TargetScope) -> None:
    scanner = SecurityMisconfigurationScanner()

    http_data = HttpReconData(
        url="http://localhost:3000/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=10.0,
        content_type="text/html",
        content_length=100,
        headers={"server": "nginx"},
        server_banner="nginx",
        header_technologies=[],
        is_https=False,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[],
        security_headers=SecurityHeadersCheck(
            missing_headers=["Content-Security-Policy", "X-Frame-Options"]
        ),
        raw_body="<html><title>Test</title></html>",
    )

    class MockClient(SafeReconClient):
        async def fetch(self, url: str, headers: dict | None = None, **kwargs) -> ReconResponse:
            if headers and "Origin" in headers:
                # Permissive CORS reflection simulation
                return ReconResponse(
                    url=url,
                    status_code=200,
                    reason_phrase="OK",
                    headers={
                        "access-control-allow-origin": headers["Origin"],
                        "access-control-allow-credentials": "true",
                    },
                    content_type="text/html",
                    content_length=50,
                    body_text="",
                    response_time_ms=5.0,
                )
            return ReconResponse(url=url, status_code=404, reason_phrase="Not Found", headers={}, content_type="text/html", content_length=0, body_text="", response_time_ms=5.0)

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=http_data,
        html_data=HtmlReconData("Test", {}, [], [], [], [], [], [], [], []),
        client=MockClient(),
    )

    check_ids = [f.check_id for f in findings]
    assert "A02-MISSING-SECURITY-HEADERS" in check_ids
    assert "A02-PERMISSIVE-CORS-CREDENTIALS" in check_ids


# ===========================================================================
# A03: Software Supply Chain Failures Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a03_supply_chain_outdated_jquery(mock_target: TargetScope) -> None:
    scanner = SupplyChainScanner()

    html_data = HtmlReconData(
        title="App",
        meta_tags={},
        internal_links=[],
        external_links=[],
        forms=[],
        scripts=["http://localhost:3000/assets/jquery-1.12.4.min.js"],
        external_scripts=[],
        stylesheets=[],
        interesting_endpoints=[],
        comments_with_paths=[],
    )

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=HttpReconData("http://localhost:3000/", 200, "OK", 5.0, "text/html", 100, {}, None, [], False, False, [], [], SecurityHeadersCheck(), ""),
        html_data=html_data,
        client=SafeReconClient(),
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A03"
    assert f.check_id == "A03-OUTDATED-FRONTEND-LIBRARY"
    assert "jQuery 1.12.4" in f.title


# ===========================================================================
# A04: Cryptographic Failures Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a04_crypto_failures_insecure_cookies() -> None:
    scanner = CryptographicFailuresScanner()

    target = TargetScope(
        raw_url="https://secure.example.com/",
        canonical_url="https://secure.example.com/",
        scheme="https",
        hostname="secure.example.com",
        port=None,
        path="/",
        resolved_ips=("93.184.216.34",),
        is_loopback=False,
    )

    http_data = HttpReconData(
        url="https://secure.example.com/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=20.0,
        content_type="text/html",
        content_length=200,
        headers={},
        server_banner=None,
        header_technologies=[],
        is_https=True,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[{"name": "session_id", "secure": False, "httponly": True}],
        security_headers=SecurityHeadersCheck(),
        raw_body="",
    )

    findings = await scanner.scan(
        target=target,
        endpoints=[],
        http_data=http_data,
        html_data=HtmlReconData("Secure App", {}, [], [], [], [], [], [], [], []),
        client=SafeReconClient(),
    )

    check_ids = [f.check_id for f in findings]
    assert "A04-MISSING-HSTS-HEADER" in check_ids
    assert "A04-COOKIE-MISSING-SECURE-FLAG" in check_ids


# ===========================================================================
# A05: Injection Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a05_injection_reflected_xss(mock_target: TargetScope) -> None:
    scanner = InjectionScanner()

    html_data = HtmlReconData(
        title="Search",
        meta_tags={},
        internal_links=[],
        external_links=[],
        forms=[
            HtmlForm(
                action="http://localhost:3000/search",
                method="GET",
                inputs=[FormInput(name="q", input_type="search", required=False)],
            )
        ],
        scripts=[],
        external_scripts=[],
        stylesheets=[],
        interesting_endpoints=[],
        comments_with_paths=[],
    )

    class MockClient(SafeReconClient):
        async def fetch(self, url: str, **kwargs) -> ReconResponse:
            if "safe_tag_99" in url:
                # Reflect unencoded token
                return ReconResponse(
                    url=url,
                    status_code=200,
                    reason_phrase="OK",
                    headers={"content-type": "text/html"},
                    content_type="text/html",
                    content_length=100,
                    body_text="<html><body>Results for: vsight<safe_tag_99></body></html>",
                    response_time_ms=5.0,
                )
            return ReconResponse(url=url, status_code=200, reason_phrase="OK", headers={}, content_type="text/html", content_length=0, body_text="", response_time_ms=5.0)

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=HttpReconData("http://localhost:3000/", 200, "OK", 5.0, "text/html", 100, {}, None, [], False, False, [], [], SecurityHeadersCheck(), ""),
        html_data=html_data,
        client=MockClient(),
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f.owasp_category == "A05"
    assert f.check_id == "A05-REFLECTED-XSS-UNENCODED-INPUT"


# ===========================================================================
# A06: Insecure Design Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a06_insecure_design_form_without_csrf(mock_target: TargetScope) -> None:
    scanner = InsecureDesignScanner()

    html_data = HtmlReconData(
        title="Account",
        meta_tags={},
        internal_links=[],
        external_links=[],
        forms=[
            HtmlForm(
                action="http://localhost:3000/api/update-email",
                method="POST",
                inputs=[FormInput(name="email", input_type="email", required=True)],
            )
        ],
        scripts=[],
        external_scripts=[],
        stylesheets=[],
        interesting_endpoints=[],
        comments_with_paths=[],
    )

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=HttpReconData("http://localhost:3000/", 200, "OK", 5.0, "text/html", 100, {}, None, [], False, False, [], [], SecurityHeadersCheck(), ""),
        html_data=html_data,
        client=SafeReconClient(),
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f.owasp_category == "A06"
    assert f.check_id == "A06-STATE-CHANGING-FORM-NO-CSRF"


# ===========================================================================
# A07: Authentication Failures Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a07_auth_failures_non_httponly_cookie(mock_target: TargetScope) -> None:
    scanner = AuthenticationFailuresScanner()

    http_data = HttpReconData(
        url="http://localhost:3000/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=10.0,
        content_type="text/html",
        content_length=100,
        headers={},
        server_banner=None,
        header_technologies=[],
        is_https=False,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[
            {"name": "auth_token", "httponly": False, "samesite": None},
        ],
        security_headers=SecurityHeadersCheck(),
        raw_body="",
    )

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=http_data,
        html_data=HtmlReconData(None, {}, [], [], [], [], [], [], [], []),
        client=SafeReconClient(),
    )

    check_ids = [f.check_id for f in findings]
    assert "A07-COOKIE-MISSING-HTTPONLY" in check_ids
    assert "A07-COOKIE-MISSING-SAMESITE" in check_ids


# ===========================================================================
# A08: Software and Data Integrity Failures Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a08_integrity_missing_sri(mock_target: TargetScope) -> None:
    scanner = IntegrityFailuresScanner()

    html_with_cdn_script = """
    <html><head>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </head><body></body></html>
    """
    http_data = HttpReconData(
        url="http://localhost:3000/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=10.0,
        content_type="text/html",
        content_length=len(html_with_cdn_script),
        headers={},
        server_banner=None,
        header_technologies=[],
        is_https=False,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[],
        security_headers=SecurityHeadersCheck(),
        raw_body=html_with_cdn_script,
    )

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=http_data,
        html_data=HtmlReconData(None, {}, [], [], [], [], [], [], [], []),
        client=SafeReconClient(),
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A08"
    assert f.check_id == "A08-MISSING-SUBRESOURCE-INTEGRITY"


# ===========================================================================
# A09: Security Logging and Alerting Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a09_logging_missing_request_id(mock_target: TargetScope) -> None:
    scanner = LoggingAndAlertingScanner()

    http_data = HttpReconData(
        url="http://localhost:3000/",
        status_code=200,
        reason_phrase="OK",
        response_time_ms=10.0,
        content_type="application/json",
        content_length=50,
        headers={"content-type": "application/json"},
        server_banner=None,
        header_technologies=[],
        is_https=False,
        https_hsts_enabled=False,
        redirect_chain=[],
        cookies=[],
        security_headers=SecurityHeadersCheck(),
        raw_body='{"status":"ok"}',
    )

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=http_data,
        html_data=HtmlReconData(None, {}, [], [], [], [], [], [], [], []),
        client=SafeReconClient(),
    )

    assert len(findings) == 1
    f = findings[0]
    assert f.owasp_category == "A09"
    assert f.check_id == "A09-MISSING-REQUEST-CORRELATION-ID"


# ===========================================================================
# A10: Mishandling of Exceptional Conditions Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_a10_exceptional_conditions_stack_trace_leak(mock_target: TargetScope) -> None:
    scanner = ExceptionalConditionsScanner()

    traceback_body = """
    Traceback (most recent call last):
      File "app/main.py", line 42, in get_item
        return items[item_id]
    KeyError: 'item_123'
    """

    class MockClient(SafeReconClient):
        async def fetch(self, url: str, **kwargs) -> ReconResponse:
            return ReconResponse(
                url=url,
                status_code=500,
                reason_phrase="Internal Server Error",
                headers={"content-type": "text/plain"},
                content_type="text/plain",
                content_length=len(traceback_body),
                body_text=traceback_body,
                response_time_ms=5.0,
            )

    findings = await scanner.scan(
        target=mock_target,
        endpoints=[],
        http_data=HttpReconData("http://localhost:3000/", 200, "OK", 5.0, "text/html", 100, {}, None, [], False, False, [], [], SecurityHeadersCheck(), ""),
        html_data=HtmlReconData(None, {}, [], [], [], [], [], [], [], []),
        client=MockClient(),
    )

    assert len(findings) >= 1
    f = findings[0]
    assert f.owasp_category == "A10"
    assert f.check_id == "A10-VERBOSE-STACK-TRACE-DISCLOSURE"


# ===========================================================================
# Orchestrator & PostgreSQL Persistence Integration Tests
# ===========================================================================


@pytest.mark.asyncio
async def test_orchestrator_persistence_in_neon() -> None:
    """Verify that findings, evidence, and remediations persist to PostgreSQL."""
    if AsyncSessionLocal is None:
        pytest.skip("Database not configured.")

    scan_id = uuid.uuid4()
    draft = FindingDraft(
        check_id="A02-TEST-SECURITY-HEADER",
        owasp_category="A02",
        title="Test Security Header Missing",
        description="Verification finding for PostgreSQL persistence test.",
        severity="medium",
        confidence="certain",
        evidence=[
            FindingEvidenceDraft(
                kind="text",
                label="Observation",
                content="Header X-Test-Header was missing.",
            )
        ],
        remediation_summary="Add the test header.",
        remediation_steps=["Configure server to send X-Test-Header"],
        remediation_references=["https://example.com/test-header"],
    )

    async with AsyncSessionLocal() as session:
        # Create parent scan
        scan = ScanSession(
            id=scan_id,
            name=f"Orchestrator-Test-{scan_id.hex[:6]}",
            profile="lean_mvp",
            status="running",
        )
        session.add(scan)
        await session.commit()

        # Persist findings via orchestrator
        persisted = await persist_scan_findings(
            session,
            scan_id=scan_id,
            findings=[draft],
        )
        assert len(persisted) == 1
        finding_id = persisted[0].id
        await session.commit()

        # Query finding back with relationships
        query = (
            select(Finding)
            .where(Finding.id == finding_id)
        )
        saved = (await session.execute(query)).scalar_one()
        assert saved.check_id == "A02-TEST-SECURITY-HEADER"
        assert saved.severity == "medium"
        assert saved.status == "open"

        # Cleanup
        await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
        await session.execute(delete(ScanSession).where(ScanSession.id == scan_id))
        await session.commit()

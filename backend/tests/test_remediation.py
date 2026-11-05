"""Comprehensive tests for Finding Management, Risk Scoring, and Remediation Center."""

from __future__ import annotations

import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from app.core.redaction import redact_sensitive_text
from app.db.engine import AsyncSessionLocal
from app.main import app
from app.models.endpoint import DiscoveredEndpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.scan import ScanSession
from app.models.target import ScanTarget
from app.remediation.knowledgebase import get_remediation_guide, list_available_guides
from app.services.risk_engine import calculate_risk_assessment
from app.services.verification_runner import run_fix_verification


# ---------------------------------------------------------------------------
# Part 1: Sensitive Information Redaction Tests
# ---------------------------------------------------------------------------

def test_redaction_engine() -> None:
    """Verify that credentials, tokens, and cookies are redacted from evidence."""
    raw_evidence = (
        "GET /api/user HTTP/1.1\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID\n"
        "Cookie: session=secret_session_token_12345; theme=dark\n"
        "Body: {\"username\": \"admin\", \"password\": \"SuperSecretP@ssw0rd!\"}\n"
        "API Key: api_key='TEST_STRIPE_KEY_NOT_REAL'\n"
        "AWS Key: AKIAIOSFODNN7EXAMPLE"
    )

    scrubbed, was_redacted = redact_sensitive_text(raw_evidence)

    assert was_redacted is True
    assert "SuperSecretP@ssw0rd!" not in scrubbed
    assert "[REDACTED]" in scrubbed
    assert "secret_session_token_12345" not in scrubbed
    assert "[REDACTED_SESSION_COOKIE]" in scrubbed
    assert "Authorization: [REDACTED_AUTH_TOKEN]" in scrubbed
    assert "[REDACTED_AWS_KEY]" in scrubbed
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
    assert "[REDACTED_API_KEY]" in scrubbed



# ---------------------------------------------------------------------------
# Part 2: Risk Assessment Engine Tests
# ---------------------------------------------------------------------------
def test_risk_assessment_engine() -> None:
    """Verify transparent risk score calculation across severity and confidence."""
    # Critical + Certain
    crit = calculate_risk_assessment(severity="critical", confidence="certain", owasp_category="A01")
    assert crit.score >= 9.0
    assert crit.rating == "Critical"
    assert crit.impact_score == 10.0
    assert crit.confidence_weight == 1.0
    assert "VulnSight Risk Score is an internal automated heuristic" in crit.disclaimer
    assert "Score =" in crit.formula

    # Low + Tentative
    low = calculate_risk_assessment(severity="low", confidence="tentative", owasp_category="A09")
    assert low.score <= 3.0
    assert low.rating in ("Low", "Informational")
    assert low.impact_score == 3.0
    assert low.confidence_weight == 0.80

    # Custom Likelihood override
    custom = calculate_risk_assessment(
        severity="high",
        confidence="firm",
        owasp_category="A05",
        custom_likelihood=0.2,
    )
    assert custom.likelihood_score == 0.2
    assert custom.likelihood_level == "low"


# ---------------------------------------------------------------------------
# Part 3: Remediation Knowledgebase Multi-Framework Tests
# ---------------------------------------------------------------------------
def test_remediation_knowledgebase_coverage() -> None:
    """Verify that every OWASP category guide provides multi-framework examples."""
    guides = list_available_guides()
    assert len(guides) >= 8

    # Test A01 Guide
    a01 = get_remediation_guide("A01-ADMIN-EXPOSED")
    assert a01 is not None
    assert a01.owasp_category == "A01"
    assert a01.vulnerability_meaning
    assert a01.business_impact
    assert a01.root_cause
    assert len(a01.step_by_step_remediation) >= 3

    # Check multi-framework code examples (Node/Express, FastAPI, Django, Spring)
    examples = a01.code_examples
    assert "nodejs_express" in examples
    assert "python_fastapi" in examples
    assert "python_django" in examples
    assert "java_spring" in examples

    assert examples["nodejs_express"].vulnerable_code
    assert examples["nodejs_express"].secure_code
    assert examples["python_fastapi"].vulnerable_code
    assert examples["python_fastapi"].secure_code

    # Test A05 SQL Syntax Error Guide has SQL prepared statement examples
    a05_sql = get_remediation_guide("A05-SQL-SYNTAX-ERROR")
    assert a05_sql is not None
    assert "sql" in a05_sql.code_examples
    assert "SELECT" in a05_sql.code_examples["sql"].secure_code


# ---------------------------------------------------------------------------
# Part 4: Fix Verification Criteria Tests
# ---------------------------------------------------------------------------
def test_fix_verification_criteria() -> None:
    """Verify that remediation guides define explicit fix verification instructions."""
    guide = get_remediation_guide("A02-SECURITY-HEADERS")
    assert guide is not None

    criteria = guide.fix_verification
    assert "Content-Security-Policy" in criteria.what_should_change
    assert criteria.check_to_rerun
    assert criteria.expected_evidence
    assert criteria.inconclusive_conditions


# ---------------------------------------------------------------------------
# Part 5: End-to-End API Integration Tests (Findings, Remediation, Verification)
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_findings_and_remediation_api_lifecycle() -> None:
    """Test full finding lifecycle, risk scoring, remediation guide, and fix verification."""
    if AsyncSessionLocal is None:
        pytest.skip("Database session is not available.")

    scan_id = uuid.uuid4()
    target_id = uuid.uuid4()
    endpoint_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    async with AsyncSessionLocal() as session:
        # Create scan session
        scan = ScanSession(
            id=scan_id,
            name="Test Scan Session",
            status="completed",
            profile="lean_mvp",
        )
        session.add(scan)

        # Create target
        target = ScanTarget(
            id=target_id,
            scan_id=scan_id,
            url="http://localhost:3000/",
            scheme="http",
            hostname="localhost",
            port=3000,
            path="/",
            is_authorized=True,
        )
        session.add(target)

        # Create endpoint
        ep_url = "http://localhost:3000/api/admin/users"
        ep = DiscoveredEndpoint(
            id=endpoint_id,
            scan_id=scan_id,
            target_id=target_id,
            url=ep_url,
            url_hash="6c6c756f70a1a8c3d9a785b88c4bdf45e45a278913b827e69f8e52cb7b64f331",
            path="/api/admin/users",
            method="GET",
            status_code=200,
            content_type="application/json",
        )
        session.add(ep)

        # Create finding
        finding = Finding(
            id=finding_id,
            scan_id=scan_id,
            endpoint_id=endpoint_id,
            check_id="A01-ADMIN-EXPOSED",
            owasp_category="A01",
            title="Unauthenticated Access to Administrative Endpoint (/api/admin/users)",
            description="The administrative endpoint was accessed without authentication.",
            severity="high",
            confidence="firm",
            status="open",
            risk_score=7.1,
            detection_method="active_path_probe",
            fingerprint="test_fingerprint_abc123",
        )
        session.add(finding)
        await session.flush()

        # Add evidence
        ev = Evidence(
            finding_id=finding_id,
            kind="response",
            label="Admin Response Snippet",
            content="HTTP 200 OK - Admin Dashboard Users List",
            content_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_redacted=False,
        )
        session.add(ev)

        # Add initial remediation record
        rem = Remediation(
            finding_id=finding_id,
            summary="Protect administrative route with RBAC authentication middleware.",
            steps=["Implement requireAuth middleware", "Return 401 on missing token"],
            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
            status="not_started",
        )
        session.add(rem)
        await session.commit()

    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 1. List findings for scan
            list_resp = await client.get(f"/api/v1/scans/{scan_id}/findings")
            assert list_resp.status_code == 200
            list_data = list_resp.json()
            assert list_data["total"] == 1
            item = list_data["items"][0]
            assert item["id"] == str(finding_id)
            assert item["vulnerability_name"] == finding.title
            assert item["affected_url"] == "http://localhost:3000/api/admin/users"
            assert item["severity"] == "high"
            assert item["confidence"] == "firm"
            assert item["risk_score"] == 7.1
            assert item["detection_method"] == "active_path_probe"
            assert item["remediation_status"] == "not_started"

            # 2. Get individual finding details
            detail_resp = await client.get(f"/api/v1/findings/{finding_id}")
            assert detail_resp.status_code == 200
            detail_data = detail_resp.json()
            assert detail_data["id"] == str(finding_id)
            assert len(detail_data["evidence"]) == 1
            assert len(detail_data["technical_evidence"]) == 1
            assert detail_data["risk_assessment"] is not None
            assert detail_data["risk_assessment"]["score"] >= 7.0
            assert "VulnSight Risk Score" in detail_data["risk_assessment"]["disclaimer"]
            assert detail_data["remediation_guide"] is not None
            assert "nodejs_express" in detail_data["remediation_guide"]["code_examples"]

            # 3. Get dedicated remediation guide endpoint
            guide_resp = await client.get(f"/api/v1/findings/{finding_id}/remediation-guide")
            assert guide_resp.status_code == 200
            guide_data = guide_resp.json()
            assert guide_data["check_id"] == "A01-ADMIN-EXPOSED"
            assert "python_fastapi" in guide_data["code_examples"]
            assert guide_data["fix_verification"]["what_should_change"]

            # 4. Browse remediation center directly
            center_resp = await client.get("/api/v1/remediation-center")
            assert center_resp.status_code == 200
            assert len(center_resp.json()) >= 8

            check_resp = await client.get("/api/v1/remediation-center/A01-ADMIN-EXPOSED")
            assert check_resp.status_code == 200
            assert check_resp.json()["owasp_category"] == "A01"

            # 5. Update remediation status
            patch_resp = await client.patch(
                f"/api/v1/findings/{finding_id}/remediation",
                json={"status": "in_progress", "notes": "Engineer assigned to add RBAC middleware."},
            )
            assert patch_resp.status_code == 200
            assert patch_resp.json()["status"] == "in_progress"

            # 6. Request Fix Verification
            verify_resp = await client.post(
                f"/api/v1/findings/{finding_id}/verify",
                json={"note": "RBAC middleware deployed to staging environment."},
            )
            assert verify_resp.status_code == 202
            verify_data = verify_resp.json()
            assert verify_data["finding_id"] == str(finding_id)
            assert verify_data["status"] in ("passed", "failed", "error", "pending")

    finally:
        # Cleanup test records
        async with AsyncSessionLocal() as session:
            await session.execute(delete(ScanSession).where(ScanSession.id == scan_id))
            await session.commit()

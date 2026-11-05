"""Unit tests for the Fix Verification Engine and Cybersecurity Principles."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx

from app.services.verification_runner import (
    VERDICT_FAILED,
    VERDICT_FIXED,
    VERDICT_INCONCLUSIVE,
    VERDICT_PERSISTS,
    run_fix_verification,
)


class DummyResponse:
    def __init__(self, status_code: int, text: str = "", headers: dict | None = None, url: str = "http://127.0.0.1:8000"):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = httpx.URL(url)


def _create_mock_finding(check_id: str, owasp_category: str, target_url: str = "http://127.0.0.1:8000/admin"):
    finding = MagicMock()
    finding.id = uuid.uuid4()
    finding.check_id = check_id
    finding.owasp_category = owasp_category
    finding.title = "Test Finding"
    finding.severity = "high"
    finding.status = "open"
    finding.scan_id = uuid.uuid4()

    endpoint = MagicMock()
    endpoint.url = target_url
    finding.endpoint = endpoint

    remediation = MagicMock()
    remediation.status = "in_progress"
    finding.remediation = remediation

    ev1 = MagicMock()
    ev1.kind = "http_response"
    ev1.label = "Initial Response"
    ev1.content = "Initial vulnerable response"
    ev1.content_sha256 = "0" * 64
    finding.evidence = [ev1]

    scan = MagicMock()
    scan.targets = []
    finding.scan = scan

    return finding


def _create_mock_session(finding):
    mock_session = MagicMock()
    mock_session.execute = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = finding
    mock_session.execute.return_value = mock_result
    mock_session.flush = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.add = MagicMock()
    return mock_session


@pytest.mark.asyncio
async def test_fix_verification_confirms_fixed_access_control():
    """Verify that an HTTP 401 challenge produces a VERDICT_FIXED and updates finding to 'verified'."""
    finding = _create_mock_finding("A01-ADMIN", "A01:2025", "http://127.0.0.1:8000/admin")
    mock_session = _create_mock_session(finding)

    # Mock client returning HTTP 401 Unauthorized
    with patch("app.services.verification_runner.validate_recon_target", new_callable=AsyncMock) as mock_val, \
         patch("app.services.verification_runner.SafeReconClient") as mock_client_cls:
        
        mock_val.return_value = MagicMock(is_loopback=True)
        mock_client = MagicMock()
        mock_client.fetch = AsyncMock(return_value=DummyResponse(401, text="Unauthorized: Authentication required"))
        mock_client_cls.return_value = mock_client

        run = await run_fix_verification(mock_session, finding.id, note="Applied AuthMiddleware")

        assert run.status == "fixed"
        assert run.details["verification_verdict"] == VERDICT_FIXED
        assert "Defensive access control verified" in run.result_summary
        assert finding.status == "verified"
        assert finding.remediation.status == "done"
        assert run.details["comparison_delta"]["status_code_changed"] is True


@pytest.mark.asyncio
async def test_fix_verification_detects_persisting_vulnerability():
    """Verify that an HTTP 200 with admin UI elements marks the run as persisting."""
    finding = _create_mock_finding("A01-ADMIN", "A01:2025", "http://127.0.0.1:8000/admin")
    mock_session = _create_mock_session(finding)

    # Mock client returning HTTP 200 with Dashboard elements
    with patch("app.services.verification_runner.validate_recon_target", new_callable=AsyncMock) as mock_val, \
         patch("app.services.verification_runner.SafeReconClient") as mock_client_cls:
        
        mock_val.return_value = MagicMock(is_loopback=True)
        mock_client = MagicMock()
        mock_client.fetch = AsyncMock(return_value=DummyResponse(200, text="<html><body><h1>Admin Dashboard</h1></body></html>"))
        mock_client_cls.return_value = mock_client

        run = await run_fix_verification(mock_session, finding.id)

        assert run.status == "persists"
        assert run.details["verification_verdict"] == VERDICT_PERSISTS
        assert "Vulnerability persists" in run.result_summary
        assert finding.status == "open"
        assert finding.remediation.status == "in_progress"


@pytest.mark.asyncio
async def test_fix_verification_server_error_is_inconclusive_not_fixed():
    """CORE PRINCIPLE: An HTTP 500 or timeout must NOT be treated as fixed.

    Absence of evidence != evidence of absence. A server fault prevents
    proper verification and must be classified as INCONCLUSIVE.
    """
    finding = _create_mock_finding("A01-ADMIN", "A01:2025", "http://127.0.0.1:8000/admin")
    mock_session = _create_mock_session(finding)

    # Mock client returning HTTP 500 Internal Server Error
    with patch("app.services.verification_runner.validate_recon_target", new_callable=AsyncMock) as mock_val, \
         patch("app.services.verification_runner.SafeReconClient") as mock_client_cls:
        
        mock_val.return_value = MagicMock(is_loopback=True)
        mock_client = MagicMock()
        mock_client.fetch = AsyncMock(return_value=DummyResponse(500, text="Internal Server Error"))
        mock_client_cls.return_value = mock_client

        run = await run_fix_verification(mock_session, finding.id)

        # Must be inconclusive, NEVER fixed!
        assert run.status == "inconclusive"
        assert run.details["verification_verdict"] == VERDICT_INCONCLUSIVE
        assert "Inconclusive" in run.result_summary
        # Finding must NOT be changed to verified!
        assert finding.status == "open"
        assert finding.remediation.status != "done"


@pytest.mark.asyncio
async def test_fix_verification_security_headers_verification():
    """Verify security headers re-test logic for A02."""
    finding = _create_mock_finding("A02-HEADER", "A02:2025", "http://127.0.0.1:8000/api")
    mock_session = _create_mock_session(finding)

    # 1. First test with headers present:
    with patch("app.services.verification_runner.validate_recon_target", new_callable=AsyncMock) as mock_val, \
         patch("app.services.verification_runner.SafeReconClient") as mock_client_cls:
        
        mock_val.return_value = MagicMock(is_loopback=True)
        mock_client = MagicMock()
        mock_client.fetch = AsyncMock(return_value=DummyResponse(
            200,
            text="OK",
            headers={
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
        ))
        mock_client_cls.return_value = mock_client

        run = await run_fix_verification(mock_session, finding.id)
        assert run.status == "fixed"
        assert run.details["verification_verdict"] == VERDICT_FIXED
        assert finding.status == "verified"


@pytest.mark.asyncio
async def test_fix_verification_network_exception_is_verification_failed():
    """Verify network connection exception is handled gracefully as VERDICT_FAILED."""
    finding = _create_mock_finding("A02-HEADER", "A02:2025", "http://127.0.0.1:8000/api")
    mock_session = _create_mock_session(finding)

    with patch("app.services.verification_runner.validate_recon_target", new_callable=AsyncMock) as mock_val, \
         patch("app.services.verification_runner.SafeReconClient") as mock_client_cls:
        
        mock_val.return_value = MagicMock(is_loopback=True)
        mock_client = MagicMock()
        mock_client.fetch = AsyncMock(side_effect=httpx.ConnectError("Connection refused by host"))
        mock_client_cls.return_value = mock_client

        run = await run_fix_verification(mock_session, finding.id)
        assert run.status == "error"
        assert run.details["verification_verdict"] == VERDICT_FAILED
        assert "Verification failed" in run.result_summary
        assert "Connection refused" in run.details["error"]

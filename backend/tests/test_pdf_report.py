"""Unit and integration tests for PDF Report Generation using ReportLab."""

from __future__ import annotations

import base64
import hashlib
import io
from typing import Any

import pytest

from app.services.pdf_generator import generate_pdf_report


def _sample_snapshot(with_findings: bool = True) -> dict[str, Any]:
    findings = []
    if with_findings:
        findings = [
            {
                "id": "11111111-2222-3333-4444-555555555555",
                "title": "Unauthenticated Administrative Dashboard",
                "severity": "critical",
                "confidence": "certain",
                "check_id": "A01-ADMIN-EXPOSURE",
                "owasp_category": "A01:2025",
                "description": "Administrative control panel is reachable without authentication challenges.",
                "endpoint": {
                    "method": "GET",
                    "url": "http://127.0.0.1:8000/admin",
                    "path": "/admin",
                    "status_code": 200,
                    "content_type": "text/html",
                },
                "evidence": [
                    {
                        "id": "ev-1",
                        "kind": "http_response",
                        "label": "Admin Panel HTML",
                        "content": "HTTP 200 OK\n\n<h1>Admin Dashboard</h1>\nToken: [REDACTED_API_KEY]",
                        "content_sha256": hashlib.sha256(b"admin").hexdigest(),
                        "is_redacted": True,
                    }
                ],
                "remediation": {
                    "summary": "Enforce RBAC and authentication checks before routing to /admin.",
                    "steps": [
                        "Configure middleware authentication filter.",
                        "Enforce HTTP 401 challenge on missing session cookie.",
                    ],
                    "status": "in_progress",
                },
                "verification_runs": [
                    {
                        "id": "run-1",
                        "status": "fixed",
                        "result_summary": "Fixed: Endpoint now returns HTTP 401 challenge.",
                        "created_at": "2026-11-05T12:00:00Z",
                    }
                ],
            },
            {
                "id": "22222222-3333-4444-5555-666666666666",
                "title": "Missing Defensive Security Headers",
                "severity": "medium",
                "confidence": "firm",
                "check_id": "A02-SECURITY-HEADERS",
                "owasp_category": "A02:2025",
                "description": "Response does not include X-Content-Type-Options or Content-Security-Policy.",
                "endpoint": {
                    "method": "GET",
                    "url": "http://127.0.0.1:8000/api/data",
                    "path": "/api/data",
                    "status_code": 200,
                    "content_type": "application/json",
                },
                "evidence": [
                    {
                        "id": "ev-2",
                        "kind": "http_headers",
                        "label": "Response Headers",
                        "content": "Server: uvicorn\nContent-Type: application/json",
                        "content_sha256": hashlib.sha256(b"headers").hexdigest(),
                        "is_redacted": False,
                    }
                ],
                "remediation": {
                    "summary": "Add X-Content-Type-Options: nosniff header.",
                    "steps": ["Apply SecurityHeadersMiddleware in FastAPI."],
                    "status": "not_started",
                },
                "verification_runs": [],
            },
        ]

    return {
        "schema_version": "1.0",
        "generated_at": "2026-11-05T18:00:00Z",
        "disclaimer": "Authorized security assessment conducted under controlled parameters.",
        "scan": {
            "id": "00000000-0000-0000-0000-000000000001",
            "name": "Intentionally Vulnerable Lab Audit",
            "status": "completed",
            "profile": "full",
            "status_message": "Completed assessment across all OWASP categories.",
            "created_at": "2026-11-05T17:50:00Z",
            "started_at": "2026-11-05T17:51:00Z",
            "finished_at": "2026-11-05T17:59:00Z",
            "target_count": 1,
            "finding_count": len(findings),
        },
        "targets": [
            {
                "id": "tgt-1",
                "url": "http://127.0.0.1:8000",
                "scheme": "http",
                "hostname": "127.0.0.1",
                "port": 8000,
                "path": "/",
                "is_authorized": True,
                "authorization_reference": "SEC-AUDIT-2026-001",
            }
        ],
        "summary": {
            "by_severity": {
                "critical": 1 if with_findings else 0,
                "high": 0,
                "medium": 1 if with_findings else 0,
                "low": 0,
                "info": 0,
            },
            "by_status": {"open": 1, "verified": 1} if with_findings else {},
            "by_owasp_category": {
                "A01:2025": 1 if with_findings else 0,
                "A02:2025": 1 if with_findings else 0,
            },
        },
        "findings": findings,
    }


def test_pdf_report_generates_valid_pdf_stream():
    """Verify PDF output begins with standard %PDF- header and contains non-trivial payload."""
    snapshot = _sample_snapshot(with_findings=True)
    pdf_bytes = generate_pdf_report(snapshot)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000
    assert pdf_bytes.startswith(b"%PDF-")
    # Verify standard PDF end marker
    assert b"%%EOF" in pdf_bytes[-1024:]


def test_pdf_report_handles_zero_findings_cleanly():
    """Ensure report can compile when target has 0 findings (clean posture)."""
    snapshot = _sample_snapshot(with_findings=False)
    pdf_bytes = generate_pdf_report(snapshot)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")
    assert b"%%EOF" in pdf_bytes[-1024:]


def test_pdf_report_encodes_and_decodes_base64_durable_storage():
    """Ensure generated PDF bytes can be base64-encoded for database Text column and restored without corruption."""
    snapshot = _sample_snapshot(with_findings=True)
    pdf_bytes = generate_pdf_report(snapshot)

    encoded_str = base64.b64encode(pdf_bytes).decode("ascii")
    assert isinstance(encoded_str, str)

    restored_bytes = base64.b64decode(encoded_str.encode("ascii"))
    assert restored_bytes == pdf_bytes
    assert hashlib.sha256(restored_bytes).hexdigest() == hashlib.sha256(pdf_bytes).hexdigest()


def test_pdf_report_title_metadata_and_watermark():
    """Ensure PDF includes explicit title metadata (avoiding Chrome 'anonymous') and Khushi Shah watermark."""
    import re

    snapshot = _sample_snapshot(with_findings=True)
    pdf_bytes = generate_pdf_report(snapshot)

    # 1. Verify Title does NOT say anonymous
    title_match = re.search(rb"/Title\s*(\([^)]*\)|<[^>]*>)", pdf_bytes)
    assert title_match is not None
    title_str = title_match.group(0).decode("latin1")
    assert "anonymous" not in title_str.lower()
    assert "Khushi Shah" in title_str

    # 2. Verify Khushi Shah watermark exists in canvas stream
    assert b"Khushi Shah" in pdf_bytes

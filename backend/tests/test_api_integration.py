"""Integration tests against the real Neon database.

These tests use the FastAPI app in-process through ``httpx.ASGITransport``.
They need a working ``DATABASE_URL`` and an up-to-date schema
(``alembic upgrade head``). Each test cleans up the scans it creates.

Run only these tests with::

    .\\.venv\\Scripts\\pytest.exe tests\\test_api_integration.py -v
"""

from __future__ import annotations

import hashlib
import json
import uuid

import httpx
import pytest
from sqlalchemy import delete, select, text
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.db.engine import AsyncSessionLocal, dispose_engine
from app.main import app
from app.models.audit_log import AuditLog
from app.models.endpoint import DiscoveredEndpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.scan import ScanSession
from app.models.target import ScanTarget
from app.models.verification import VerificationRun

API = "/api/v1"
HOST = "http://127.0.0.1:8000"

pytestmark = pytest.mark.asyncio(loop_scope="session")


@pytest.fixture(scope="session", autouse=True)
async def _dispose_engine():
    """Close pooled Neon connections at the end of the test session."""

    yield
    await dispose_engine()


@pytest.fixture
async def client() -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
        timeout=30.0,
    ) as http_client:
        yield http_client


async def _delete_scan(scan_id: uuid.UUID) -> None:
    if AsyncSessionLocal is None:
        return
    async with AsyncSessionLocal() as session:
        await session.execute(
            delete(AuditLog).where(AuditLog.scan_id == scan_id)
        )
        await session.execute(
            delete(ScanSession).where(ScanSession.id == scan_id)
        )
        await session.commit()


async def _create_scan(
    client: httpx.AsyncClient,
    *,
    name: str | None = None,
    targets: list[dict[str, str]] | None = None,
) -> dict:
    response = await client.post(
        f"{API}/scans",
        json={
            "name": name or f"pytest-scan-{uuid.uuid4().hex[:12]}",
            "profile": "lean_mvp",
            "targets": targets
            or [
                {
                    "url": f"{HOST}/",
                    "authorization_reference": "pytest-local-lab",
                },
                {"url": "http://localhost:8000/"},
            ],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.fixture
async def scan(client: httpx.AsyncClient):
    """Create a scan through the API and remove it afterwards."""

    created = await _create_scan(client)
    yield created
    await _delete_scan(uuid.UUID(created["id"]))


async def _seed_finding(scan_id: uuid.UUID) -> uuid.UUID:
    """Insert a finding and its related rows directly through SQLAlchemy."""

    if AsyncSessionLocal is None:
        raise RuntimeError("Database is not configured.")

    async with AsyncSessionLocal() as session:
        target = (
            await session.execute(
                select(ScanTarget)
                .where(ScanTarget.scan_id == scan_id)
                .limit(1)
            )
        ).scalar_one()

        url = f"{HOST}/login"
        endpoint = DiscoveredEndpoint(
            scan_id=scan_id,
            target_id=target.id,
            method="GET",
            url=url,
            url_hash=hashlib.sha256(url.encode()).hexdigest(),
            path="/login",
            status_code=200,
            content_type="text/html",
        )
        session.add(endpoint)
        await session.flush()

        finding = Finding(
            scan_id=scan_id,
            endpoint_id=endpoint.id,
            check_id="A05-SECURITY-HEADERS",
            owasp_category="A05",
            title="Missing Content-Security-Policy header",
            description="The response did not include a CSP header.",
            severity="high",
            confidence="firm",
            status="open",
            fingerprint=uuid.uuid4().hex,
        )
        session.add(finding)
        await session.flush()

        evidence_text = "Response headers did not contain Content-Security-Policy."
        session.add(
            Evidence(
                finding_id=finding.id,
                kind="text",
                label="Response header observation",
                content=evidence_text,
                content_sha256=hashlib.sha256(
                    evidence_text.encode()
                ).hexdigest(),
                is_redacted=True,
            )
        )
        session.add(
            Remediation(
                finding_id=finding.id,
                summary="Add a restrictive Content-Security-Policy header.",
                steps=["Define a policy", "Send it on every response"],
                references=["https://owasp.org/www-project-secure-headers/"],
                status="not_started",
            )
        )
        await session.commit()
        return finding.id


# ---------------------------------------------------------------------------
# Connectivity and schema
# ---------------------------------------------------------------------------


async def test_database_health(client: httpx.AsyncClient) -> None:
    response = await client.get(f"{API}/health/db")

    assert response.status_code == 200
    assert response.json()["database"] == "connected"


async def test_expected_tables_and_partial_index_exist() -> None:
    assert AsyncSessionLocal is not None

    expected = {
        "users",
        "scan_sessions",
        "scan_targets",
        "discovered_endpoints",
        "findings",
        "evidence",
        "remediations",
        "verification_runs",
        "reports",
        "audit_logs",
    }
    async with AsyncSessionLocal() as session:
        tables = set(
            (
                await session.execute(
                    text(
                        "select tablename from pg_tables "
                        "where schemaname = 'public'"
                    )
                )
            )
            .scalars()
            .all()
        )
        assert expected <= tables

        index_definition = (
            await session.execute(
                text(
                    "select indexdef from pg_indexes "
                    "where indexname = 'uq_scan_sessions_single_running'"
                )
            )
        ).scalar_one()
        assert "UNIQUE INDEX" in index_definition
        assert "status" in index_definition
        assert "running" in index_definition

        foreign_keys = (
            await session.execute(
                text(
                    "select count(*) from information_schema.table_constraints "
                    "where constraint_schema = 'public' "
                    "and constraint_type = 'FOREIGN KEY'"
                )
            )
        ).scalar_one()
        assert foreign_keys >= 12


# ---------------------------------------------------------------------------
# Scan CRUD, lifecycle, and history
# ---------------------------------------------------------------------------


async def test_scan_creation_and_retrieval(
    client: httpx.AsyncClient,
    scan: dict,
) -> None:
    assert scan["status"] == "pending"
    assert scan["target_count"] == 2
    assert scan["finding_count"] == 0
    assert {target["hostname"] for target in scan["targets"]} == {
        "127.0.0.1",
        "localhost",
    }
    assert scan["targets"][0]["authorization_reference"] == "pytest-local-lab"
    assert scan["targets"][0]["is_authorized"] is True

    response = await client.get(f"{API}/scans/{scan['id']}")
    assert response.status_code == 200
    detail = response.json()
    assert detail["id"] == scan["id"]
    assert len(detail["targets"]) == 2

    status_response = await client.get(f"{API}/scans/{scan['id']}/status")
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "pending"


async def test_scan_lifecycle_completes_with_placeholder(
    client: httpx.AsyncClient,
    scan: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "scan_executor_mode", "placeholder")
    started = await client.post(f"{API}/scans/{scan['id']}/start")

    assert started.status_code == 202
    assert started.json()["status"] == "running"
    assert started.json()["started_at"] is not None

    # ASGITransport waits for background tasks, so the placeholder executor has
    # already closed the run by the time the start request returns.
    status_response = await client.get(f"{API}/scans/{scan['id']}/status")
    assert status_response.status_code == 200
    body = status_response.json()
    assert body["status"] == "completed"
    assert body["finished_at"] is not None
    assert "Scanner modules are not implemented" in body["status_message"]

    restart = await client.post(f"{API}/scans/{scan['id']}/start")
    assert restart.status_code == 409
    assert restart.json()["error"]["code"] == "conflict"

    cancel = await client.post(f"{API}/scans/{scan['id']}/cancel")
    assert cancel.status_code == 409


async def test_pending_scan_can_be_cancelled(client: httpx.AsyncClient) -> None:
    created = await _create_scan(client)
    try:
        cancelled = await client.post(f"{API}/scans/{created['id']}/cancel")

        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "cancelled"
        assert cancelled.json()["finished_at"] is not None
    finally:
        await _delete_scan(uuid.UUID(created["id"]))


async def test_scan_history_and_status_filter(
    client: httpx.AsyncClient,
    scan: dict,
) -> None:
    history = await client.get(f"{API}/scans", params={"limit": 100})

    assert history.status_code == 200
    body = history.json()
    assert body["total"] >= 1
    assert scan["id"] in {item["id"] for item in body["items"]}

    filtered = await client.get(
        f"{API}/scans",
        params={"status": "pending", "limit": 100},
    )
    assert filtered.status_code == 200
    filtered_body = filtered.json()
    assert all(item["status"] == "pending" for item in filtered_body["items"])
    assert scan["id"] in {item["id"] for item in filtered_body["items"]}


# ---------------------------------------------------------------------------
# Validation and error handling
# ---------------------------------------------------------------------------


async def test_request_validation_and_allowlist(
    client: httpx.AsyncClient,
) -> None:
    cases = [
        ({"targets": [{"url": "http://example.com/"}]}, 400),
        (
            {
                "targets": [
                    {"url": f"{HOST}/"},
                    {"url": f"{HOST}/"},
                ]
            },
            400,
        ),
        ({"targets": [{"url": "ftp://127.0.0.1/"}]}, 400),
        ({"targets": [{"url": "http://user:pass@127.0.0.1/"}]}, 400),
        ({"targets": [{"url": f"{HOST}/#fragment"}]}, 400),
        ({"targets": [{"url": f"{HOST}/?a=1"}]}, 400),
        ({"targets": [{"url": "   "}]}, 422),
        ({"targets": []}, 422),
        (
            {
                "targets": [
                    {"url": f"{HOST}/{index}"} for index in range(11)
                ]
            },
            400,
        ),
    ]

    for payload, expected_status in cases:
        response = await client.post(f"{API}/scans", json=payload)
        assert response.status_code == expected_status, (
            payload,
            response.text,
        )
        assert "error" in response.json()


async def test_unknown_and_malformed_ids(client: httpx.AsyncClient) -> None:
    unknown_scan = await client.get(f"{API}/scans/{uuid.uuid4()}")
    assert unknown_scan.status_code == 404
    assert unknown_scan.json()["error"]["code"] == "not_found"

    unknown_finding = await client.get(f"{API}/findings/{uuid.uuid4()}")
    assert unknown_finding.status_code == 404

    unknown_report = await client.get(f"{API}/reports/{uuid.uuid4()}")
    assert unknown_report.status_code == 404

    malformed = await client.get(f"{API}/scans/not-a-uuid")
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "validation_error"


# ---------------------------------------------------------------------------
# Findings, relationships, remediation, and verification
# ---------------------------------------------------------------------------


async def test_finding_retrieval_with_relationships(
    client: httpx.AsyncClient,
    scan: dict,
) -> None:
    finding_id = await _seed_finding(uuid.UUID(scan["id"]))

    listing = await client.get(f"{API}/scans/{scan['id']}/findings")
    assert listing.status_code == 200
    body = listing.json()
    assert body["total"] == 1
    assert body["items"][0]["severity"] == "high"
    assert body["items"][0]["owasp_category"] == "A05"

    by_severity = await client.get(
        f"{API}/scans/{scan['id']}/findings",
        params={"severity": "high"},
    )
    assert by_severity.json()["total"] == 1

    by_severity_empty = await client.get(
        f"{API}/scans/{scan['id']}/findings",
        params={"severity": "critical"},
    )
    assert by_severity_empty.json()["total"] == 0

    detail = await client.get(f"{API}/findings/{finding_id}")
    assert detail.status_code == 200
    finding = detail.json()
    assert finding["check_id"] == "A05-SECURITY-HEADERS"
    assert finding["endpoint"]["path"] == "/login"
    assert len(finding["evidence"]) == 1
    assert finding["evidence"][0]["is_redacted"] is True
    assert finding["remediation"]["status"] == "not_started"
    assert finding["verification_runs"] == []

    scan_detail = await client.get(f"{API}/scans/{scan['id']}")
    assert scan_detail.json()["finding_count"] == 1


async def test_remediation_workflow(
    client: httpx.AsyncClient,
    scan: dict,
) -> None:
    finding_id = await _seed_finding(uuid.UUID(scan["id"]))

    in_progress = await client.patch(
        f"{API}/findings/{finding_id}/remediation",
        json={"status": "in_progress", "notes": "Header draft prepared."},
    )
    assert in_progress.status_code == 200
    assert in_progress.json()["status"] == "in_progress"
    assert in_progress.json()["notes"] == "Header draft prepared."

    finding = await client.get(f"{API}/findings/{finding_id}")
    assert finding.json()["status"] == "in_progress"

    done = await client.patch(
        f"{API}/findings/{finding_id}/remediation",
        json={"status": "done"},
    )
    assert done.status_code == 200
    assert done.json()["status"] == "done"

    finding = await client.get(f"{API}/findings/{finding_id}")
    assert finding.json()["status"] == "remediated"

    invalid = await client.patch(
        f"{API}/findings/{finding_id}/remediation",
        json={"status": "banana"},
    )
    assert invalid.status_code == 422


async def test_verification_request_history(
    client: httpx.AsyncClient,
    scan: dict,
) -> None:
    finding_id = await _seed_finding(uuid.UUID(scan["id"]))

    requested = await client.post(
        f"{API}/findings/{finding_id}/verify",
        json={"note": "Please re-test after deployment."},
    )
    assert requested.status_code == 202
    body = requested.json()
    assert body["status"] == "pending"
    assert body["finding_id"] == str(finding_id)

    duplicate = await client.post(
        f"{API}/findings/{finding_id}/verify",
        json={},
    )
    assert duplicate.status_code == 409

    detail = await client.get(f"{API}/findings/{finding_id}")
    runs = detail.json()["verification_runs"]
    assert len(runs) == 1
    assert runs[0]["status"] == "pending"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


async def test_report_generation_versions_and_download(
    client: httpx.AsyncClient,
    scan: dict,
) -> None:
    await _seed_finding(uuid.UUID(scan["id"]))

    first = await client.post(
        f"{API}/scans/{scan['id']}/reports",
        json={"format": "json"},
    )
    assert first.status_code == 201
    first_body = first.json()
    assert first_body["version"] == 1
    assert first_body["status"] == "generated"
    assert first_body["size_bytes"] > 0
    assert first_body["download_url"].endswith(
        f"/reports/{first_body['id']}/download"
    )

    second = await client.post(
        f"{API}/scans/{scan['id']}/reports",
        json={"format": "json"},
    )
    assert second.status_code == 201
    assert second.json()["version"] == 2

    html_report = await client.post(
        f"{API}/scans/{scan['id']}/reports",
        json={"format": "html"},
    )
    assert html_report.status_code == 201
    assert html_report.json()["version"] == 1

    download = await client.get(f"{API}/reports/{first_body['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/json")
    assert "attachment" in download.headers["content-disposition"]

    snapshot = json.loads(download.content)
    assert snapshot["scan"]["id"] == scan["id"]
    assert snapshot["findings"][0]["check_id"] == "A05-SECURITY-HEADERS"
    assert snapshot["summary"]["by_severity"]["high"] == 1

    html_download = await client.get(
        f"{API}/reports/{html_report.json()['id']}/download"
    )
    assert html_download.status_code == 200
    assert b"VulnSight report" in html_download.content

    report_list = await client.get(f"{API}/scans/{scan['id']}/reports")
    assert report_list.status_code == 200
    assert report_list.json()["total"] == 3

    metadata = await client.get(f"{API}/reports/{first_body['id']}")
    assert metadata.status_code == 200
    assert metadata.json()["file_name"].endswith(".json")


# ---------------------------------------------------------------------------
# Database constraints
# ---------------------------------------------------------------------------


async def test_foreign_key_constraint_rejects_orphan_finding() -> None:
    assert AsyncSessionLocal is not None

    async with AsyncSessionLocal() as session:
        session.add(
            Finding(
                scan_id=uuid.uuid4(),
                check_id="A01-ORPHAN",
                owasp_category="A01",
                title="Orphan",
                description="Should not be insertable.",
                severity="low",
                confidence="firm",
                status="open",
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


async def test_check_constraints_reject_invalid_target() -> None:
    assert AsyncSessionLocal is not None

    async with AsyncSessionLocal() as session:
        scan = ScanSession(
            name=f"pytest-constraint-{uuid.uuid4().hex[:8]}",
            status="pending",
        )
        session.add(scan)
        await session.flush()
        session.add(
            ScanTarget(
                scan_id=scan.id,
                url="ftp://127.0.0.1/",
                scheme="ftp",
                hostname="127.0.0.1",
                port=21,
                path="/",
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
        # The rollback also discards the unsaved scan.
        await session.rollback()

    async with AsyncSessionLocal() as session:
        scan = ScanSession(
            name=f"pytest-constraint-{uuid.uuid4().hex[:8]}",
            status="pending",
        )
        session.add(scan)
        await session.flush()
        session.add(
            ScanTarget(
                scan_id=scan.id,
                url=f"{HOST}/",
                scheme="http",
                hostname="127.0.0.1",
                port=70000,
                path="/",
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
        await session.rollback()


async def test_only_one_running_scan_is_allowed() -> None:
    assert AsyncSessionLocal is not None

    first_id = uuid.uuid4()
    async with AsyncSessionLocal() as session:
        first = ScanSession(
            id=first_id,
            name=f"pytest-running-{first_id.hex[:8]}",
            status="running",
        )
        session.add(first)
        await session.commit()

    try:
        async with AsyncSessionLocal() as session:
            session.add(
                ScanSession(
                    name=f"pytest-running-{uuid.uuid4().hex[:8]}",
                    status="running",
                )
            )
            with pytest.raises(IntegrityError):
                await session.commit()
            await session.rollback()
    finally:
        async with AsyncSessionLocal() as session:
            await session.execute(
                delete(ScanSession).where(ScanSession.id == first_id)
            )
            await session.commit()

"""Exercise the VulnSight API end to end against the running server.

Usage (from ``backend``, with uvicorn already running):

    .\\.venv\\Scripts\\python.exe scripts\\e2e_smoke.py

The script creates one scan, starts it, waits for the placeholder executor to
finish, generates both report formats, checks validation errors, then deletes
the scan it created. It prints every request and a short result summary.
"""

from __future__ import annotations

import asyncio
import sys
import time
import uuid

import httpx
from sqlalchemy import delete

from app.db.engine import AsyncSessionLocal, dispose_engine
from app.models.audit_log import AuditLog
from app.models.scan import ScanSession

BASE_URL = "http://127.0.0.1:8000/api/v1"


def show(label: str, response: httpx.Response) -> dict | None:
    body: dict | None = None
    try:
        body = response.json()
    except ValueError:
        body = None
    print(f"[{response.status_code}] {label}")
    return body


async def cleanup(scan_id: uuid.UUID) -> None:
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
    await dispose_engine()


def main() -> int:
    created_scan_id: uuid.UUID | None = None
    failures: list[str] = []

    with httpx.Client(timeout=30.0) as client:
        health = client.get(f"{BASE_URL}/health")
        show("GET /health", health)
        if health.status_code != 200:
            failures.append("health check failed")

        db_health = client.get(f"{BASE_URL}/health/db")
        show("GET /health/db", db_health)
        if db_health.status_code != 200:
            failures.append("database health check failed")

        payload = {
            "name": f"e2e smoke {int(time.time())}",
            "profile": "lean_mvp",
            "targets": [
                {
                    "url": "http://127.0.0.1:8000/",
                    "authorization_reference": "local-lab",
                },
                {"url": "http://localhost:8000/"},
            ],
        }
        created = client.post(f"{BASE_URL}/scans", json=payload)
        body = show("POST /scans", created)
        if created.status_code != 201 or body is None:
            print("Cannot continue without a created scan.")
            print(body)
            return 1
        created_scan_id = uuid.UUID(body["id"])
        print(f"    scan id: {created_scan_id}")

        detail = client.get(f"{BASE_URL}/scans/{created_scan_id}")
        show("GET /scans/{id}", detail)
        if detail.status_code != 200:
            failures.append("scan detail failed")

        started = client.post(f"{BASE_URL}/scans/{created_scan_id}/start")
        started_body = show("POST /scans/{id}/start", started)
        if started.status_code != 202 or not started_body:
            failures.append("scan start failed")
        elif started_body["status"] != "running":
            failures.append("start did not return running")

        deadline = time.time() + 20
        final_status = None
        while time.time() < deadline:
            status_response = client.get(
                f"{BASE_URL}/scans/{created_scan_id}/status"
            )
            if status_response.status_code != 200:
                failures.append("scan status failed")
                break
            status_body = status_response.json()
            final_status = status_body["status"]
            if final_status in {"completed", "failed", "cancelled"}:
                print(f"[200] GET /scans/{{id}}/status -> {final_status}")
                break
            time.sleep(0.5)
        else:
            failures.append("scan did not reach a terminal state")

        if final_status != "completed":
            failures.append(f"placeholder scan ended as {final_status}")

        history = client.get(f"{BASE_URL}/scans", params={"limit": 5})
        history_body = show("GET /scans?limit=5", history)
        if history.status_code != 200 or not history_body:
            failures.append("scan history failed")
        elif str(created_scan_id) not in {
            item["id"] for item in history_body["items"]
        }:
            failures.append("created scan missing from history")

        findings = client.get(f"{BASE_URL}/scans/{created_scan_id}/findings")
        findings_body = show("GET /scans/{id}/findings", findings)
        if findings.status_code != 200 or not findings_body:
            failures.append("finding list failed")
        elif findings_body["total"] != 0:
            failures.append("placeholder scan unexpectedly produced findings")

        json_report = client.post(
            f"{BASE_URL}/scans/{created_scan_id}/reports",
            json={"format": "json"},
        )
        json_body = show("POST /scans/{id}/reports (json)", json_report)
        if json_report.status_code != 201 or not json_body:
            failures.append("json report generation failed")
        else:
            download = client.get(
                f"{BASE_URL}/reports/{json_body['id']}/download"
            )
            print(
                f"[{download.status_code}] GET /reports/{{id}}/download "
                f"({len(download.content)} bytes, "
                f"{download.headers.get('content-type')})"
            )
            if download.status_code != 200 or not download.content:
                failures.append("json report download failed")

        html_report = client.post(
            f"{BASE_URL}/scans/{created_scan_id}/reports",
            json={"format": "html"},
        )
        html_body = show("POST /scans/{id}/reports (html)", html_report)
        if html_report.status_code != 201 or not html_body:
            failures.append("html report generation failed")
        else:
            download = client.get(
                f"{BASE_URL}/reports/{html_body['id']}/download"
            )
            print(
                f"[{download.status_code}] GET /reports/{{id}}/download "
                f"({len(download.content)} bytes, "
                f"{download.headers.get('content-type')})"
            )
            if download.status_code != 200 or b"VulnSight report" not in download.content:
                failures.append("html report download failed")

        # --- Validation and error paths -------------------------------------
        bad_host = client.post(
            f"{BASE_URL}/scans",
            json={
                "targets": [{"url": "http://example.com/"}],
            },
        )
        show("POST /scans with disallowed host", bad_host)
        if bad_host.status_code != 400:
            failures.append("allowlist rejection did not return 400")

        duplicate = client.post(
            f"{BASE_URL}/scans",
            json={
                "targets": [
                    {"url": "http://127.0.0.1:8000/"},
                    {"url": "http://127.0.0.1:8000/"},
                ],
            },
        )
        show("POST /scans with duplicate targets", duplicate)
        if duplicate.status_code != 400:
            failures.append("duplicate target rejection did not return 400")

        bad_scheme = client.post(
            f"{BASE_URL}/scans",
            json={"targets": [{"url": "ftp://127.0.0.1/"}]},
        )
        show("POST /scans with ftp scheme", bad_scheme)
        if bad_scheme.status_code != 400:
            failures.append("scheme rejection did not return 400")

        empty = client.post(f"{BASE_URL}/scans", json={"targets": []})
        show("POST /scans with no targets", empty)
        if empty.status_code != 422:
            failures.append("empty target list did not return 422")

        missing = client.get(f"{BASE_URL}/scans/{uuid.uuid4()}")
        show("GET /scans/{unknown-uuid}", missing)
        if missing.status_code != 404:
            failures.append("unknown scan did not return 404")

        bad_finding = client.get(f"{BASE_URL}/findings/{uuid.uuid4()}")
        show("GET /findings/{unknown-uuid}", bad_finding)
        if bad_finding.status_code != 404:
            failures.append("unknown finding did not return 404")

        restart = client.post(f"{BASE_URL}/scans/{created_scan_id}/start")
        show("POST /scans/{id}/start on completed scan", restart)
        if restart.status_code != 409:
            failures.append("restarting a completed scan did not return 409")

    if created_scan_id is not None:
        asyncio.run(cleanup(created_scan_id))
        print(f"Cleaned up scan {created_scan_id}")

    if failures:
        print("\nFAILURES:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print("\nAll end-to-end checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

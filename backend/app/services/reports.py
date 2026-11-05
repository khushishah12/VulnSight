"""Report generation and retrieval.

Reports are immutable snapshots. Regenerating a report creates a new version so
historical output is not silently overwritten.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ConflictError, NotFoundError
from app.models.finding import Finding
from app.models.report import Report
from app.models.scan import ScanSession
from app.schemas.report import ReportListResponse, ReportRead
from app.services.audit import record_audit
from app.services.pdf_generator import generate_pdf_report

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


async def _build_snapshot(
    session: AsyncSession,
    scan_id: uuid.UUID,
) -> dict[str, Any]:
    result = await session.execute(
        select(ScanSession)
        .options(
            selectinload(ScanSession.targets),
            selectinload(ScanSession.findings).selectinload(Finding.endpoint),
            selectinload(ScanSession.findings).selectinload(Finding.evidence),
            selectinload(ScanSession.findings).selectinload(
                Finding.remediation
            ),
            selectinload(ScanSession.findings).selectinload(
                Finding.verification_runs
            ),
        )
        .where(ScanSession.id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise NotFoundError("Scan not found.")

    findings = sorted(
        scan.findings,
        key=lambda finding: (
            _SEVERITY_RANK.get(finding.severity, 99),
            finding.created_at,
        ),
    )

    finding_rows: list[dict[str, Any]] = []
    severity_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    owasp_counts: Counter[str] = Counter()

    for finding in findings:
        severity_counts[finding.severity] += 1
        status_counts[finding.status] += 1
        owasp_counts[finding.owasp_category] += 1

        endpoint = None
        if finding.endpoint is not None:
            endpoint = {
                "id": str(finding.endpoint.id),
                "method": finding.endpoint.method,
                "url": finding.endpoint.url,
                "path": finding.endpoint.path,
                "status_code": finding.endpoint.status_code,
                "content_type": finding.endpoint.content_type,
            }

        remediation = None
        if finding.remediation is not None:
            remediation = {
                "summary": finding.remediation.summary,
                "steps": finding.remediation.steps,
                "references": finding.remediation.references,
                "status": finding.remediation.status,
                "notes": finding.remediation.notes,
                "updated_at": _iso(finding.remediation.updated_at),
            }

        finding_rows.append(
            {
                "id": str(finding.id),
                "check_id": finding.check_id,
                "owasp_category": finding.owasp_category,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "status": finding.status,
                "fingerprint": finding.fingerprint,
                "created_at": _iso(finding.created_at),
                "endpoint": endpoint,
                "evidence": [
                    {
                        "id": str(evidence.id),
                        "kind": evidence.kind,
                        "label": evidence.label,
                        "content": evidence.content,
                        "content_sha256": evidence.content_sha256,
                        "is_redacted": evidence.is_redacted,
                    }
                    for evidence in finding.evidence
                ],
                "remediation": remediation,
                "verification_runs": [
                    {
                        "id": str(run.id),
                        "status": run.status,
                        "result_summary": run.result_summary,
                        "created_at": _iso(run.created_at),
                        "finished_at": _iso(run.finished_at),
                    }
                    for run in sorted(
                        finding.verification_runs,
                        key=lambda item: item.created_at,
                        reverse=True,
                    )
                ],
            }
        )

    return {
        "schema_version": "1.0",
        "generated_at": _iso(datetime.now(timezone.utc)),
        "disclaimer": (
            "Authorized local assessment. This build uses a placeholder scan "
            "executor; no vulnerability checks or network probing were "
            "performed. Findings shown here come only from data already stored "
            "in VulnSight."
        ),
        "scan": {
            "id": str(scan.id),
            "name": scan.name,
            "status": scan.status,
            "profile": scan.profile,
            "status_message": scan.status_message,
            "created_at": _iso(scan.created_at),
            "started_at": _iso(scan.started_at),
            "finished_at": _iso(scan.finished_at),
            "target_count": len(scan.targets),
            "finding_count": len(findings),
        },
        "targets": [
            {
                "id": str(target.id),
                "url": target.url,
                "scheme": target.scheme,
                "hostname": target.hostname,
                "port": target.port,
                "path": target.path,
                "is_authorized": target.is_authorized,
                "authorization_reference": target.authorization_reference,
            }
            for target in scan.targets
        ],
        "summary": {
            "by_severity": dict(severity_counts),
            "by_status": dict(status_counts),
            "by_owasp_category": dict(owasp_counts),
        },
        "findings": finding_rows,
    }


def _render_json(snapshot: dict[str, Any]) -> str:
    return json.dumps(snapshot, indent=2, ensure_ascii=False)


def _render_html(snapshot: dict[str, Any]) -> str:
    scan = snapshot["scan"]
    summary = snapshot["summary"]
    severity_order = ["critical", "high", "medium", "low", "info"]

    severity_rows = "".join(
        f"<tr><td>{_esc(level)}</td>"
        f"<td>{_esc(summary['by_severity'].get(level, 0))}</td></tr>"
        for level in severity_order
    )
    target_rows = "".join(
        "<tr>"
        f"<td>{_esc(target['url'])}</td>"
        f"<td>{_esc(target['authorization_reference'] or 'Not recorded')}</td>"
        f"<td>{_esc('Yes' if target['is_authorized'] else 'No')}</td>"
        "</tr>"
        for target in snapshot["targets"]
    ) or '<tr><td colspan="3">No targets recorded.</td></tr>'

    finding_sections: list[str] = []
    for finding in snapshot["findings"]:
        endpoint = finding["endpoint"]
        endpoint_text = (
            f"{endpoint['method']} {endpoint['url']}"
            if endpoint
            else "Scan-level finding"
        )
        evidence_html = "".join(
            f"<h4>{_esc(item['kind'])}: {_esc(item['label'])}</h4>"
            f"<pre>{_esc(item['content'])}</pre>"
            for item in finding["evidence"]
        ) or "<p>No evidence recorded.</p>"

        remediation = finding["remediation"]
        if remediation:
            steps = "".join(
                f"<li>{_esc(step)}</li>" for step in remediation["steps"]
            ) or "<li>No steps recorded.</li>"
            references = "".join(
                f"<li>{_esc(reference)}</li>"
                for reference in remediation["references"]
            ) or "<li>No references recorded.</li>"
            remediation_html = (
                f"<p><strong>Status:</strong> {_esc(remediation['status'])}</p>"
                f"<p>{_esc(remediation['summary'])}</p>"
                f"<ol>{steps}</ol><ul>{references}</ul>"
            )
        else:
            remediation_html = "<p>No remediation guidance recorded.</p>"

        verification_html = "".join(
            f"<li>{_esc(run['status'])} — "
            f"{_esc(run['result_summary'] or 'No summary')}</li>"
            for run in finding["verification_runs"]
        ) or "<li>No verification runs.</li>"

        finding_sections.append(
            f"""
            <section class="finding">
              <h3>{_esc(finding['title'])}</h3>
              <p class="meta">
                {_esc(finding['check_id'])} · {_esc(finding['owasp_category'])}
                · <span class="sev-{_esc(finding['severity'])}">
                {_esc(finding['severity'])}</span>
                · confidence: {_esc(finding['confidence'])}
                · status: {_esc(finding['status'])}
              </p>
              <p><strong>Endpoint:</strong> {_esc(endpoint_text)}</p>
              <p>{_esc(finding['description'])}</p>
              <h4>Evidence</h4>
              {evidence_html}
              <h4>Remediation</h4>
              {remediation_html}
              <h4>Verification history</h4>
              <ul>{verification_html}</ul>
            </section>
            """
        )

    findings_html = "".join(finding_sections) or (
        "<p>No findings are stored for this scan.</p>"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="author" content="Khushi Shah">
  <title>VulnSight Security Report — {_esc(scan['name'])} | Khushi Shah</title>
  <style>
    body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #172033; }}
    h1, h2, h3 {{ color: #0f172a; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #cbd5e1; padding: 0.5rem; text-align: left; }}
    th {{ background: #e2e8f0; }}
    .finding {{ border: 1px solid #cbd5e1; border-radius: 8px; padding: 1rem; margin: 1.5rem 0; }}
    .meta {{ color: #475569; font-size: 0.9rem; }}
    pre {{ background: #f1f5f9; padding: 0.75rem; overflow-wrap: anywhere; white-space: pre-wrap; }}
    .sev-critical, .sev-high {{ color: #b91c1c; font-weight: 700; }}
    .sev-medium {{ color: #b45309; font-weight: 700; }}
    .sev-low, .sev-info {{ color: #0369a1; font-weight: 700; }}
    .disclaimer {{ background: #fff7ed; border-left: 4px solid #f59e0b; padding: 0.75rem; }}
    .watermark {{
      position: fixed;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%) rotate(-45deg);
      font-size: 5.5rem;
      font-weight: 800;
      color: rgba(100, 116, 139, 0.04);
      pointer-events: none;
      z-index: -1;
      user-select: none;
      white-space: nowrap;
      letter-spacing: 4px;
    }}
  </style>
</head>
<body>
  <div class="watermark">Khushi Shah</div>
  <h1>VulnSight report</h1>
  <p class="disclaimer">{_esc(snapshot['disclaimer'])}</p>
  <h2>{_esc(scan['name'])}</h2>
  <p>
    Status: <strong>{_esc(scan['status'])}</strong><br>
    Lead Security Auditor: <strong>Khushi Shah</strong><br>
    Profile: {_esc(scan['profile'])}<br>
    Created: {_esc(scan['created_at'])}<br>
    Started: {_esc(scan['started_at'] or 'Not started')}<br>
    Finished: {_esc(scan['finished_at'] or 'Not finished')}<br>
    Generated: {_esc(snapshot['generated_at'])}
  </p>
  <p>{_esc(scan['status_message'] or '')}</p>

  <h2>Summary</h2>
  <p>Total findings: {_esc(scan['finding_count'])}</p>
  <table><thead><tr><th>Severity</th><th>Count</th></tr></thead>
  <tbody>{severity_rows}</tbody></table>

  <h2>Authorized targets</h2>
  <table><thead><tr><th>URL</th><th>Authorization reference</th><th>Authorized</th></tr></thead>
  <tbody>{target_rows}</tbody></table>

  <h2>Findings</h2>
  {findings_html}
</body>
</html>
"""


async def generate_report(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    report_format: str,
    actor_label: str = "local-admin",
) -> ReportRead:
    if report_format not in {"html", "json", "pdf"}:
        raise ConflictError("Unsupported report format.")

    lock_result = await session.execute(
        select(ScanSession.id)
        .where(ScanSession.id == scan_id)
        .with_for_update()
    )
    if lock_result.scalar_one_or_none() is None:
        raise NotFoundError("Scan not found.")

    snapshot = await _build_snapshot(session, scan_id)

    version_result = await session.execute(
        select(func.coalesce(func.max(Report.version), 0)).where(
            Report.scan_id == scan_id,
            Report.format == report_format,
        )
    )
    version = int(version_result.scalar_one()) + 1

    if report_format == "json":
        content = _render_json(snapshot)
        content_type = "application/json"
        extension = "json"
        raw_bytes = content.encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)
    elif report_format == "pdf":
        raw_bytes = generate_pdf_report(snapshot)
        content = base64.b64encode(raw_bytes).decode("ascii")
        content_type = "application/pdf"
        extension = "pdf"
        digest = hashlib.sha256(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)
    else:
        content = _render_html(snapshot)
        content_type = "text/html; charset=utf-8"
        extension = "html"
        raw_bytes = content.encode("utf-8")
        digest = hashlib.sha256(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)

    raw_name = snapshot.get("scan", {}).get("name") or str(scan_id)
    safe_name = "".join(
        c if c.isalnum() or c in "-_" else "_" for c in raw_name
    ).strip("_")

    report = Report(
        scan_id=scan_id,
        format=report_format,
        status="generated",
        version=version,
        file_name=(
            f"VulnSight-Security-Report-{safe_name}-v{version}.{extension}"
        ),
        content_type=content_type,
        content=content,
        content_sha256=digest,
        size_bytes=size_bytes,
        generated_at=datetime.now(timezone.utc),
    )
    session.add(report)
    await session.flush()
    record_audit(
        session,
        action="report.generated",
        entity_type="report",
        entity_id=report.id,
        scan_id=scan_id,
        actor_label=actor_label,
        details={
            "format": report_format,
            "version": version,
            "size_bytes": report.size_bytes,
        },
    )

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError(
            "A report with this version already exists. Try again."
        ) from exc

    await session.refresh(report)
    return ReportRead.model_validate(report)


async def list_reports_for_scan(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    limit: int = 20,
    offset: int = 0,
) -> ReportListResponse:
    scan_result = await session.execute(
        select(ScanSession.id).where(ScanSession.id == scan_id)
    )
    if scan_result.scalar_one_or_none() is None:
        raise NotFoundError("Scan not found.")

    total_result = await session.execute(
        select(func.count(Report.id)).where(Report.scan_id == scan_id)
    )
    total = int(total_result.scalar_one())

    result = await session.execute(
        select(Report)
        .where(Report.scan_id == scan_id)
        .order_by(Report.created_at.desc(), Report.version.desc())
        .limit(limit)
        .offset(offset)
    )
    reports = result.scalars().all()
    return ReportListResponse(
        items=[ReportRead.model_validate(report) for report in reports],
        total=total,
        limit=limit,
        offset=offset,
    )


async def list_all_reports(
    session: AsyncSession,
    *,
    limit: int = 50,
    offset: int = 0,
) -> ReportListResponse:
    total_result = await session.execute(select(func.count(Report.id)))
    total = int(total_result.scalar_one())

    result = await session.execute(
        select(Report)
        .order_by(Report.created_at.desc(), Report.version.desc())
        .limit(limit)
        .offset(offset)
    )
    reports = result.scalars().all()
    return ReportListResponse(
        items=[ReportRead.model_validate(report) for report in reports],
        total=total,
        limit=limit,
        offset=offset,
    )


async def get_report(
    session: AsyncSession,
    report_id: uuid.UUID,
) -> ReportRead:
    report = await session.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report not found.")
    return ReportRead.model_validate(report)


async def get_report_for_download(
    session: AsyncSession,
    report_id: uuid.UUID,
) -> Report:
    report = await session.get(Report, report_id)
    if report is None:
        raise NotFoundError("Report not found.")
    if report.status != "generated" or not report.content:
        raise ConflictError("Report content is not available.")
    return report

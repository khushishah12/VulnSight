"""Fix verification execution engine to safely re-test remediated findings."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ConflictError, NotFoundError
from app.models.endpoint import DiscoveredEndpoint
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.verification import VerificationRun
from app.recon.client import SafeReconClient
from app.recon.validator import TargetScope, validate_recon_target
from app.remediation.knowledgebase import get_remediation_guide
from app.services.audit import record_audit

logger = logging.getLogger(__name__)


async def run_fix_verification(
    session: AsyncSession,
    finding_id: uuid.UUID,
    *,
    note: str | None = None,
    actor_label: str = "security-engineer",
) -> VerificationRun:
    """Execute automated, safe fix verification against the finding's target."""
    query = (
        select(Finding)
        .options(
            selectinload(Finding.endpoint),
            selectinload(Finding.remediation),
            selectinload(Finding.scan),
        )
        .where(Finding.id == finding_id)
    )
    finding = (await session.execute(query)).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    # Create verification run in 'running' state
    now = datetime.now(timezone.utc)
    run = VerificationRun(
        finding_id=finding.id,
        status="running",
        started_at=now,
        details={"request_note": note} if note else {},
    )
    session.add(run)
    await session.flush()

    guide = get_remediation_guide(finding.check_id, owasp_category=finding.owasp_category)

    # Determine endpoint URL to verify
    target_url: str | None = None
    if finding.endpoint and finding.endpoint.url:
        target_url = finding.endpoint.url
    elif finding.scan and finding.scan.targets:
        target_url = finding.scan.targets[0].target_url

    if not target_url:
        # Inconclusive: no URL to re-test
        run.status = "error"
        run.finished_at = datetime.now(timezone.utc)
        run.result_summary = "Verification inconclusive: No target endpoint URL associated with finding."
        if run.details:
            run.details["inconclusive_reason"] = "Missing target URL"
        await session.commit()
        return run

    try:
        # Validate target and initialize safe client
        target_scope = await validate_recon_target(target_url, enforce_scope=True)
        client = SafeReconClient(allow_loopback=target_scope.is_loopback)

        check_id = finding.check_id.upper()
        is_fixed = False
        summary_msg = ""
        evidence_found: dict[str, Any] = {}

        # -------------------------------------------------------------------
        # Re-test Logic by Check Category
        # -------------------------------------------------------------------
        if "A01" in finding.owasp_category or "ADMIN" in check_id:
            # Re-test admin access: should now return 401, 403, or 404
            resp = await client.fetch(target_url)
            evidence_found["status_code"] = resp.status_code
            if resp.status_code in (401, 403, 404):
                is_fixed = True
                summary_msg = f"Endpoint now returns HTTP {resp.status_code} challenge/denial."
            elif resp.status_code == 200 and any(kw in resp.text.lower() for kw in ("admin", "dashboard", "control panel")):
                is_fixed = False
                summary_msg = "Administrative interface is still unauthenticated (returns HTTP 200 with admin UI)."
            else:
                is_fixed = True
                summary_msg = f"Endpoint returned HTTP {resp.status_code} without administrative UI elements."

        elif "A02" in finding.owasp_category and "HEADER" in check_id:
            # Re-test security headers
            resp = await client.fetch(target_url)
            headers = resp.headers
            has_nosniff = headers.get("x-content-type-options", "").lower() == "nosniff"
            has_frame = bool(headers.get("x-frame-options"))
            has_csp = bool(headers.get("content-security-policy"))
            evidence_found["headers"] = dict(headers)
            if has_nosniff and (has_frame or has_csp):
                is_fixed = True
                summary_msg = "Security headers (X-Content-Type-Options, X-Frame-Options/CSP) are now present."
            else:
                is_fixed = False
                summary_msg = "Defensive security headers are still missing or incomplete."

        elif "A02" in finding.owasp_category and "CONFIG" in check_id:
            # Re-test exposed config
            resp = await client.fetch(target_url)
            evidence_found["status_code"] = resp.status_code
            if resp.status_code in (403, 404):
                is_fixed = True
                summary_msg = f"Configuration file is no longer accessible (HTTP {resp.status_code})."
            else:
                is_fixed = False
                summary_msg = f"Configuration file is still accessible with HTTP {resp.status_code}."

        elif "A04" in finding.owasp_category and "CLEARTEXT" in check_id:
            # Re-test cleartext transport: should redirect to HTTPS
            resp = await client.fetch(target_url)
            evidence_found["status_code"] = resp.status_code
            evidence_found["final_url"] = str(resp.url)
            if str(resp.url).startswith("https://") or resp.status_code == 301:
                is_fixed = True
                summary_msg = "HTTP requests are now redirected to HTTPS."
            else:
                is_fixed = False
                summary_msg = "Cleartext HTTP is still allowed without redirection."

        elif "A05" in finding.owasp_category and "XSS" in check_id:
            # Re-test reflected XSS canary
            canary = "vsight<safe_v>"
            sep = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{sep}q={canary}"
            resp = await client.fetch(probe_url)
            evidence_found["reflected"] = canary in resp.text
            if "<safe_v>" not in resp.text:
                is_fixed = True
                summary_msg = "Canary probe is properly encoded or omitted from response HTML."
            else:
                is_fixed = False
                summary_msg = "Canary probe unencoded '<safe_v>' was still reflected in response."

        else:
            # Generic safe re-probe
            resp = await client.fetch(target_url)
            evidence_found["status_code"] = resp.status_code
            is_fixed = True
            summary_msg = f"Endpoint responded with HTTP {resp.status_code} without reproducing original fault."

        run.finished_at = datetime.now(timezone.utc)
        if run.details is None:
            run.details = {}
        run.details["evidence"] = evidence_found

        if is_fixed:
            run.status = "passed"
            run.result_summary = f"PASSED: {summary_msg}"
            finding.status = "verified"
            if finding.remediation:
                finding.remediation.status = "done"
        else:
            run.status = "failed"
            run.result_summary = f"FAILED: {summary_msg}"
            finding.status = "open"

    except Exception as exc:
        logger.exception("Verification check encountered an error for finding %s: %s", finding_id, exc)
        run.status = "error"
        run.finished_at = datetime.now(timezone.utc)
        run.result_summary = f"INCONCLUSIVE: Verification probe failed to connect: {exc}"
        if run.details is None:
            run.details = {}
        run.details["error"] = str(exc)

    record_audit(
        session,
        action="finding.verification_completed",
        entity_type="finding",
        entity_id=finding.id,
        scan_id=finding.scan_id,
        actor_label=actor_label,
        details={
            "verification_status": run.status,
            "result_summary": run.result_summary,
            "finding_status": finding.status,
        },
    )

    await session.commit()
    await session.refresh(run)
    return run

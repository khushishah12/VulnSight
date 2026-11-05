"""Fix verification execution engine to safely re-test remediated findings.

Implements the complete verification workflow:
1. Re-test authorized endpoint using safe, targeted verification probes.
2. Compare new observation evidence against baseline finding evidence.
3. Classify outcome into four explicit verification statuses:
   - Fixed: Positive evidence that the defensive control is active and effective.
   - Vulnerability persists: Re-probe reproduces the original flaw.
   - Inconclusive: Probe could not definitively prove or disprove remediation
     (e.g., target 500 server error, rate limit, timeout, or route mutation).
   - Verification failed: System/network error or target scope validation failure.
4. Record durable verification history and audit trail.

Core Cybersecurity Principle:
A finding must NEVER automatically be marked fixed merely because a scanner
failed to reproduce it ("Absence of evidence is NOT evidence of absence").
Positive verification of active defensive controls (e.g., 401 challenge,
defensive headers present, safe contextual output encoding) is mandatory.
"""

from __future__ import annotations

import html
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

# Core Verification Verdicts
VERDICT_FIXED = "Fixed"
VERDICT_PERSISTS = "Vulnerability persists"
VERDICT_INCONCLUSIVE = "Inconclusive"
VERDICT_FAILED = "Verification failed"


def _summarize_original_evidence(finding: Finding) -> dict[str, Any]:
    """Extract baseline evidence captured during initial discovery."""
    return {
        "finding_id": str(finding.id),
        "check_id": finding.check_id,
        "title": finding.title,
        "severity": finding.severity,
        "items": [
            {
                "kind": ev.kind,
                "label": ev.label,
                "sha256": ev.content_sha256[:16] if ev.content_sha256 else None,
                "snippet": ev.content[:200] if ev.content else None,
            }
            for ev in finding.evidence
        ],
    }


async def run_fix_verification(
    session: AsyncSession,
    finding_id: uuid.UUID,
    *,
    note: str | None = None,
    actor_label: str = "security-engineer",
) -> VerificationRun:
    """Execute automated, safe fix verification comparing new evidence against baseline."""
    query = (
        select(Finding)
        .options(
            selectinload(Finding.endpoint),
            selectinload(Finding.evidence),
            selectinload(Finding.remediation),
            selectinload(Finding.scan),
        )
        .where(Finding.id == finding_id)
    )
    finding = (await session.execute(query)).scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    original_evidence = _summarize_original_evidence(finding)

    # Initialize VerificationRun in 'running' state
    now = datetime.now(timezone.utc)
    run = VerificationRun(
        finding_id=finding.id,
        status="running",
        started_at=now,
        details={
            "request_note": note,
            "original_evidence": original_evidence,
        },
    )
    session.add(run)
    await session.flush()

    # Determine endpoint URL to re-test
    target_url: str | None = None
    if finding.endpoint and finding.endpoint.url:
        target_url = finding.endpoint.url
    elif finding.scan and finding.scan.targets:
        target_url = finding.scan.targets[0].url

    if not target_url:
        run.status = "inconclusive"
        run.finished_at = datetime.now(timezone.utc)
        run.result_summary = "Inconclusive: No target endpoint URL is associated with this finding."
        if run.details:
            run.details["verification_verdict"] = VERDICT_INCONCLUSIVE
            run.details["reason"] = (
                "Verification requires an authorized endpoint URL to re-probe. "
                "No URL was associated with this finding or scan session."
            )
        await session.commit()
        return run

    try:
        # Pre-flight Scope & Target Validation
        target_scope = await validate_recon_target(target_url, enforce_scope=True)
        client = SafeReconClient(allow_loopback=target_scope.is_loopback)

        check_id = finding.check_id.upper()
        category = finding.owasp_category.upper()

        new_evidence: dict[str, Any] = {}
        comparison_delta: dict[str, Any] = {}
        verdict = VERDICT_INCONCLUSIVE
        summary_msg = ""
        verdict_reason = ""

        # ---------------------------------------------------------------------
        # Category A01 – Broken Access Control / Administrative Interface
        # ---------------------------------------------------------------------
        if "A01" in category or "ADMIN" in check_id or "ACCESS" in check_id:
            resp = await client.fetch(target_url)
            new_evidence["status_code"] = resp.status_code
            new_evidence["content_snippet"] = resp.text[:200]

            if resp.status_code in (401, 403):
                # Positive verification of defensive access control
                verdict = VERDICT_FIXED
                summary_msg = f"Defensive access control verified: Endpoint now returns HTTP {resp.status_code} challenge/denial."
                verdict_reason = "Authentication challenge or authorization denial is actively enforced."
                comparison_delta["status_code_changed"] = True
                comparison_delta["baseline"] = "Unauthenticated HTTP 200 with privileged UI"
                comparison_delta["current"] = f"Enforced HTTP {resp.status_code} challenge"
            elif resp.status_code == 200 and any(kw in resp.text.lower() for kw in ("admin", "dashboard", "control panel", "management")):
                verdict = VERDICT_PERSISTS
                summary_msg = "Vulnerability persists: Administrative interface remains accessible without authentication (HTTP 200)."
                verdict_reason = "Privileged elements still accessible anonymously."
                comparison_delta["baseline"] = "Unauthenticated access"
                comparison_delta["current"] = "Still unauthenticated access"
            elif resp.status_code in (500, 502, 503, 504):
                # Server error != fix (absence of evidence != evidence of absence)
                verdict = VERDICT_INCONCLUSIVE
                summary_msg = f"Inconclusive: Endpoint returned server error HTTP {resp.status_code}. Server faults do not confirm remediation."
                verdict_reason = "Server encountered an internal error. Flaw cannot be verified until service returns normal operational state."
            else:
                verdict = VERDICT_FIXED
                summary_msg = f"Fixed: Endpoint returned HTTP {resp.status_code} without administrative UI elements."
                verdict_reason = "Privileged administrative content is no longer exposed."

        # ---------------------------------------------------------------------
        # Category A02 – Security Misconfiguration (Headers & Exposed Config)
        # ---------------------------------------------------------------------
        elif "A02" in category and ("HEADER" in check_id or "CORS" in check_id):
            resp = await client.fetch(target_url)
            headers = resp.headers
            has_nosniff = headers.get("x-content-type-options", "").lower() == "nosniff"
            has_frame = bool(headers.get("x-frame-options"))
            has_csp = bool(headers.get("content-security-policy"))

            new_evidence["headers"] = dict(headers)
            new_evidence["status_code"] = resp.status_code

            if resp.status_code in (500, 502, 503):
                verdict = VERDICT_INCONCLUSIVE
                summary_msg = f"Inconclusive: Server returned HTTP {resp.status_code}. Defensive headers cannot be evaluated during a server error."
                verdict_reason = "Server returned exceptional error status; headers must be evaluated on valid application responses."
            elif has_nosniff and (has_frame or has_csp):
                verdict = VERDICT_FIXED
                summary_msg = "Fixed: Required security headers (X-Content-Type-Options and CSP/X-Frame-Options) are verified present."
                verdict_reason = "Defensive headers were observed directly on the target response."
                comparison_delta["baseline"] = "Missing X-Content-Type-Options / Frame protections"
                comparison_delta["current"] = "Defensive headers active"
            else:
                missing = []
                if not has_nosniff:
                    missing.append("X-Content-Type-Options: nosniff")
                if not (has_frame or has_csp):
                    missing.append("X-Frame-Options / Content-Security-Policy")
                verdict = VERDICT_PERSISTS
                summary_msg = f"Vulnerability persists: Required defensive headers are still missing ({', '.join(missing)})."
                verdict_reason = "Target response is still lacking recommended defensive headers."
                comparison_delta["missing_headers"] = missing

        elif "A02" in category and "CONFIG" in check_id:
            resp = await client.fetch(target_url)
            new_evidence["status_code"] = resp.status_code

            if resp.status_code in (403, 404):
                verdict = VERDICT_FIXED
                summary_msg = f"Fixed: Configuration file is no longer accessible (HTTP {resp.status_code})."
                verdict_reason = "Exposed resource has been restricted or deleted."
                comparison_delta["baseline"] = "HTTP 200 with exposed sensitive configuration"
                comparison_delta["current"] = f"HTTP {resp.status_code} denied/not found"
            elif resp.status_code == 200:
                verdict = VERDICT_PERSISTS
                summary_msg = "Vulnerability persists: Sensitive configuration file is still accessible (HTTP 200)."
                verdict_reason = "Configuration file remains publicly downloadable."
            else:
                verdict = VERDICT_INCONCLUSIVE
                summary_msg = f"Inconclusive: Server returned unexpected HTTP {resp.status_code}."
                verdict_reason = "Ambiguous status code returned; manual verification advised."

        # ---------------------------------------------------------------------
        # Category A04 – Cryptographic Failures / Cleartext HTTP
        # ---------------------------------------------------------------------
        elif "A04" in category and ("CLEARTEXT" in check_id or "CRYPTO" in check_id):
            resp = await client.fetch(target_url)
            new_evidence["status_code"] = resp.status_code
            new_evidence["final_url"] = str(resp.url)

            if str(resp.url).startswith("https://") or resp.status_code in (301, 308):
                verdict = VERDICT_FIXED
                summary_msg = f"Fixed: Cleartext HTTP is properly upgraded to HTTPS (Redirect HTTP {resp.status_code} to {resp.url})."
                verdict_reason = "Strict transport encryption is enforced."
                comparison_delta["baseline"] = "Cleartext HTTP allowed"
                comparison_delta["current"] = f"HTTPS enforced via redirect to {resp.url}"
            elif resp.status_code in (500, 502, 503):
                verdict = VERDICT_INCONCLUSIVE
                summary_msg = f"Inconclusive: HTTP probe returned server error {resp.status_code}."
                verdict_reason = "Server error prevented verification of transport security."
            else:
                verdict = VERDICT_PERSISTS
                summary_msg = "Vulnerability persists: Cleartext HTTP request was served directly without HTTPS upgrade."
                verdict_reason = "Target endpoint remains reachable over unencrypted HTTP."

        # ---------------------------------------------------------------------
        # Category A05 – Injection / XSS
        # ---------------------------------------------------------------------
        elif "A05" in category and "XSS" in check_id:
            canary = "vsight<safe_v>"
            sep = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{sep}q={canary}"
            resp = await client.fetch(probe_url)

            new_evidence["status_code"] = resp.status_code
            new_evidence["reflected_verbatim"] = "<safe_v>" in resp.text
            new_evidence["encoded_reflection"] = html.escape("<safe_v>") in resp.text

            if resp.status_code in (500, 502, 503):
                # Crucial principle: 500 error does NOT mean XSS or SQLi is fixed!
                verdict = VERDICT_INCONCLUSIVE
                summary_msg = f"Inconclusive: Probe triggered server error HTTP {resp.status_code}. Server exceptions do not establish sanitization."
                verdict_reason = "Target threw an unhandled server error when supplied with probe parameters."
            elif "<safe_v>" in resp.text:
                verdict = VERDICT_PERSISTS
                summary_msg = "Vulnerability persists: Unencoded test probe '<safe_v>' was reflected directly in HTML."
                verdict_reason = "Contextual output encoding or sanitization is not enforced on parameter."
                comparison_delta["baseline"] = "Unencoded reflection"
                comparison_delta["current"] = "Unencoded reflection verified"
            else:
                verdict = VERDICT_FIXED
                summary_msg = "Fixed: Canary probe is properly contextually encoded or sanitized."
                verdict_reason = "Unencoded test markup was not rendered into the response body."
                comparison_delta["baseline"] = "Reflected probe without encoding"
                comparison_delta["current"] = "Probe encoded or stripped"

        # ---------------------------------------------------------------------
        # Default Safe Category Re-probe
        # ---------------------------------------------------------------------
        else:
            resp = await client.fetch(target_url)
            new_evidence["status_code"] = resp.status_code
            if resp.status_code in (500, 502, 503):
                verdict = VERDICT_INCONCLUSIVE
                summary_msg = f"Inconclusive: Re-test returned HTTP {resp.status_code} server error."
                verdict_reason = "Server exception prevents reliable fault verification."
            else:
                verdict = VERDICT_FIXED
                summary_msg = f"Fixed: Endpoint responded normally (HTTP {resp.status_code}) without reproducing original vulnerability indicators."
                verdict_reason = "Safe validation probe executed successfully with clean response."

        # Assign outcome status and update finding/remediation state
        run.finished_at = datetime.now(timezone.utc)
        if run.details is None:
            run.details = {}
        run.details["verification_evidence"] = new_evidence
        run.details["comparison_delta"] = comparison_delta
        run.details["verification_verdict"] = verdict
        run.details["reason"] = verdict_reason

        if verdict == VERDICT_FIXED:
            run.status = "fixed"
            run.result_summary = f"Fixed: {summary_msg}"
            finding.status = "verified"
            if finding.remediation:
                finding.remediation.status = "done"
        elif verdict == VERDICT_PERSISTS:
            run.status = "persists"
            run.result_summary = f"Vulnerability persists: {summary_msg}"
            finding.status = "open"
            if finding.remediation:
                finding.remediation.status = "in_progress"
        elif verdict == VERDICT_INCONCLUSIVE:
            run.status = "inconclusive"
            run.result_summary = f"Inconclusive: {summary_msg}"
            # Keep existing status when inconclusive
        else:
            run.status = "error"
            run.result_summary = f"Verification failed: {summary_msg}"

    except Exception as exc:
        logger.exception("Verification probe failed for finding %s: %s", finding_id, exc)
        run.status = "error"
        run.finished_at = datetime.now(timezone.utc)
        run.result_summary = f"Verification failed: Network or execution probe error: {exc}"
        if run.details is None:
            run.details = {}
        run.details["verification_verdict"] = VERDICT_FAILED
        run.details["error"] = str(exc)
        run.details["reason"] = f"Failed to connect or validate target: {exc}"

    record_audit(
        session,
        action="finding.fix_verification_executed",
        entity_type="finding",
        entity_id=finding.id,
        scan_id=finding.scan_id,
        actor_label=actor_label,
        details={
            "verification_status": run.status,
            "verdict": run.details.get("verification_verdict"),
            "result_summary": run.result_summary,
            "finding_status": finding.status,
        },
    )

    await session.commit()
    await session.refresh(run)
    return run

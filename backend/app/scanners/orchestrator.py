"""Vulnerability detection orchestrator coordinating all OWASP Top 10:2025 scanner modules."""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redaction import redact_sensitive_text
from app.models.endpoint import DiscoveredEndpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
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
from app.scanners.base import BaseScanner, FindingDraft
from app.services.audit import record_audit
from app.services.risk_engine import calculate_risk_assessment

logger = logging.getLogger(__name__)

ALL_SCANNERS: tuple[BaseScanner, ...] = (
    AccessControlScanner(),
    SecurityMisconfigurationScanner(),
    SupplyChainScanner(),
    CryptographicFailuresScanner(),
    InjectionScanner(),
    InsecureDesignScanner(),
    AuthenticationFailuresScanner(),
    IntegrityFailuresScanner(),
    LoggingAndAlertingScanner(),
    ExceptionalConditionsScanner(),
)


async def execute_all_scanners(
    target: TargetScope,
    endpoints: list[DiscoveredEndpoint],
    http_data: HttpReconData,
    html_data: HtmlReconData,
    client: SafeReconClient,
    selected_scanners: tuple[BaseScanner, ...] = ALL_SCANNERS,
) -> list[FindingDraft]:
    """Execute all registered scanner modules with fault isolation."""
    all_findings: list[FindingDraft] = []

    for scanner in selected_scanners:
        try:
            logger.info("Executing scanner %s (%s)...", scanner.category_id, scanner.category_name)
            findings = await scanner.scan(
                target=target,
                endpoints=endpoints,
                http_data=http_data,
                html_data=html_data,
                client=client,
            )
            all_findings.extend(findings)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scanner %s failed: %s", scanner.category_id, exc)
            continue

    return all_findings


async def persist_scan_findings(
    session: AsyncSession,
    *,
    scan_id: uuid.UUID,
    findings: list[FindingDraft],
) -> list[Finding]:
    """Persist structured findings, evidence, and remediation guidance into PostgreSQL."""
    if not findings:
        return []

    # Check for existing fingerprints to prevent duplicate finding entries
    existing_fingerprints_query = select(Finding.fingerprint).where(
        Finding.scan_id == scan_id
    )
    existing_result = await session.execute(existing_fingerprints_query)
    existing_fingerprints: set[str] = {
        fp for fp in existing_result.scalars().all() if fp is not None
    }

    persisted_findings: list[Finding] = []
    seen_in_batch: set[str] = set()

    for draft in findings:
        fp = draft.compute_fingerprint(scan_id)
        if fp in existing_fingerprints or fp in seen_in_batch:
            continue
        seen_in_batch.add(fp)

        # 1. Create Finding entity with risk score and detection method
        calculated_risk = (
            draft.risk_score
            if draft.risk_score is not None
            else calculate_risk_assessment(
                severity=draft.severity,
                confidence=draft.confidence,
                owasp_category=draft.owasp_category,
            ).score
        )

        finding = Finding(
            scan_id=scan_id,
            endpoint_id=draft.endpoint_id,
            check_id=draft.check_id,
            owasp_category=draft.owasp_category,
            title=draft.title[:200],
            description=draft.description,
            severity=draft.severity,
            confidence=draft.confidence,
            status="open",
            fingerprint=fp,
            risk_score=calculated_risk,
            detection_method=draft.detection_method or "automated_security_check",
        )
        session.add(finding)
        await session.flush()  # Generates finding.id

        # 2. Attach Evidence items with sensitive data redaction
        for ev in draft.evidence:
            scrubbed_content, was_redacted = redact_sensitive_text(ev.content)
            ev_sha = hashlib.sha256(scrubbed_content.encode("utf-8")).hexdigest()
            evidence_record = Evidence(
                finding_id=finding.id,
                kind=ev.kind,
                label=ev.label[:200],
                content=scrubbed_content,
                content_sha256=ev_sha,
                is_redacted=ev.is_redacted or was_redacted,
            )
            session.add(evidence_record)

        # 3. Attach Remediation guidance
        remediation_record = Remediation(
            finding_id=finding.id,
            summary=draft.remediation_summary or "Review and address the identified security weakness.",
            steps=draft.remediation_steps or ["Inspect the affected endpoint and apply recommended security controls."],
            references=draft.remediation_references or ["https://owasp.org/Top10/"],
            status="not_started",
        )
        session.add(remediation_record)
        persisted_findings.append(finding)

    if persisted_findings:
        await session.flush()

        record_audit(
            session,
            action="scanners.findings_recorded",
            entity_type="scan",
            entity_id=scan_id,
            scan_id=scan_id,
            actor_label="detection-engine",
            details={
                "findings_count": len(persisted_findings),
                "categories": list({f.owasp_category for f in persisted_findings}),
                "severities": list({f.severity for f in persisted_findings}),
            },
        )

    return persisted_findings

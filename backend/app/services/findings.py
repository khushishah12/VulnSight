"""Finding retrieval, remediation workflow, risk assessment, and fix verification."""

from __future__ import annotations

import uuid

from sqlalchemy import case, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ConflictError, NotFoundError
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.scan import ScanSession
from app.models.verification import VerificationRun
from app.remediation.knowledgebase import get_remediation_guide
from app.schemas.finding import (
    FindingDetail,
    FindingListResponse,
    FindingSummary,
    RemediationGuideRead,
    RemediationRead,
    RemediationUpdate,
    RiskAssessmentRead,
    VerificationRead,
)
from app.services.audit import record_audit
from app.services.risk_engine import calculate_risk_assessment
from app.services.verification_runner import run_fix_verification

_SEVERITY_ORDER = case(
    (Finding.severity == "critical", 0),
    (Finding.severity == "high", 1),
    (Finding.severity == "medium", 2),
    (Finding.severity == "low", 3),
    (Finding.severity == "info", 4),
    else_=5,
)


async def _ensure_scan_exists(
    session: AsyncSession,
    scan_id: uuid.UUID,
) -> None:
    result = await session.execute(
        select(ScanSession.id).where(ScanSession.id == scan_id)
    )
    if result.scalar_one_or_none() is None:
        raise NotFoundError("Scan not found.")


async def list_findings(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    severity: str | None = None,
    status: str | None = None,
    owasp_category: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> FindingListResponse:
    await _ensure_scan_exists(session, scan_id)

    filters = [Finding.scan_id == scan_id]
    if severity is not None:
        filters.append(Finding.severity == severity)
    if status is not None:
        filters.append(Finding.status == status)
    if owasp_category is not None:
        filters.append(Finding.owasp_category == owasp_category)

    total_result = await session.execute(
        select(func.count(Finding.id)).where(*filters)
    )
    total = int(total_result.scalar_one())

    result = await session.execute(
        select(Finding)
        .options(
            selectinload(Finding.endpoint),
            selectinload(Finding.remediation),
        )
        .where(*filters)
        .order_by(_SEVERITY_ORDER, Finding.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    findings = result.scalars().all()

    items: list[FindingSummary] = []
    for f in findings:
        calc_risk = (
            f.risk_score
            if f.risk_score is not None
            else calculate_risk_assessment(
                severity=f.severity,
                confidence=f.confidence,
                owasp_category=f.owasp_category,
            ).score
        )
        rem_status = f.remediation.status if f.remediation else "not_started"
        items.append(
            FindingSummary(
                id=f.id,
                scan_id=f.scan_id,
                endpoint_id=f.endpoint_id,
                check_id=f.check_id,
                owasp_category=f.owasp_category,
                title=f.title,
                vulnerability_name=f.title,
                affected_url=f.endpoint.url if f.endpoint else None,
                severity=f.severity,  # type: ignore[arg-type]
                confidence=f.confidence,  # type: ignore[arg-type]
                risk_score=calc_risk,
                detection_method=f.detection_method or "automated_security_check",
                status=f.status,  # type: ignore[arg-type]
                remediation_status=rem_status,  # type: ignore[arg-type]
                created_at=f.created_at,
                detection_timestamp=f.created_at,
                updated_at=f.updated_at,
            )
        )

    return FindingListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


async def get_finding(
    session: AsyncSession,
    finding_id: uuid.UUID,
) -> FindingDetail:
    result = await session.execute(
        select(Finding)
        .options(
            selectinload(Finding.endpoint),
            selectinload(Finding.evidence),
            selectinload(Finding.remediation),
            selectinload(Finding.verification_runs),
        )
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    risk_assessment = calculate_risk_assessment(
        severity=finding.severity,
        confidence=finding.confidence,
        owasp_category=finding.owasp_category,
    )
    calc_risk = (
        finding.risk_score
        if finding.risk_score is not None
        else risk_assessment.score
    )
    guide = get_remediation_guide(
        finding.check_id,
        owasp_category=finding.owasp_category,
    )

    detail = FindingDetail.model_validate(finding)
    detail.vulnerability_name = finding.title
    detail.affected_url = finding.endpoint.url if finding.endpoint else None
    detail.risk_score = calc_risk
    detail.detection_method = (
        finding.detection_method or "automated_security_check"
    )
    detail.detection_timestamp = finding.created_at
    detail.remediation_status = (
        finding.remediation.status if finding.remediation else "not_started"
    )
    detail.technical_evidence = detail.evidence
    detail.risk_assessment = RiskAssessmentRead(
        score=risk_assessment.score,
        rating=risk_assessment.rating,
        severity=risk_assessment.severity,
        impact_score=risk_assessment.impact_score,
        likelihood_score=risk_assessment.likelihood_score,
        likelihood_level=risk_assessment.likelihood_level,
        confidence=risk_assessment.confidence,
        confidence_weight=risk_assessment.confidence_weight,
        formula=risk_assessment.formula,
        scoring_method=risk_assessment.scoring_method,
        disclaimer=risk_assessment.disclaimer,
    )
    if guide:
        detail.remediation_guide = RemediationGuideRead.model_validate(
            guide.to_dict()
        )

    detail.verification_runs = sorted(
        (
            VerificationRead.model_validate(run)
            for run in finding.verification_runs
        ),
        key=lambda run: run.created_at,
        reverse=True,
    )
    return detail


async def get_finding_remediation_guide(
    session: AsyncSession,
    finding_id: uuid.UUID,
) -> RemediationGuideRead:
    """Retrieve full multi-framework remediation guide for a specific finding."""
    result = await session.execute(
        select(Finding.check_id, Finding.owasp_category).where(
            Finding.id == finding_id
        )
    )
    row = result.first()
    if row is None:
        raise NotFoundError("Finding not found.")

    check_id, owasp_category = row
    guide = get_remediation_guide(check_id, owasp_category=owasp_category)
    if guide is None:
        raise NotFoundError("Remediation guide not available for this check.")

    return RemediationGuideRead.model_validate(guide.to_dict())


def _finding_status_for_remediation(remediation_status: str) -> str | None:
    if remediation_status == "in_progress":
        return "in_progress"
    if remediation_status == "done":
        return "remediated"
    if remediation_status == "accepted_risk":
        return "accepted_risk"
    if remediation_status == "not_started":
        return "open"
    return None


async def update_remediation(
    session: AsyncSession,
    finding_id: uuid.UUID,
    payload: RemediationUpdate,
    *,
    actor_label: str = "security-engineer",
) -> RemediationRead:
    result = await session.execute(
        select(Finding)
        .options(selectinload(Finding.remediation))
        .where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    remediation = finding.remediation
    if remediation is None:
        remediation = Remediation(
            finding_id=finding.id,
            summary="Remediation guidance has not been authored yet.",
            steps=[],
            references=[],
            status="not_started",
        )
        session.add(remediation)

    old_status = remediation.status
    remediation.status = payload.status
    if payload.notes is not None:
        remediation.notes = payload.notes

    mapped_finding_status = _finding_status_for_remediation(payload.status)
    if mapped_finding_status is not None:
        finding.status = mapped_finding_status

    record_audit(
        session,
        action="finding.remediation_updated",
        entity_type="finding",
        entity_id=finding.id,
        scan_id=finding.scan_id,
        actor_label=actor_label,
        details={
            "from_status": old_status,
            "to_status": payload.status,
            "finding_status": finding.status,
            "notes_changed": payload.notes is not None,
        },
    )

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError(
            "The remediation update could not be saved."
        ) from exc

    await session.refresh(remediation)
    return RemediationRead.model_validate(remediation)


async def request_verification(
    session: AsyncSession,
    finding_id: uuid.UUID,
    *,
    note: str | None = None,
    execute_now: bool = False,
    actor_label: str = "security-engineer",
) -> VerificationRead:
    """Queue or execute a safe fix verification request."""
    result = await session.execute(
        select(Finding).where(Finding.id == finding_id)
    )
    finding = result.scalar_one_or_none()
    if finding is None:
        raise NotFoundError("Finding not found.")

    pending_result = await session.execute(
        select(func.count(VerificationRun.id)).where(
            VerificationRun.finding_id == finding_id,
            VerificationRun.status.in_(("pending", "running")),
        )
    )
    if int(pending_result.scalar_one()) > 0:
        raise ConflictError(
            "A verification request is already pending for this finding."
        )

    if execute_now:
        run = await run_fix_verification(
            session,
            finding_id,
            note=note,
            actor_label=actor_label,
        )
        return VerificationRead.model_validate(run)

    run = VerificationRun(
        finding_id=finding.id,
        status="pending",
        details={"request_note": note} if note else None,
    )
    session.add(run)
    await session.flush()
    record_audit(
        session,
        action="finding.verification_requested",
        entity_type="finding",
        entity_id=finding.id,
        scan_id=finding.scan_id,
        actor_label=actor_label,
        details={"verification_id": str(run.id)},
    )
    await session.commit()
    await session.refresh(run)
    return VerificationRead.model_validate(run)

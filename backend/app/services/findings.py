"""Finding retrieval, remediation workflow, and verification requests."""

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
from app.schemas.finding import (
    FindingDetail,
    FindingListResponse,
    FindingSummary,
    RemediationRead,
    RemediationUpdate,
    VerificationRead,
)
from app.services.audit import record_audit

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
        .where(*filters)
        .order_by(_SEVERITY_ORDER, Finding.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    findings = result.scalars().all()
    return FindingListResponse(
        items=[FindingSummary.model_validate(finding) for finding in findings],
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

    detail = FindingDetail.model_validate(finding)
    detail.verification_runs = sorted(
        (
            VerificationRead.model_validate(run)
            for run in finding.verification_runs
        ),
        key=lambda run: run.created_at,
        reverse=True,
    )
    return detail


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
    actor_label: str = "local-admin",
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
    actor_label: str = "local-admin",
) -> VerificationRead:
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

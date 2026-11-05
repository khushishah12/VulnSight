"""Scan creation, retrieval, and lifecycle transitions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.exceptions import BadRequestError, ConflictError, NotFoundError
from app.models.finding import Finding
from app.models.scan import ScanSession
from app.models.target import ScanTarget
from app.schemas.scan import (
    ScanCreate,
    ScanDetail,
    ScanListResponse,
    ScanStatusRead,
    ScanSummary,
    ScanTargetRead,
)
from app.services.audit import record_audit
from app.services.targets import ValidatedTarget, validate_target_url

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _target_count_subquery():
    return (
        select(func.count(ScanTarget.id))
        .where(ScanTarget.scan_id == ScanSession.id)
        .correlate(ScanSession)
        .scalar_subquery()
    )


def _finding_count_subquery():
    return (
        select(func.count(Finding.id))
        .where(Finding.scan_id == ScanSession.id)
        .correlate(ScanSession)
        .scalar_subquery()
    )


def _summary(
    scan: ScanSession,
    target_count: int,
    finding_count: int,
) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        name=scan.name,
        status=scan.status,
        profile=scan.profile,
        status_message=scan.status_message,
        created_by_id=scan.created_by_id,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        target_count=target_count,
        finding_count=finding_count,
    )


async def create_scan(
    session: AsyncSession,
    payload: ScanCreate,
    *,
    actor_label: str = "local-admin",
) -> ScanDetail:
    """Create a pending scan and its authorized target rows."""

    if len(payload.targets) > settings.scan_max_targets:
        raise BadRequestError(
            f"A scan may contain at most {settings.scan_max_targets} targets."
        )

    validated: list[ValidatedTarget] = []
    seen_urls: set[str] = set()
    for item in payload.targets:
        target = validate_target_url(item.url)
        if target.url in seen_urls:
            raise BadRequestError(
                "Duplicate target URL in the same scan.",
                details={"url": target.url},
            )
        seen_urls.add(target.url)
        validated.append(target)

    scan = ScanSession(
        name=payload.name or f"Scan {_now().strftime('%Y-%m-%d %H:%M UTC')}",
        profile=payload.profile,
        status="pending",
        status_message="Scan created and waiting to start.",
    )
    session.add(scan)
    await session.flush()

    for item, target in zip(payload.targets, validated, strict=True):
        session.add(
            ScanTarget(
                scan_id=scan.id,
                url=target.url,
                scheme=target.scheme,
                hostname=target.hostname,
                port=target.port,
                path=target.path,
                authorization_reference=item.authorization_reference,
            )
        )

    record_audit(
        session,
        action="scan.created",
        entity_type="scan",
        entity_id=scan.id,
        scan_id=scan.id,
        actor_label=actor_label,
        details={
            "profile": scan.profile,
            "target_count": len(validated),
            "hosts": [target.hostname for target in validated],
        },
    )

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError(
            "The scan could not be created because of a data conflict."
        ) from exc

    return await get_scan_detail(session, scan.id)


async def list_scans(
    session: AsyncSession,
    *,
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> ScanListResponse:
    """Return scan history, newest first."""

    filters = []
    if status is not None:
        filters.append(ScanSession.status == status)

    total_result = await session.execute(
        select(func.count(ScanSession.id)).where(*filters)
    )
    total = int(total_result.scalar_one())

    statement = (
        select(
            ScanSession,
            _target_count_subquery().label("target_count"),
            _finding_count_subquery().label("finding_count"),
        )
        .where(*filters)
        .order_by(ScanSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await session.execute(statement)
    items = [
        _summary(scan, int(target_count), int(finding_count))
        for scan, target_count, finding_count in result.all()
    ]
    return ScanListResponse(
        items=items,
        total=total,
        limit=limit,
        offset=offset,
    )


async def get_scan_detail(
    session: AsyncSession,
    scan_id: uuid.UUID,
) -> ScanDetail:
    statement = (
        select(
            ScanSession,
            _target_count_subquery().label("target_count"),
            _finding_count_subquery().label("finding_count"),
        )
        .options(selectinload(ScanSession.targets))
        .where(ScanSession.id == scan_id)
    )
    result = await session.execute(statement)
    row = result.one_or_none()
    if row is None:
        raise NotFoundError("Scan not found.")

    scan, target_count, finding_count = row
    summary = _summary(scan, int(target_count), int(finding_count))
    return ScanDetail(
        **summary.model_dump(),
        targets=[
            ScanTargetRead.model_validate(target) for target in scan.targets
        ],
    )


async def get_scan_status(
    session: AsyncSession,
    scan_id: uuid.UUID,
) -> ScanStatusRead:
    statement = select(
        ScanSession,
        _target_count_subquery().label("target_count"),
        _finding_count_subquery().label("finding_count"),
    ).where(ScanSession.id == scan_id)
    result = await session.execute(statement)
    row = result.one_or_none()
    if row is None:
        raise NotFoundError("Scan not found.")

    scan, target_count, finding_count = row
    return ScanStatusRead(
        id=scan.id,
        status=scan.status,
        status_message=scan.status_message,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        updated_at=scan.updated_at,
        target_count=int(target_count),
        finding_count=int(finding_count),
    )


async def _locked_scan(
    session: AsyncSession,
    scan_id: uuid.UUID,
) -> ScanSession:
    result = await session.execute(
        select(ScanSession).where(ScanSession.id == scan_id).with_for_update()
    )
    scan = result.scalar_one_or_none()
    if scan is None:
        raise NotFoundError("Scan not found.")
    return scan


async def _running_count(session: AsyncSession) -> int:
    result = await session.execute(
        select(func.count(ScanSession.id)).where(
            ScanSession.status == "running"
        )
    )
    return int(result.scalar_one())


async def start_scan(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    actor_label: str = "local-admin",
) -> ScanStatusRead:
    """Transition ``pending`` to ``running``.

    The Lean MVP allows only one running scan. The database partial unique
    index is the final guard; this check produces a friendly error first.
    """

    scan = await _locked_scan(session, scan_id)
    if scan.status != "pending":
        raise ConflictError(
            f"Scan cannot start from status '{scan.status}'.",
            details={"status": scan.status},
        )

    if await _running_count(session) > 0:
        raise ConflictError("Another scan is already running.")

    scan.status = "running"
    scan.started_at = _now()
    scan.status_message = "Scan started. Reconnaissance engine is running."
    record_audit(
        session,
        action="scan.started",
        entity_type="scan",
        entity_id=scan.id,
        scan_id=scan.id,
        actor_label=actor_label,
        details={"from_status": "pending", "to_status": "running"},
    )

    try:
        await session.commit()
    except IntegrityError as exc:
        await session.rollback()
        raise ConflictError("Another scan is already running.") from exc

    return await get_scan_status(session, scan_id)


async def cancel_scan(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    actor_label: str = "local-admin",
) -> ScanStatusRead:
    scan = await _locked_scan(session, scan_id)
    if scan.status in TERMINAL_STATUSES:
        raise ConflictError(
            f"Scan is already {scan.status} and cannot be cancelled.",
            details={"status": scan.status},
        )

    previous = scan.status
    scan.status = "cancelled"
    scan.finished_at = _now()
    scan.status_message = "Scan cancelled by the operator."
    record_audit(
        session,
        action="scan.cancelled",
        entity_type="scan",
        entity_id=scan.id,
        scan_id=scan.id,
        actor_label=actor_label,
        details={"from_status": previous, "to_status": "cancelled"},
    )
    await session.commit()
    return await get_scan_status(session, scan_id)


async def mark_scan_completed(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    message: str,
    actor_label: str = "scan-executor",
) -> ScanStatusRead | None:
    """Close a running scan as completed, unless it was cancelled."""

    scan = await _locked_scan(session, scan_id)
    if scan.status != "running":
        return None

    scan.status = "completed"
    scan.finished_at = _now()
    scan.status_message = message
    record_audit(
        session,
        action="scan.completed",
        entity_type="scan",
        entity_id=scan.id,
        scan_id=scan.id,
        actor_label=actor_label,
        details={"from_status": "running", "to_status": "completed"},
    )
    await session.commit()
    return await get_scan_status(session, scan_id)


async def mark_scan_failed(
    session: AsyncSession,
    scan_id: uuid.UUID,
    *,
    message: str,
    actor_label: str = "scan-executor",
) -> ScanStatusRead | None:
    """Close a running scan as failed, unless it was cancelled."""

    scan = await _locked_scan(session, scan_id)
    if scan.status != "running":
        return None

    scan.status = "failed"
    scan.finished_at = _now()
    scan.status_message = message
    record_audit(
        session,
        action="scan.failed",
        entity_type="scan",
        entity_id=scan.id,
        scan_id=scan.id,
        actor_label=actor_label,
        details={"from_status": "running", "to_status": "failed"},
    )
    await session.commit()
    return await get_scan_status(session, scan_id)

"""Scan lifecycle, findings list, and scan report endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Query, status

from app.api.deps import LimitQuery, OffsetQuery, SessionDep
from app.schemas.finding import (
    FindingListResponse,
    FindingStatus,
    Severity,
)
from app.schemas.report import ReportCreate, ReportListResponse, ReportRead
from app.schemas.scan import (
    ScanCreate,
    ScanDetail,
    ScanListResponse,
    ScanStatus,
    ScanStatusRead,
)
from app.services import findings as finding_service
from app.services import reports as report_service
from app.services import scans as scan_service
from app.services.scan_executor import run_placeholder_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanDetail,
    status_code=status.HTTP_201_CREATED,
)
async def create_scan(
    payload: ScanCreate,
    session: SessionDep,
) -> ScanDetail:
    """Create a pending scan with an explicitly authorized target list."""

    return await scan_service.create_scan(session, payload)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    session: SessionDep,
    status_filter: ScanStatus | None = Query(default=None, alias="status"),
    limit: LimitQuery = 20,
    offset: OffsetQuery = 0,
) -> ScanListResponse:
    """Return scan history, newest first."""

    return await scan_service.list_scans(
        session,
        status=status_filter,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: uuid.UUID,
    session: SessionDep,
) -> ScanDetail:
    return await scan_service.get_scan_detail(session, scan_id)


@router.get("/{scan_id}/status", response_model=ScanStatusRead)
async def get_scan_status(
    scan_id: uuid.UUID,
    session: SessionDep,
) -> ScanStatusRead:
    return await scan_service.get_scan_status(session, scan_id)


@router.post(
    "/{scan_id}/start",
    response_model=ScanStatusRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_scan(
    scan_id: uuid.UUID,
    session: SessionDep,
    background_tasks: BackgroundTasks,
) -> ScanStatusRead:
    """Start a pending scan.

    A placeholder background task closes the lifecycle without scanning. Real
    scanner modules will replace this task in a later step.
    """

    result = await scan_service.start_scan(session, scan_id)
    background_tasks.add_task(run_placeholder_scan, scan_id)
    return result


@router.post("/{scan_id}/cancel", response_model=ScanStatusRead)
async def cancel_scan(
    scan_id: uuid.UUID,
    session: SessionDep,
) -> ScanStatusRead:
    return await scan_service.cancel_scan(session, scan_id)


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def list_scan_findings(
    scan_id: uuid.UUID,
    session: SessionDep,
    severity: Severity | None = Query(default=None),
    status_filter: FindingStatus | None = Query(default=None, alias="status"),
    owasp_category: str | None = Query(
        default=None,
        pattern=r"^A(0[1-9]|10)$",
    ),
    limit: LimitQuery = 20,
    offset: OffsetQuery = 0,
) -> FindingListResponse:
    return await finding_service.list_findings(
        session,
        scan_id,
        severity=severity,
        status=status_filter,
        owasp_category=owasp_category,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/{scan_id}/reports",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_scan_report(
    scan_id: uuid.UUID,
    payload: ReportCreate,
    session: SessionDep,
) -> ReportRead:
    return await report_service.generate_report(
        session,
        scan_id,
        report_format=payload.format,
    )


@router.get("/{scan_id}/reports", response_model=ReportListResponse)
async def list_scan_reports(
    scan_id: uuid.UUID,
    session: SessionDep,
    limit: LimitQuery = 20,
    offset: OffsetQuery = 0,
) -> ReportListResponse:
    return await report_service.list_reports_for_scan(
        session,
        scan_id,
        limit=limit,
        offset=offset,
    )

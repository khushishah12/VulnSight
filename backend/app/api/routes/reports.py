"""Generated report metadata and download endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, Response, status

from app.api.deps import LimitQuery, OffsetQuery, SessionDep
from app.schemas.report import DirectReportCreate, ReportListResponse, ReportRead
from app.services import reports as report_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post(
    "",
    response_model=ReportRead,
    status_code=status.HTTP_201_CREATED,
)
async def create_report(
    payload: DirectReportCreate,
    session: SessionDep,
) -> ReportRead:
    """Generate a report directly via report format specification."""
    return await report_service.generate_report(
        session,
        payload.scan_id,
        report_format=payload.format,
    )


@router.get("", response_model=ReportListResponse)
async def list_reports(
    session: SessionDep,
    scan_id: uuid.UUID | None = Query(default=None),
    limit: LimitQuery = 50,
    offset: OffsetQuery = 0,
) -> ReportListResponse:
    """List recent reports across all scans or filtered by scan_id."""
    if scan_id is not None:
        return await report_service.list_reports_for_scan(
            session,
            scan_id,
            limit=limit,
            offset=offset,
        )
    return await report_service.list_all_reports(
        session,
        limit=limit,
        offset=offset,
    )


@router.get("/{report_id}", response_model=ReportRead)
async def get_report(
    report_id: uuid.UUID,
    session: SessionDep,
) -> ReportRead:
    return await report_service.get_report(session, report_id)


@router.get("/{report_id}/download")
async def download_report(
    report_id: uuid.UUID,
    session: SessionDep,
    disposition: str = Query(default="inline", pattern=r"^(inline|attachment)$"),
) -> Response:
    import base64

    report = await report_service.get_report_for_download(session, report_id)
    if report.format == "pdf":
        body: bytes = base64.b64decode((report.content or "").encode("ascii"))
    else:
        body = (report.content or "").encode("utf-8")

    return Response(
        content=body,
        media_type=report.content_type,
        headers={
            "Content-Disposition": (
                f'{disposition}; filename="{report.file_name}"'
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )

"""Generated report metadata and download endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Response

from app.api.deps import SessionDep
from app.schemas.report import ReportRead
from app.services import reports as report_service

router = APIRouter(prefix="/reports", tags=["reports"])


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
                f'attachment; filename="{report.file_name}"'
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )

"""Request and response schemas for generated reports."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import computed_field

from app.schemas.common import ORMModel, Page

ReportFormat = Literal["html", "json"]
ReportStatus = Literal["pending", "generated", "failed"]


class ReportCreate(ORMModel):
    format: ReportFormat


class ReportRead(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    format: ReportFormat
    status: ReportStatus
    version: int
    file_name: str
    content_type: str
    size_bytes: int | None
    content_sha256: str | None
    created_at: datetime
    generated_at: datetime | None

    @computed_field
    @property
    def download_url(self) -> str:
        return f"/api/v1/reports/{self.id}/download"


class ReportListResponse(Page[ReportRead]):
    pass

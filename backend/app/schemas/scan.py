"""Request and response schemas for scans and targets."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from app.schemas.common import ORMModel, Page

ScanStatus = Literal["pending", "running", "completed", "failed", "cancelled"]


class TargetCreate(ORMModel):
    url: str = Field(min_length=1, max_length=2048)
    authorization_reference: str | None = Field(default=None, max_length=255)

    @field_validator("url")
    @classmethod
    def url_must_not_be_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Target URL must not be blank.")
        return value.strip()


class ScanCreate(ORMModel):
    name: str | None = Field(default=None, max_length=200)
    profile: Literal["lean_mvp"] = "lean_mvp"
    targets: list[TargetCreate] = Field(min_length=1, max_length=50)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class ScanTargetRead(ORMModel):
    id: uuid.UUID
    url: str
    scheme: str
    hostname: str
    port: int | None
    path: str
    is_authorized: bool
    authorization_reference: str | None
    created_at: datetime


class ScanSummary(ORMModel):
    id: uuid.UUID
    name: str
    status: ScanStatus
    profile: str
    status_message: str | None
    created_by_id: uuid.UUID | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    updated_at: datetime
    target_count: int
    finding_count: int


class ScanDetail(ScanSummary):
    targets: list[ScanTargetRead]


class ScanStatusRead(ORMModel):
    id: uuid.UUID
    status: ScanStatus
    status_message: str | None
    started_at: datetime | None
    finished_at: datetime | None
    updated_at: datetime
    target_count: int
    finding_count: int


class ScanListResponse(Page[ScanSummary]):
    pass

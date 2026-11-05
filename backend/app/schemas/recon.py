"""Pydantic schemas for reconnaissance data and endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import ORMModel, Page


class TargetValidateRequest(ORMModel):
    url: str = Field(min_length=1, max_length=2048)


class TargetValidateResponse(ORMModel):
    url: str
    canonical_url: str
    hostname: str
    scheme: str
    port: int | None
    path: str
    resolved_ips: list[str]
    is_authorized: bool
    is_safe: bool


class DiscoveredEndpointRead(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    target_id: uuid.UUID
    method: str
    url: str
    path: str
    status_code: int | None
    content_type: str | None
    discovered_at: datetime


class DiscoveredEndpointListResponse(Page[DiscoveredEndpointRead]):
    pass


class TechnologyRead(ORMModel):
    name: str
    category: str
    confidence: str
    evidence: str


class FormFieldRead(ORMModel):
    name: str | None
    input_type: str
    required: bool


class FormRead(ORMModel):
    action: str
    method: str
    inputs: list[FormFieldRead]
    has_file_upload: bool
    has_password: bool


class TargetReconSummaryRead(ORMModel):
    target_id: uuid.UUID
    target_url: str
    hostname: str
    resolved_ips: list[str]
    status_code: int
    server_banner: str | None
    response_time_ms: float
    is_https: bool
    hsts_enabled: bool
    missing_security_headers: list[str]
    technologies: list[TechnologyRead]
    robots_txt_found: bool
    sitemap_found: bool
    security_txt_found: bool
    endpoints_count: int


class ScanReconSummaryResponse(ORMModel):
    scan_id: uuid.UUID
    status: str
    status_message: str | None
    total_endpoints: int
    targets: list[TargetReconSummaryRead]
    technologies: list[TechnologyRead]

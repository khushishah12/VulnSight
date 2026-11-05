"""Request and response schemas for findings, evidence, and remediation."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import Field

from app.schemas.common import ORMModel, Page

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["certain", "firm", "tentative"]
FindingStatus = Literal[
    "open",
    "in_progress",
    "remediated",
    "verified",
    "accepted_risk",
    "false_positive",
]
RemediationStatus = Literal[
    "not_started",
    "in_progress",
    "done",
    "accepted_risk",
]
VerificationStatus = Literal[
    "pending",
    "running",
    "passed",
    "failed",
    "error",
    "cancelled",
]


class EndpointRead(ORMModel):
    id: uuid.UUID
    method: str
    url: str
    path: str
    status_code: int | None
    content_type: str | None


class EvidenceRead(ORMModel):
    id: uuid.UUID
    kind: str
    label: str
    content: str
    content_sha256: str
    is_redacted: bool
    created_at: datetime


class RemediationRead(ORMModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    summary: str
    steps: list[str]
    references: list[str]
    status: RemediationStatus
    notes: str | None
    updated_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


class VerificationRead(ORMModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    status: VerificationStatus
    started_at: datetime | None
    finished_at: datetime | None
    result_summary: str | None
    details: dict[str, object] | None
    created_at: datetime


class FindingSummary(ORMModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    endpoint_id: uuid.UUID | None
    check_id: str
    owasp_category: str
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    created_at: datetime
    updated_at: datetime


class FindingDetail(FindingSummary):
    description: str
    fingerprint: str | None
    endpoint: EndpointRead | None
    evidence: list[EvidenceRead]
    remediation: RemediationRead | None
    verification_runs: list[VerificationRead]


class FindingListResponse(Page[FindingSummary]):
    pass


class RemediationUpdate(ORMModel):
    status: RemediationStatus
    notes: str | None = Field(default=None, max_length=2000)


class VerificationRequest(ORMModel):
    note: str | None = Field(default=None, max_length=1000)

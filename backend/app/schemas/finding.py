"""Request and response schemas for findings, evidence, remediation, and verification."""

from __future__ import annotations

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
    "fixed",
    "persists",
    "inconclusive",
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


class RiskAssessmentRead(ORMModel):
    score: float
    rating: str
    severity: str
    impact_score: float
    likelihood_score: float
    likelihood_level: str
    confidence: str
    confidence_weight: float
    formula: str
    scoring_method: str
    disclaimer: str


class CodeSnippetRead(ORMModel):
    stack_name: str
    vulnerable_code: str
    secure_code: str
    explanation: str


class FrameworkGuidanceRead(ORMModel):
    framework_name: str
    recommendations: list[str]
    config_snippet: str | None = None


class FixVerificationCriteriaRead(ORMModel):
    what_should_change: str
    check_to_rerun: str
    expected_evidence: str
    inconclusive_conditions: str


class RemediationGuideRead(ORMModel):
    check_id: str
    owasp_category: str
    title: str
    vulnerability_meaning: str
    why_it_occurs: str
    internal_workings: str
    safe_exploitation_scenario: str
    business_impact: str
    root_cause: str
    step_by_step_remediation: list[str]
    code_examples: dict[str, CodeSnippetRead]
    framework_guidance: dict[str, FrameworkGuidanceRead]
    fix_verification: FixVerificationCriteriaRead
    references: list[str]


class FindingSummary(ORMModel):
    """Standardized finding summary structure."""

    id: uuid.UUID
    scan_id: uuid.UUID
    endpoint_id: uuid.UUID | None = None
    check_id: str
    owasp_category: str
    title: str
    vulnerability_name: str | None = None
    affected_url: str | None = None
    severity: Severity
    confidence: Confidence
    risk_score: float | None = 0.0
    detection_method: str | None = "automated_security_check"
    status: FindingStatus
    remediation_status: RemediationStatus | None = None
    created_at: datetime
    detection_timestamp: datetime | None = None
    updated_at: datetime


class FindingDetail(FindingSummary):
    """Full finding detail with technical evidence, risk assessment, and remediation guidance."""

    description: str
    fingerprint: str | None = None
    endpoint: EndpointRead | None = None
    evidence: list[EvidenceRead] = []
    technical_evidence: list[EvidenceRead] = []
    remediation: RemediationRead | None = None
    risk_assessment: RiskAssessmentRead | None = None
    remediation_guide: RemediationGuideRead | None = None
    verification_runs: list[VerificationRead] = []


class FindingListResponse(Page[FindingSummary]):
    pass


class RemediationUpdate(ORMModel):
    status: RemediationStatus
    notes: str | None = Field(default=None, max_length=2000)


class VerificationRequest(ORMModel):
    note: str | None = Field(default=None, max_length=1000)
    execute_now: bool = False

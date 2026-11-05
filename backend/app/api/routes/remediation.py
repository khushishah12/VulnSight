"""Direct Remediation Center browsing endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from app.core.exceptions import NotFoundError
from app.remediation.knowledgebase import get_remediation_guide, list_available_guides
from app.schemas.finding import RemediationGuideRead

router = APIRouter(prefix="/remediation-center", tags=["remediation-center"])


@router.get("", response_model=list[RemediationGuideRead])
def list_remediation_guides() -> list[RemediationGuideRead]:
    """List all available multi-framework remediation guides in the Knowledgebase."""
    guides = list_available_guides()
    return [RemediationGuideRead.model_validate(g.to_dict()) for g in guides]


@router.get("/{check_id}", response_model=RemediationGuideRead)
def get_remediation_guide_by_check(check_id: str) -> RemediationGuideRead:
    """Retrieve full multi-framework remediation guide for a specific check ID."""
    guide = get_remediation_guide(check_id)
    if guide is None:
        raise NotFoundError(f"No remediation guide found for check '{check_id}'.")
    return RemediationGuideRead.model_validate(guide.to_dict())

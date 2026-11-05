"""Individual finding, remediation, and verification endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from app.api.deps import SessionDep
from app.schemas.finding import (
    FindingDetail,
    RemediationGuideRead,
    RemediationRead,
    RemediationUpdate,
    VerificationRead,
    VerificationRequest,
)
from app.services import findings as finding_service

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("/{finding_id}", response_model=FindingDetail)
async def get_finding(
    finding_id: uuid.UUID,
    session: SessionDep,
) -> FindingDetail:
    return await finding_service.get_finding(session, finding_id)


@router.get("/{finding_id}/remediation-guide", response_model=RemediationGuideRead)
async def get_finding_remediation_guide(
    finding_id: uuid.UUID,
    session: SessionDep,
) -> RemediationGuideRead:
    """Retrieve full multi-framework remediation guide for this finding."""
    return await finding_service.get_finding_remediation_guide(session, finding_id)


@router.patch(
    "/{finding_id}/remediation",
    response_model=RemediationRead,
)
async def update_remediation(
    finding_id: uuid.UUID,
    payload: RemediationUpdate,
    session: SessionDep,
) -> RemediationRead:
    return await finding_service.update_remediation(
        session,
        finding_id,
        payload,
    )


@router.post(
    "/{finding_id}/verify",
    response_model=VerificationRead,
    status_code=status.HTTP_202_ACCEPTED,
)
async def request_verification(
    finding_id: uuid.UUID,
    payload: VerificationRequest,
    session: SessionDep,
) -> VerificationRead:
    """Queue a fix verification request.

    The verification engine is not implemented yet. The request is stored as
    ``pending`` so it can be processed later without losing history.
    """

    return await finding_service.request_verification(
        session,
        finding_id,
        note=payload.note,
        execute_now=payload.execute_now,
    )

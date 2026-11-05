"""API routes for reconnaissance validation, endpoint listings, and summaries."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status
from sqlalchemy import func, select

from app.api.deps import LimitQuery, OffsetQuery, SessionDep
from app.core.exceptions import NotFoundError
from app.models.audit_log import AuditLog
from app.models.endpoint import DiscoveredEndpoint
from app.models.scan import ScanSession
from app.recon.validator import validate_recon_target
from app.schemas.recon import (
    DiscoveredEndpointListResponse,
    DiscoveredEndpointRead,
    ScanReconSummaryResponse,
    TargetReconSummaryRead,
    TargetValidateRequest,
    TargetValidateResponse,
    TechnologyRead,
)

router = APIRouter(tags=["recon"])


@router.post(
    "/recon/validate-target",
    response_model=TargetValidateResponse,
    status_code=status.HTTP_200_OK,
)
async def validate_target(payload: TargetValidateRequest) -> TargetValidateResponse:
    """Validate a target URL, resolve DNS, and verify SSRF safety rules."""
    scope = await validate_recon_target(payload.url, enforce_scope=True)
    return TargetValidateResponse(
        url=scope.raw_url,
        canonical_url=scope.canonical_url,
        hostname=scope.hostname,
        scheme=scope.scheme,
        port=scope.port,
        path=scope.path,
        resolved_ips=list(scope.resolved_ips),
        is_authorized=True,
        is_safe=True,
    )


@router.get(
    "/recon/scans/{scan_id}/endpoints",
    response_model=DiscoveredEndpointListResponse,
    include_in_schema=False,
)
@router.get(
    "/scans/{scan_id}/endpoints",
    response_model=DiscoveredEndpointListResponse,
)
async def list_scan_endpoints(
    scan_id: uuid.UUID,
    session: SessionDep,
    method: str | None = Query(default=None),
    limit: LimitQuery = 20,
    offset: OffsetQuery = 0,
) -> DiscoveredEndpointListResponse:
    """Return paginated list of discovered endpoints stored in PostgreSQL for a scan."""
    # Confirm scan exists
    scan_exists = await session.execute(
        select(ScanSession.id).where(ScanSession.id == scan_id)
    )
    if scan_exists.scalar_one_or_none() is None:
        raise NotFoundError("Scan not found.")

    filters = [DiscoveredEndpoint.scan_id == scan_id]
    if method:
        filters.append(DiscoveredEndpoint.method == method.upper())

    total_query = select(func.count(DiscoveredEndpoint.id)).where(*filters)
    total = int((await session.execute(total_query)).scalar_one())

    records_query = (
        select(DiscoveredEndpoint)
        .where(*filters)
        .order_by(DiscoveredEndpoint.discovered_at.desc(), DiscoveredEndpoint.url.asc())
        .limit(limit)
        .offset(offset)
    )
    rows = (await session.execute(records_query)).scalars().all()

    return DiscoveredEndpointListResponse(
        items=[DiscoveredEndpointRead.model_validate(r) for r in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/scans/{scan_id}/recon",
    response_model=ScanReconSummaryResponse,
)
async def get_scan_recon_summary(
    scan_id: uuid.UUID,
    session: SessionDep,
) -> ScanReconSummaryResponse:
    """Return consolidated reconnaissance summary, detected technologies, and targets."""
    scan = (
        await session.execute(
            select(ScanSession).where(ScanSession.id == scan_id)
        )
    ).scalar_one_or_none()

    if scan is None:
        raise NotFoundError("Scan not found.")

    # Count total endpoints
    total_endpoints = int(
        (
            await session.execute(
                select(func.count(DiscoveredEndpoint.id)).where(
                    DiscoveredEndpoint.scan_id == scan_id
                )
            )
        ).scalar_one()
    )

    # Query recon audit log entries
    audit_query = select(AuditLog).where(
        AuditLog.scan_id == scan_id,
        AuditLog.action == "recon.completed",
    )
    audit_logs = (await session.execute(audit_query)).scalars().all()

    target_summaries: list[TargetReconSummaryRead] = []
    all_technologies: dict[str, TechnologyRead] = {}

    for log in audit_logs:
        details = log.details or {}
        tech_list = [
            TechnologyRead(**t) for t in details.get("technologies", [])
        ]
        for t in tech_list:
            all_technologies[t.name] = t

        target_summaries.append(
            TargetReconSummaryRead(
                target_id=log.entity_id or uuid.uuid4(),
                target_url=details.get("target_url", ""),
                hostname=details.get("target_url", "").split("/")[2] if "/" in details.get("target_url", "") else "",
                resolved_ips=[],
                status_code=details.get("status_code", 200),
                server_banner=details.get("server"),
                response_time_ms=details.get("response_time_ms", 0.0),
                is_https=details.get("is_https", False),
                hsts_enabled=details.get("hsts", False),
                missing_security_headers=details.get("missing_security_headers", []),
                technologies=tech_list,
                robots_txt_found=details.get("robots_txt_found", False),
                sitemap_found=details.get("sitemap_found", False),
                security_txt_found=details.get("security_txt_found", False),
                endpoints_count=details.get("discovered_endpoints_count", 0),
            )
        )

    return ScanReconSummaryResponse(
        scan_id=scan.id,
        status=scan.status,
        status_message=scan.status_message,
        total_endpoints=total_endpoints,
        targets=target_summaries,
        technologies=list(all_technologies.values()),
    )

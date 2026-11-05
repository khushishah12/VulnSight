"""Reconnaissance orchestrator service."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import NotFoundError
from app.models.audit_log import AuditLog
from app.models.endpoint import DiscoveredEndpoint
from app.models.scan import ScanSession
from app.models.target import ScanTarget
from app.recon.client import SafeReconClient
from app.recon.discovery import DiscoverySummary, TechnologyProfile, perform_full_discovery
from app.recon.html_recon import HtmlReconData, parse_html_recon
from app.recon.http_recon import HttpReconData, perform_http_recon
from app.recon.storage import record_recon_audit, store_discovered_endpoints
from app.recon.validator import TargetScope, validate_recon_target

logger = logging.getLogger(__name__)


@dataclass
class TargetReconResult:
    target_id: uuid.UUID
    target_url: str
    hostname: str
    resolved_ips: list[str]
    http_data: HttpReconData
    html_data: HtmlReconData
    discovery: DiscoverySummary
    stored_endpoints_count: int


@dataclass
class ScanReconResult:
    scan_id: uuid.UUID
    status: str
    targets: list[TargetReconResult] = field(default_factory=list)
    total_endpoints_discovered: int = 0
    technologies: list[TechnologyProfile] = field(default_factory=list)


async def run_reconnaissance_for_target(
    session: AsyncSession,
    *,
    scan_id: uuid.UUID,
    target: ScanTarget,
    client: SafeReconClient | None = None,
) -> TargetReconResult:
    """Execute complete reconnaissance workflow against one authorized scan target."""
    # 1. Target Validation & DNS resolution with SSRF defense
    scope: TargetScope = await validate_recon_target(
        target.url,
        enforce_scope=True,
    )

    recon_client = client or SafeReconClient(allow_loopback=scope.is_loopback)

    # 2. HTTP Reconnaissance
    http_data: HttpReconData = await perform_http_recon(scope, recon_client)

    # 3. HTML Reconnaissance (if HTML content returned)
    is_html = "text/html" in http_data.content_type.lower() or "<html" in http_data.raw_body.lower()
    html_data: HtmlReconData = (
        parse_html_recon(http_data.url, http_data.raw_body)
        if is_html
        else HtmlReconData(
            title=None,
            meta_tags={},
            internal_links=[],
            external_links=[],
            forms=[],
            scripts=[],
            external_scripts=[],
            stylesheets=[],
            interesting_endpoints=[],
            comments_with_paths=[],
        )
    )

    # 4. Safe Discovery (robots.txt, sitemap.xml, security.txt, technologies)
    discovery: DiscoverySummary = await perform_full_discovery(
        scope,
        recon_client,
        http_data,
        html_data,
    )

    # 5. Persist discovered endpoints into PostgreSQL
    known_statuses = {http_data.url: http_data.status_code}
    known_cts = {http_data.url: http_data.content_type}
    if discovery.robots.found:
        known_statuses[f"{target.url.rstrip('/')}/robots.txt"] = discovery.robots.status_code
    if discovery.security_txt.found:
        known_statuses[f"{target.url.rstrip('/')}/.well-known/security.txt"] = discovery.security_txt.status_code

    stored_records = await store_discovered_endpoints(
        session,
        scan_id=scan_id,
        target_id=target.id,
        urls=discovery.discovered_urls,
        known_statuses=known_statuses,
        known_content_types=known_cts,
    )

    # 6. Record audit log entry
    await record_recon_audit(
        session,
        scan_id=scan_id,
        target_id=target.id,
        target_url=target.url,
        http_data=http_data,
        discovery=discovery,
        stored_count=len(stored_records),
    )

    return TargetReconResult(
        target_id=target.id,
        target_url=target.url,
        hostname=scope.hostname,
        resolved_ips=list(scope.resolved_ips),
        http_data=http_data,
        html_data=html_data,
        discovery=discovery,
        stored_endpoints_count=len(stored_records),
    )


async def run_scan_reconnaissance(
    session: AsyncSession,
    scan_id: uuid.UUID,
) -> ScanReconResult:
    """Execute reconnaissance across all authorized targets of a scan session."""
    statement = (
        select(ScanSession)
        .options(selectinload(ScanSession.targets))
        .where(ScanSession.id == scan_id)
    )
    result = await session.execute(statement)
    scan = result.scalar_one_or_none()
    if scan is None:
        raise NotFoundError(f"Scan '{scan_id}' not found.")

    target_results: list[TargetReconResult] = []
    total_endpoints = 0
    all_techs: list[TechnologyProfile] = []

    for target in scan.targets:
        try:
            target_res = await run_reconnaissance_for_target(
                session,
                scan_id=scan.id,
                target=target,
            )
            target_results.append(target_res)
            total_endpoints += target_res.stored_endpoints_count
            all_techs.extend(target_res.discovery.technologies)
        except Exception as exc:
            logger.exception("Reconnaissance failed for target %s: %s", target.url, exc)
            continue

    # Update scan status message with reconnaissance summary
    tech_names = list({t.name for t in all_techs})
    tech_str = ", ".join(tech_names[:5]) if tech_names else "none detected"
    scan.status_message = (
        f"Reconnaissance complete: discovered {total_endpoints} endpoints "
        f"across {len(target_results)} targets. Identified technologies: {tech_str}."
    )
    await session.commit()

    return ScanReconResult(
        scan_id=scan.id,
        status=scan.status,
        targets=target_results,
        total_endpoints_discovered=total_endpoints,
        technologies=all_techs,
    )

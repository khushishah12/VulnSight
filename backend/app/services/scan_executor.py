"""Scan execution coordinator orchestrating reconnaissance and OWASP Top 10 detection."""

from __future__ import annotations

import asyncio
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.db.engine import AsyncSessionLocal
from app.models.endpoint import DiscoveredEndpoint
from app.models.scan import ScanSession
from app.recon.client import SafeReconClient
from app.recon.service import run_scan_reconnaissance
from app.recon.validator import validate_recon_target
from app.scanners.orchestrator import execute_all_scanners, persist_scan_findings
from app.services.scans import mark_scan_completed, mark_scan_failed

logger = logging.getLogger(__name__)

PLACEHOLDER_MESSAGE = (
    "Placeholder executor finished. Scanner modules are not implemented yet, "
    "so no vulnerability checks or network requests were performed."
)


async def run_scan_execution(scan_id: uuid.UUID) -> None:
    """Execute complete scan workflow (reconnaissance + OWASP Top 10 scanners)."""
    if AsyncSessionLocal is None:
        logger.warning("Database session factory is unavailable.")
        return

    mode = settings.scan_executor_mode.lower()

    if mode == "placeholder":
        await asyncio.sleep(0.5)
        async with AsyncSessionLocal() as session:
            try:
                await mark_scan_completed(
                    session,
                    scan_id,
                    message=PLACEHOLDER_MESSAGE,
                )
            except Exception:  # noqa: BLE001
                logger.exception("Placeholder scan executor failed for %s.", scan_id)
        return

    # Active Scanning Mode (Reconnaissance + OWASP Top 10 detection)
    logger.info("Executing vulnerability scan for %s in '%s' mode...", scan_id, mode)
    async with AsyncSessionLocal() as session:
        try:
            # 1. Run Reconnaissance Phase
            recon_result = await run_scan_reconnaissance(session, scan_id)

            # 2. Run OWASP Top 10 Scanners on each authorized target
            total_findings_count = 0

            # Query scan with its targets and newly discovered endpoints
            scan_query = (
                select(ScanSession)
                .options(
                    selectinload(ScanSession.targets),
                    selectinload(ScanSession.endpoints),
                )
                .where(ScanSession.id == scan_id)
            )
            scan = (await session.execute(scan_query)).scalar_one_or_none()

            if scan and recon_result.targets:
                for target_recon in recon_result.targets:
                    # Match target entity
                    target_scope = await validate_recon_target(
                        target_recon.target_url,
                        enforce_scope=True,
                    )
                    client = SafeReconClient(allow_loopback=target_scope.is_loopback)
                    target_endpoints = [
                        ep for ep in scan.endpoints if ep.target_id == target_recon.target_id
                    ]

                    # Execute all 10 OWASP Top 10:2025 scanner modules
                    finding_drafts = await execute_all_scanners(
                        target=target_scope,
                        endpoints=target_endpoints,
                        http_data=target_recon.http_data,
                        html_data=target_recon.html_data,
                        client=client,
                    )

                    # Persist findings to PostgreSQL
                    persisted = await persist_scan_findings(
                        session,
                        scan_id=scan_id,
                        findings=finding_drafts,
                    )
                    total_findings_count += len(persisted)

            # 3. Mark Scan Completed
            await mark_scan_completed(
                session,
                scan_id,
                message=(
                    f"Scan completed successfully. Discovered {recon_result.total_endpoints_discovered} "
                    f"endpoints and identified {total_findings_count} vulnerability findings across "
                    "OWASP Top 10:2025 categories."
                ),
            )
            await session.commit()
            logger.info(
                "Scan %s completed: %d endpoints, %d findings.",
                scan_id,
                recon_result.total_endpoints_discovered,
                total_findings_count,
            )
        except Exception as exc:  # noqa: BLE001
            logger.exception("Vulnerability scan execution failed for %s: %s", scan_id, exc)
            try:
                await mark_scan_failed(
                    session,
                    scan_id,
                    message=f"Scan execution failed: {exc}",
                )
            except Exception:
                logger.exception("Could not mark scan %s as failed.", scan_id)


# Backward-compatible alias
run_placeholder_scan = run_scan_execution

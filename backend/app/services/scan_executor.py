"""Scan execution coordinator supporting placeholder and active reconnaissance."""

from __future__ import annotations

import asyncio
import logging
import uuid

from app.core.config import settings
from app.db.engine import AsyncSessionLocal
from app.recon.service import run_scan_reconnaissance
from app.services.scans import mark_scan_completed, mark_scan_failed

logger = logging.getLogger(__name__)

PLACEHOLDER_MESSAGE = (
    "Placeholder executor finished. Scanner modules are not implemented yet, "
    "so no vulnerability checks or network requests were performed."
)


async def run_scan_execution(scan_id: uuid.UUID) -> None:
    """Execute scan workflow in background based on configured scan_executor_mode."""
    if AsyncSessionLocal is None:
        logger.warning("Database session factory is unavailable.")
        return

    mode = settings.scan_executor_mode.lower()

    if mode == "recon":
        logger.info("Executing reconnaissance phase for scan %s...", scan_id)
        async with AsyncSessionLocal() as session:
            try:
                recon_result = await run_scan_reconnaissance(session, scan_id)
                await mark_scan_completed(
                    session,
                    scan_id,
                    message=(
                        f"Reconnaissance completed. Discovered {recon_result.total_endpoints_discovered} "
                        f"endpoints across {len(recon_result.targets)} target(s)."
                    ),
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception("Reconnaissance execution failed for %s.", scan_id)
                try:
                    await mark_scan_failed(
                        session,
                        scan_id,
                        message=f"Reconnaissance failed: {exc}",
                    )
                except Exception:
                    logger.exception("Could not mark scan %s as failed.", scan_id)
        return

    # Default to placeholder mode for tests or simulation
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


# Backward-compatible alias for existing route handlers
run_placeholder_scan = run_scan_execution


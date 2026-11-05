"""Storage operations for reconnaissance results in PostgreSQL."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.endpoint import DiscoveredEndpoint
from app.recon.discovery import DiscoverySummary
from app.recon.http_recon import HttpReconData
from app.services.audit import record_audit


def compute_url_hash(url: str) -> str:
    """Compute SHA-256 hash for URL deduplication within btree index limits."""
    return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()


async def store_discovered_endpoints(
    session: AsyncSession,
    *,
    scan_id: uuid.UUID,
    target_id: uuid.UUID,
    urls: set[str],
    known_statuses: dict[str, int] | None = None,
    known_content_types: dict[str, str] | None = None,
    method: str = "GET",
) -> list[DiscoveredEndpoint]:
    """Persist normalized discovered endpoints into the PostgreSQL database.

    Avoids duplicates by inspecting existing (scan_id, method, url_hash) pairs.
    """
    if not urls:
        return []

    status_map = known_statuses or {}
    ct_map = known_content_types or {}

    # Query already recorded hashes for this scan
    existing_hashes_query = select(DiscoveredEndpoint.url_hash).where(
        DiscoveredEndpoint.scan_id == scan_id,
        DiscoveredEndpoint.method == method,
    )
    existing_result = await session.execute(existing_hashes_query)
    existing_hashes: set[str] = set(existing_result.scalars().all())

    new_records: list[DiscoveredEndpoint] = []
    seen_in_batch: set[str] = set()

    for raw_url in urls:
        clean_url = raw_url.strip()
        if not clean_url:
            continue
        try:
            parts = urlsplit(clean_url)
            path = parts.path or "/"
        except Exception:
            continue

        h = compute_url_hash(clean_url)
        if h in existing_hashes or h in seen_in_batch:
            continue
        seen_in_batch.add(h)

        status_code = status_map.get(clean_url)
        # Ensure status code satisfies CheckConstraint (100-599)
        if status_code is not None and not (100 <= status_code <= 599):
            status_code = None

        content_type = ct_map.get(clean_url)
        if content_type and len(content_type) > 255:
            content_type = content_type[:255]

        endpoint = DiscoveredEndpoint(
            scan_id=scan_id,
            target_id=target_id,
            method=method,
            url=clean_url,
            url_hash=h,
            path=path[:2048],
            status_code=status_code,
            content_type=content_type,
        )
        session.add(endpoint)
        new_records.append(endpoint)

    if new_records:
        await session.flush()

    return new_records


async def record_recon_audit(
    session: AsyncSession,
    *,
    scan_id: uuid.UUID,
    target_id: uuid.UUID,
    target_url: str,
    http_data: HttpReconData,
    discovery: DiscoverySummary,
    stored_count: int,
    actor_label: str = "recon-engine",
) -> None:
    """Record an append-only audit log entry with complete reconnaissance findings."""
    tech_list = [
        {
            "name": t.name,
            "category": t.category,
            "confidence": t.confidence,
            "evidence": t.evidence,
        }
        for t in discovery.technologies
    ]

    details: dict[str, Any] = {
        "target_url": target_url,
        "status_code": http_data.status_code,
        "server": http_data.server_banner,
        "response_time_ms": http_data.response_time_ms,
        "is_https": http_data.is_https,
        "hsts": http_data.https_hsts_enabled,
        "missing_security_headers": http_data.security_headers.missing_headers,
        "technologies": tech_list,
        "robots_txt_found": discovery.robots.found,
        "sitemap_found": discovery.sitemap.found,
        "security_txt_found": discovery.security_txt.found,
        "discovered_endpoints_count": stored_count,
    }

    record_audit(
        session,
        action="recon.completed",
        entity_type="scan",
        entity_id=scan_id,
        scan_id=scan_id,
        actor_label=actor_label,
        details=details,
    )

"""Audit-log helper.

Audit rows are added to the caller's transaction so the action and its audit
record commit or roll back together.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


def record_audit(
    session: AsyncSession,
    *,
    action: str,
    entity_type: str,
    entity_id: uuid.UUID | None,
    scan_id: uuid.UUID | None = None,
    actor_label: str = "local-admin",
    details: dict[str, object] | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_label=actor_label,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        scan_id=scan_id,
        details=details,
    )
    session.add(entry)
    return entry

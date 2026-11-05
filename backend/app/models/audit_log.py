"""Append-only audit trail for security-relevant actions."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import Uuid

from app.db.base import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan import ScanSession
    from app.models.user import User


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """One redacted, append-only record of an action.

    Never store secrets, raw evidence, cookies, tokens, or request bodies here.
    ``details`` should contain identifiers and small status changes only.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
        Index("ix_audit_logs_created_at", "created_at"),
    )

    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    actor_label: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="local-admin",
        server_default="local-admin",
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    entity_type: Mapped[str | None] = mapped_column(String(50))
    entity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_sessions.id", ondelete="SET NULL"),
        index=True,
    )
    details: Mapped[dict[str, object] | None] = mapped_column(JSON)
    request_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    actor: Mapped[User | None] = relationship(back_populates="audit_logs")
    scan: Mapped[ScanSession | None] = relationship(back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"AuditLog(id={self.id!r}, action={self.action!r})"

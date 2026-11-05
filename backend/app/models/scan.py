"""Scan session and lifecycle model."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.endpoint import DiscoveredEndpoint
    from app.models.finding import Finding
    from app.models.report import Report
    from app.models.target import ScanTarget
    from app.models.user import User


class ScanSession(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One authorized assessment run.

    Status transitions are:

    ``pending -> running -> completed | failed | cancelled``

    A partial unique index enforces the Lean MVP rule that only one scan may be
    running at a time. The service also checks this to return a friendly error.
    """

    __tablename__ = "scan_sessions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed', "
            "'cancelled')",
            name="status_allowed",
        ),
        CheckConstraint(
            "profile IN ('lean_mvp')",
            name="profile_allowed",
        ),
        Index("ix_scan_sessions_created_at", "created_at"),
        Index(
            "uq_scan_sessions_single_running",
            "status",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )
    profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="lean_mvp",
        server_default="lean_mvp",
    )
    status_message: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    created_by: Mapped[User | None] = relationship(back_populates="scans")
    targets: Mapped[list[ScanTarget]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="ScanTarget.created_at",
    )
    endpoints: Mapped[list[DiscoveredEndpoint]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        back_populates="scan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"ScanSession(id={self.id!r}, status={self.status!r})"

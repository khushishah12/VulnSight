"""Fix verification request history."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.user import User


class VerificationRun(UUIDPrimaryKeyMixin, Base):
    """A request to re-test one finding after remediation.

    The verification engine is not implemented in this step. A request creates a
    ``pending`` row so the workflow and history are visible and future workers
    have a durable queue.
    """

    __tablename__ = "verification_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'passed', 'failed', 'error', "
            "'cancelled')",
            name="status_allowed",
        ),
        Index(
            "ix_verification_runs_finding_created",
            "finding_id",
            "created_at",
        ),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    result_summary: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, object] | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    finding: Mapped[Finding] = relationship(back_populates="verification_runs")
    requested_by: Mapped[User | None] = relationship(
        back_populates="verification_requests",
    )

    def __repr__(self) -> str:
        return f"VerificationRun(id={self.id!r}, status={self.status!r})"

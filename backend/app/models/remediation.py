"""Remediation guidance and operator workflow state for one finding."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.user import User


class Remediation(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One-to-one remediation record for a finding.

    Keeping instructions and workflow state together avoids duplicating the same
    guidance across every finding of a check type while still allowing each
    finding to be handled independently.
    """

    __tablename__ = "remediations"
    __table_args__ = (
        CheckConstraint(
            "status IN ('not_started', 'in_progress', 'done', 'accepted_risk')",
            name="status_allowed",
        ),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    steps: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    references: Mapped[list[str]] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="not_started",
        server_default="not_started",
        index=True,
    )
    notes: Mapped[str | None] = mapped_column(Text)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )

    finding: Mapped[Finding] = relationship(back_populates="remediation")
    updated_by: Mapped[User | None] = relationship(
        back_populates="remediation_updates",
    )

    def __repr__(self) -> str:
        return f"Remediation(id={self.id!r}, status={self.status!r})"

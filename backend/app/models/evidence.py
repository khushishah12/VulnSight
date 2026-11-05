"""Redacted evidence attached to a finding."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    String,
    Text,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.finding import Finding


class Evidence(UUIDPrimaryKeyMixin, Base):
    """Supporting proof for a finding.

    Evidence must be redacted before storage. Raw cookies, authorization
    headers, passwords, and session tokens must never be written here.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        CheckConstraint(
            "kind IN ('request', 'response', 'screenshot', 'log', 'text')",
            name="kind_allowed",
        ),
        CheckConstraint(
            "length(content_sha256) = 64",
            name="sha256_length",
        ),
    )

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    is_redacted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    finding: Mapped[Finding] = relationship(back_populates="evidence")

    def __repr__(self) -> str:
        return f"Evidence(id={self.id!r}, kind={self.kind!r})"

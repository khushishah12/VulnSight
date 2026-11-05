"""Generated HTML and JSON report metadata and content."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.scan import ScanSession
    from app.models.user import User


class Report(UUIDPrimaryKeyMixin, Base):
    """A stored report snapshot for one scan and format.

    Reports are snapshots. Regenerating a report creates a new version rather
    than mutating historical output.
    """

    __tablename__ = "reports"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "format",
            "version",
            name="uq_reports_scan_format_version",
        ),
        CheckConstraint(
            "format IN ('html', 'json', 'pdf')",
            name="format_allowed",
        ),
        CheckConstraint(
            "status IN ('pending', 'generated', 'failed')",
            name="status_allowed",
        ),
        CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="size_nonnegative",
        ),
        CheckConstraint(
            "content_sha256 IS NULL OR length(content_sha256) = 64",
            name="sha256_length",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    format: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        server_default="pending",
        index=True,
    )
    version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default="1",
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), nullable=False)
    content: Mapped[str | None] = mapped_column(Text)
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    size_bytes: Mapped[int | None] = mapped_column(Integer)
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    scan: Mapped[ScanSession] = relationship(back_populates="reports")
    generated_by: Mapped[User | None] = relationship(back_populates="reports")

    def __repr__(self) -> str:
        return (
            f"Report(id={self.id!r}, format={self.format!r}, "
            f"version={self.version!r})"
        )

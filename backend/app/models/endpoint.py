"""Endpoints discovered during a scan."""

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
    from app.models.finding import Finding
    from app.models.scan import ScanSession
    from app.models.target import ScanTarget


class DiscoveredEndpoint(UUIDPrimaryKeyMixin, Base):
    """A URL + HTTP method discovered under an authorized target.

    The full URL is stored as text because it can be long. Deduplication uses a
    SHA-256 ``url_hash`` so the unique index stays within PostgreSQL btree size
    limits.
    """

    __tablename__ = "discovered_endpoints"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "method",
            "url_hash",
            name="uq_discovered_endpoints_scan_method_url",
        ),
        CheckConstraint(
            "method IN ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', "
            "'OPTIONS')",
            name="method_allowed",
        ),
        CheckConstraint(
            "status_code IS NULL OR (status_code >= 100 AND status_code <= 599)",
            name="status_code_range",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    method: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="GET",
        server_default="GET",
    )
    url: Mapped[str] = mapped_column(Text, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(2048), nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    content_type: Mapped[str | None] = mapped_column(String(255))
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    scan: Mapped[ScanSession] = relationship(back_populates="endpoints")
    target: Mapped[ScanTarget] = relationship(back_populates="endpoints")
    findings: Mapped[list[Finding]] = relationship(
        back_populates="endpoint",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"DiscoveredEndpoint(id={self.id!r}, "
            f"method={self.method!r}, url={self.url!r})"
        )

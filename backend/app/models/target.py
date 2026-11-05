"""Per-scan authorized target scope."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.endpoint import DiscoveredEndpoint
    from app.models.scan import ScanSession


class ScanTarget(UUIDPrimaryKeyMixin, Base):
    """A URL the operator explicitly authorized for this scan.

    ``is_authorized`` is stored so the report can show the scope declaration.
    The API additionally validates every hostname against ``SCAN_ALLOWED_HOSTS``
    before this row is created.
    """

    __tablename__ = "scan_targets"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "url",
            name="uq_scan_targets_scan_url",
        ),
        CheckConstraint(
            "scheme IN ('http', 'https')",
            name="scheme_allowed",
        ),
        CheckConstraint(
            "port IS NULL OR (port >= 1 AND port <= 65535)",
            name="port_range",
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scheme: Mapped[str] = mapped_column(String(10), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    path: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        default="/",
        server_default="/",
    )
    is_authorized: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    authorization_reference: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    scan: Mapped[ScanSession] = relationship(back_populates="targets")
    endpoints: Mapped[list[DiscoveredEndpoint]] = relationship(
        back_populates="target",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"ScanTarget(id={self.id!r}, hostname={self.hostname!r})"

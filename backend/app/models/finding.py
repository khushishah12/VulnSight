"""Normalized vulnerability finding model."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import (
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.endpoint import DiscoveredEndpoint
    from app.models.evidence import Evidence
    from app.models.remediation import Remediation
    from app.models.scan import ScanSession
    from app.models.verification import VerificationRun


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One observed weakness mapped to an OWASP Top 10:2025 category."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "fingerprint",
            name="uq_findings_scan_fingerprint",
        ),
        CheckConstraint(
            "owasp_category IN ('A01', 'A02', 'A03', 'A04', 'A05', "
            "'A06', 'A07', 'A08', 'A09', 'A10')",
            name="owasp_category_allowed",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="severity_allowed",
        ),
        CheckConstraint(
            "confidence IN ('certain', 'firm', 'tentative')",
            name="confidence_allowed",
        ),
        CheckConstraint(
            "status IN ('open', 'in_progress', 'remediated', 'verified', "
            "'accepted_risk', 'false_positive')",
            name="status_allowed",
        ),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_scan_status", "scan_id", "status"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_sessions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    endpoint_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("discovered_endpoints.id", ondelete="SET NULL"),
        index=True,
    )
    check_id: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    owasp_category: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="firm",
        server_default="firm",
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="open",
        server_default="open",
        index=True,
    )
    fingerprint: Mapped[str | None] = mapped_column(String(64), index=True)
    risk_score: Mapped[float | None] = mapped_column(Float, index=True)
    detection_method: Mapped[str | None] = mapped_column(String(50))

    scan: Mapped[ScanSession] = relationship(back_populates="findings")
    endpoint: Mapped[DiscoveredEndpoint | None] = relationship(
        back_populates="findings",
    )
    evidence: Mapped[list[Evidence]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="Evidence.created_at",
    )
    remediation: Mapped[Remediation | None] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
        uselist=False,
    )
    verification_runs: Mapped[list[VerificationRun]] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return (
            f"Finding(id={self.id!r}, check_id={self.check_id!r}, "
            f"severity={self.severity!r})"
        )

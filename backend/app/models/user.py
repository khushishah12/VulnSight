"""Local operator account model.

The Lean MVP has one local admin. Authentication endpoints are not part of this
step, so ``password_hash`` is nullable and no credentials are created here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, CheckConstraint, DateTime, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.mixins import TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from app.models.audit_log import AuditLog
    from app.models.remediation import Remediation
    from app.models.report import Report
    from app.models.scan import ScanSession
    from app.models.verification import VerificationRun


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A VulnSight operator.

    Only one local admin is needed for the Lean MVP. The role column exists so
    the data model can support analyst/viewer roles later without a destructive
    migration.
    """

    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint(
            "role IN ('admin', 'analyst', 'viewer')",
            name="role_allowed",
        ),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
    )

    email: Mapped[str] = mapped_column(
        String(320),
        nullable=False,
        unique=True,
        index=True,
    )
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="admin",
        server_default="admin",
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True)
    )

    scans: Mapped[list[ScanSession]] = relationship(
        back_populates="created_by",
        passive_deletes=True,
    )
    remediation_updates: Mapped[list[Remediation]] = relationship(
        back_populates="updated_by",
        passive_deletes=True,
    )
    verification_requests: Mapped[list[VerificationRun]] = relationship(
        back_populates="requested_by",
        passive_deletes=True,
    )
    reports: Mapped[list[Report]] = relationship(
        back_populates="generated_by",
        passive_deletes=True,
    )
    audit_logs: Mapped[list[AuditLog]] = relationship(
        back_populates="actor",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, email={self.email!r})"

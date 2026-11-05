"""SQLAlchemy models.

Importing this package registers every model on ``Base.metadata`` so Alembic
autogenerate can see the complete schema.
"""

from app.models.audit_log import AuditLog
from app.models.endpoint import DiscoveredEndpoint
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.remediation import Remediation
from app.models.report import Report
from app.models.scan import ScanSession
from app.models.target import ScanTarget
from app.models.user import User
from app.models.verification import VerificationRun

__all__ = [
    "AuditLog",
    "DiscoveredEndpoint",
    "Evidence",
    "Finding",
    "Remediation",
    "Report",
    "ScanSession",
    "ScanTarget",
    "User",
    "VerificationRun",
]

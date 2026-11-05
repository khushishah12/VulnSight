"""Base scanner interface and data transfer contracts for VulnSight detection engine."""

from __future__ import annotations

import hashlib
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope


@dataclass
class FindingEvidenceDraft:
    """Evidence artifact attached to a vulnerability finding."""

    kind: str  # request, response, text, log
    label: str
    content: str
    is_redacted: bool = True


@dataclass
class FindingDraft:
    """Structured vulnerability finding produced by a scanner module."""

    check_id: str
    owasp_category: str  # A01 through A10
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    confidence: str  # certain, firm, tentative
    endpoint_id: uuid.UUID | None = None
    fingerprint: str | None = None
    evidence: list[FindingEvidenceDraft] = field(default_factory=list)
    remediation_summary: str = ""
    remediation_steps: list[str] = field(default_factory=list)
    remediation_references: list[str] = field(default_factory=list)

    def compute_fingerprint(self, scan_id: uuid.UUID) -> str:
        """Generate a deterministic SHA-256 fingerprint for deduplication."""
        if self.fingerprint:
            return self.fingerprint
        raw = f"{scan_id}:{self.check_id}:{self.title}:{self.endpoint_id or 'none'}"
        self.fingerprint = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        return self.fingerprint


class BaseScanner(ABC):
    """Abstract base class that all OWASP Top 10 scanner modules must implement."""

    category_id: str
    category_name: str

    @abstractmethod
    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        """Execute non-destructive detection checks and return structured findings."""
        pass

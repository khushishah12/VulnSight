"""Data models for VulnSight Remediation Center and Fix Verification."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CodeSnippet:
    """Side-by-side vulnerable vs. secure implementation in a specific stack."""

    stack_name: str  # e.g., "Node.js / Express", "Python / FastAPI", "Python / Django", "Java / Spring Boot", "SQL"
    vulnerable_code: str
    secure_code: str
    explanation: str


@dataclass(frozen=True)
class FrameworkGuidance:
    """Best practice framework-specific configuration and middleware directives."""

    framework_name: str
    recommendations: list[str]
    config_snippet: str | None = None


@dataclass(frozen=True)
class FixVerificationCriteria:
    """Standardized criteria defining how to safely re-test and verify a remediation."""

    what_should_change: str
    check_to_rerun: str
    expected_evidence: str
    inconclusive_conditions: str


@dataclass(frozen=True)
class RemediationGuide:
    """Comprehensive, multi-framework Remediation Center guide for a vulnerability check."""

    check_id: str
    owasp_category: str
    title: str
    vulnerability_meaning: str
    why_it_occurs: str
    internal_workings: str
    safe_exploitation_scenario: str
    business_impact: str
    root_cause: str
    step_by_step_remediation: list[str]
    code_examples: dict[str, CodeSnippet]
    framework_guidance: dict[str, FrameworkGuidance]
    fix_verification: FixVerificationCriteria
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to serializable dictionary."""
        return {
            "check_id": self.check_id,
            "owasp_category": self.owasp_category,
            "title": self.title,
            "vulnerability_meaning": self.vulnerability_meaning,
            "why_it_occurs": self.why_it_occurs,
            "internal_workings": self.internal_workings,
            "safe_exploitation_scenario": self.safe_exploitation_scenario,
            "business_impact": self.business_impact,
            "root_cause": self.root_cause,
            "step_by_step_remediation": self.step_by_step_remediation,
            "code_examples": {
                k: {
                    "stack_name": v.stack_name,
                    "vulnerable_code": v.vulnerable_code,
                    "secure_code": v.secure_code,
                    "explanation": v.explanation,
                }
                for k, v in self.code_examples.items()
            },
            "framework_guidance": {
                k: {
                    "framework_name": v.framework_name,
                    "recommendations": v.recommendations,
                    "config_snippet": v.config_snippet,
                }
                for k, v in self.framework_guidance.items()
            },
            "fix_verification": {
                "what_should_change": self.fix_verification.what_should_change,
                "check_to_rerun": self.fix_verification.check_to_rerun,
                "expected_evidence": self.fix_verification.expected_evidence,
                "inconclusive_conditions": self.fix_verification.inconclusive_conditions,
            },
            "references": self.references,
        }

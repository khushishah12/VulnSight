"""Transparent risk assessment and prioritization engine for VulnSight findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

SeverityLevel = Literal["critical", "high", "medium", "low", "info"]
ConfidenceLevel = Literal["certain", "firm", "tentative"]
LikelihoodLevel = Literal["high", "medium", "low"]
RiskRating = Literal["Critical", "High", "Medium", "Low", "Informational"]

# Technical Impact base scores (0.0 to 10.0) based on potential damage to CIA triad
_SEVERITY_IMPACT: dict[str, float] = {
    "critical": 10.0,
    "high": 8.5,
    "medium": 5.5,
    "low": 3.0,
    "info": 1.0,
}

# Detection Confidence multipliers
_CONFIDENCE_WEIGHT: dict[str, float] = {
    "certain": 1.0,     # Cryptographic proof, direct file signature match, or leaked credential
    "firm": 0.95,       # Verified unencoded canary reflection, syntax error leakage, missing header
    "tentative": 0.80,  # Path keyword match, generic status code heuristic, potential SPA fallback
}

# Default exploit likelihood factors by check category/type
# Combines attack vector exposure (remote vs. local) and exploit ease (trivial vs. complex)
_DEFAULT_LIKELIHOOD: dict[str, tuple[float, LikelihoodLevel]] = {
    "A01": (0.85, "high"),     # Unauthenticated admin access / method tampering: easily reachable
    "A02": (0.75, "high"),     # Missing headers / exposed config: automated trivial discovery
    "A03": (0.60, "medium"),   # Outdated libraries: requires specific payload targeting the CVE
    "A04": (0.70, "high"),     # Insecure transport / missing Secure flag: network eavesdropping
    "A05": (0.80, "high"),     # Injection: direct parameter reflection / syntax manipulation
    "A06": (0.65, "medium"),   # Insecure design (CSRF): requires victim interaction / malicious page
    "A07": (0.75, "high"),     # Insecure cookies / URL session tokens: easily sniffed or leaked
    "A08": (0.55, "medium"),   # Missing SRI: requires third-party CDN compromise
    "A09": (0.45, "low"),      # Missing tracing / console logs: secondary reconnaissance intelligence
    "A10": (0.70, "high"),     # Stack trace leakage: directly elicited by malformed inputs
}


@dataclass(frozen=True)
class RiskAssessment:
    """Detailed risk assessment breakdown for a vulnerability finding."""

    score: float
    rating: RiskRating
    severity: SeverityLevel
    impact_score: float
    likelihood_score: float
    likelihood_level: LikelihoodLevel
    confidence: ConfidenceLevel
    confidence_weight: float
    formula: str
    scoring_method: str
    disclaimer: str


def calculate_risk_assessment(
    *,
    severity: str,
    confidence: str = "firm",
    owasp_category: str = "A01",
    custom_likelihood: float | None = None,
) -> RiskAssessment:
    """Calculate transparent risk assessment based on Impact, Likelihood, and Confidence.

    Scoring Methodology:
    --------------------
    1. Impact (I) [0.5 - 10.0]: Evaluates technical severity and damage to Confidentiality,
       Integrity, and Availability.
    2. Likelihood (L) [0.0 - 1.0]: Evaluates exposure (unauthenticated network reachability)
       and exploit ease (trivial automated vs. complex interaction).
    3. Confidence (C) [0.6 - 1.0]: Weights the scanner's evidentiary certainty.
    4. Formula:
           Raw Risk = Impact * (0.35 + 0.65 * Likelihood) * Confidence
           Risk Score = round(clamp(Raw Risk, 0.1, 10.0), 1)

    Qualitative Bands:
        9.0 - 10.0 : Critical
        7.0 - 8.9  : High
        4.0 - 6.9  : Medium
        1.0 - 3.9  : Low
        0.1 - 0.9  : Informational

    Important:
        This internal prioritization score is NOT an official FIRST CVSS score.
    """
    clean_sev = severity.lower() if severity.lower() in _SEVERITY_IMPACT else "medium"
    clean_conf = confidence.lower() if confidence.lower() in _CONFIDENCE_WEIGHT else "firm"
    category_prefix = owasp_category.upper()[:3]

    impact = _SEVERITY_IMPACT[clean_sev]
    conf_weight = _CONFIDENCE_WEIGHT[clean_conf]

    if custom_likelihood is not None:
        likelihood = max(0.1, min(1.0, custom_likelihood))
        if likelihood >= 0.7:
            lik_level: LikelihoodLevel = "high"
        elif likelihood >= 0.4:
            lik_level = "medium"
        else:
            lik_level = "low"
    else:
        likelihood, lik_level = _DEFAULT_LIKELIHOOD.get(category_prefix, (0.65, "medium"))

    # Formula execution
    raw_risk = impact * (0.35 + 0.65 * likelihood) * conf_weight
    final_score = round(max(0.1, min(10.0, raw_risk)), 1)

    # Determine qualitative rating
    if final_score >= 9.0:
        rating: RiskRating = "Critical"
    elif final_score >= 7.0:
        rating = "High"
    elif final_score >= 4.0:
        rating = "Medium"
    elif final_score >= 1.0:
        rating = "Low"
    else:
        rating = "Informational"

    formula_str = (
        f"Score = round(Impact ({impact:.1f}) * (0.35 + 0.65 * Likelihood ({likelihood:.2f})) "
        f"* Confidence ({conf_weight:.2f}), 1) = {final_score:.1f}"
    )

    return RiskAssessment(
        score=final_score,
        rating=rating,
        severity=clean_sev,  # type: ignore[arg-type]
        impact_score=impact,
        likelihood_score=likelihood,
        likelihood_level=lik_level,
        confidence=clean_conf,  # type: ignore[arg-type]
        confidence_weight=conf_weight,
        formula=formula_str,
        scoring_method="VulnSight Transparent Risk Scoring Matrix (TRSM v1)",
        disclaimer=(
            "VulnSight Risk Score is an internal automated heuristic prioritization metric "
            "based on technical impact, exposure likelihood, and scanner confidence. It is NOT "
            "an official FIRST CVSS score."
        ),
    )

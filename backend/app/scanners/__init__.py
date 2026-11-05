"""OWASP Top 10:2025 Vulnerability Detection Engine for VulnSight."""

from app.scanners.a01_access_control import AccessControlScanner
from app.scanners.a02_security_misconfiguration import SecurityMisconfigurationScanner
from app.scanners.a03_supply_chain import SupplyChainScanner
from app.scanners.a04_crypto_failures import CryptographicFailuresScanner
from app.scanners.a05_injection import InjectionScanner
from app.scanners.a06_insecure_design import InsecureDesignScanner
from app.scanners.a07_auth_failures import AuthenticationFailuresScanner
from app.scanners.a08_integrity_failures import IntegrityFailuresScanner
from app.scanners.a09_logging_failures import LoggingAndAlertingScanner
from app.scanners.a10_exceptional_conditions import ExceptionalConditionsScanner
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft
from app.scanners.orchestrator import (
    ALL_SCANNERS,
    execute_all_scanners,
    persist_scan_findings,
)

__all__ = [
    "ALL_SCANNERS",
    "AccessControlScanner",
    "AuthenticationFailuresScanner",
    "BaseScanner",
    "CryptographicFailuresScanner",
    "ExceptionalConditionsScanner",
    "FindingDraft",
    "FindingEvidenceDraft",
    "InjectionScanner",
    "InsecureDesignScanner",
    "IntegrityFailuresScanner",
    "LoggingAndAlertingScanner",
    "SecurityMisconfigurationScanner",
    "SupplyChainScanner",
    "execute_all_scanners",
    "persist_scan_findings",
]

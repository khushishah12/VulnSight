"""Reconnaissance engine package for VulnSight."""

from app.recon.client import ReconResponse, SafeReconClient
from app.recon.discovery import (
    DiscoverySummary,
    RobotsTxtData,
    SecurityTxtData,
    SitemapData,
    TechnologyProfile,
    detect_technologies,
    perform_full_discovery,
    probe_robots_txt,
    probe_security_txt,
    probe_sitemap,
)
from app.recon.exceptions import (
    DNSResolutionError,
    ReconError,
    RedirectBlockedError,
    SSRFBlockedError,
    TargetValidationError,
)
from app.recon.html_recon import (
    FormInput,
    HtmlForm,
    HtmlReconData,
    parse_html_recon,
)
from app.recon.http_recon import (
    HttpReconData,
    SecurityHeadersCheck,
    analyze_security_headers,
    detect_header_technologies,
    perform_http_recon,
)
from app.recon.service import (
    ScanReconResult,
    TargetReconResult,
    run_reconnaissance_for_target,
    run_scan_reconnaissance,
)
from app.recon.storage import record_recon_audit, store_discovered_endpoints
from app.recon.validator import (
    TargetScope,
    check_ip_ssrf,
    resolve_hostname_safe,
    validate_recon_target,
    validate_redirect_target,
    validate_target_syntax,
)

__all__ = [
    "DNSResolutionError",
    "DiscoverySummary",
    "FormInput",
    "HtmlForm",
    "HtmlReconData",
    "HttpReconData",
    "ReconError",
    "ReconResponse",
    "RedirectBlockedError",
    "RobotsTxtData",
    "SSRFBlockedError",
    "SafeReconClient",
    "ScanReconResult",
    "SecurityHeadersCheck",
    "SecurityTxtData",
    "SitemapData",
    "TargetReconResult",
    "TargetScope",
    "TargetValidationError",
    "TechnologyProfile",
    "analyze_security_headers",
    "check_ip_ssrf",
    "detect_header_technologies",
    "detect_technologies",
    "parse_html_recon",
    "perform_full_discovery",
    "perform_http_recon",
    "probe_robots_txt",
    "probe_security_txt",
    "probe_sitemap",
    "record_recon_audit",
    "resolve_hostname_safe",
    "run_reconnaissance_for_target",
    "run_scan_reconnaissance",
    "store_discovered_endpoints",
    "validate_recon_target",
    "validate_redirect_target",
    "validate_target_syntax",
]

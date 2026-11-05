"""Tests for Target Validation, SSRF Protection, Scope Boundaries, and OWASP Scanners."""

from __future__ import annotations

import ipaddress
import pytest

from app.recon.exceptions import (
    DNSResolutionError,
    RedirectBlockedError,
    SSRFBlockedError,
    TargetValidationError,
)
from app.recon.validator import (
    CLOUD_METADATA_IPS,
    check_ip_ssrf,
    is_ip_address,
    normalize_hostname,
    validate_recon_target,
    validate_target_syntax,
)


# -----------------------------------------------------------------------------
# 1. Target URL Validation Tests
# -----------------------------------------------------------------------------
def test_url_syntax_rejects_forbidden_schemes():
    """Verify non-HTTP(S) schemes like ftp, file, gopher, and ldap are rejected."""
    for scheme in ["ftp://target.local", "file:///etc/passwd", "gopher://evil.com", "ldap://internal"]:
        with pytest.raises(TargetValidationError) as exc_info:
            validate_target_syntax(scheme)
        assert "Unsupported scheme" in str(exc_info.value)


def test_url_syntax_rejects_embedded_credentials():
    """Verify target URLs with user:pass credentials are blocked."""
    with pytest.raises(TargetValidationError) as exc_info:
        validate_target_syntax("https://admin:secret@target.internal")
    assert "Embedded credentials" in str(exc_info.value)


def test_url_syntax_rejects_url_fragments():
    """Verify base target URLs cannot contain fragments."""
    with pytest.raises(TargetValidationError) as exc_info:
        validate_target_syntax("https://target.internal/app#dashboard")
    assert "fragment" in str(exc_info.value)


def test_url_syntax_rejects_missing_hostname():
    """Verify URLs without hostnames are rejected."""
    for bad_url in ["https://", "http://:8080/path", ""]:
        with pytest.raises(TargetValidationError):
            validate_target_syntax(bad_url)


def test_url_syntax_normalizes_standard_ports():
    """Verify valid URLs are parsed correctly."""
    parts = validate_target_syntax("https://example.com:443/login")
    assert parts.scheme == "https"
    assert parts.hostname == "example.com"
    assert parts.port == 443


# -----------------------------------------------------------------------------
# 2. SSRF Protection & Cloud Metadata Blocking Tests
# -----------------------------------------------------------------------------
def test_ssrf_blocks_cloud_metadata_ips():
    """Verify well-known cloud metadata IP addresses are unconditionally blocked."""
    for meta_ip_str in ["169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"]:
        ip = ipaddress.ip_address(meta_ip_str)
        with pytest.raises(SSRFBlockedError) as exc_info:
            check_ip_ssrf(ip, allow_loopback=True)  # Even with allow_loopback=True, metadata must be blocked
        assert "metadata" in str(exc_info.value).lower()


def test_ssrf_blocks_private_rfc1918_networks():
    """Verify private IPv4 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are blocked."""
    private_ips = [
        "10.0.0.1",
        "10.254.1.5",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.100.50",
    ]
    for ip_str in private_ips:
        ip = ipaddress.ip_address(ip_str)
        with pytest.raises(SSRFBlockedError) as exc_info:
            check_ip_ssrf(ip, allow_loopback=False)
        assert "restricted" in str(exc_info.value).lower()


def test_ssrf_handles_loopback_permission_strictly():
    """Verify loopback is blocked by default unless allow_loopback is explicitly True."""
    loopback_ip = ipaddress.ip_address("127.0.0.1")
    # Blocked by default
    with pytest.raises(SSRFBlockedError):
        check_ip_ssrf(loopback_ip, allow_loopback=False)

    # Allowed when explicitly authorized for testing
    check_ip_ssrf(loopback_ip, allow_loopback=True)


# -----------------------------------------------------------------------------
# 3. Scope Boundary Enforcement
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scope_validation_rejects_unauthorized_hosts():
    """Verify targets outside SCAN_ALLOWED_HOSTS are rejected before DNS resolution."""
    unauthorized_url = "http://unauthorized-internal-server.corp:8080"
    with pytest.raises(TargetValidationError) as exc_info:
        await validate_recon_target(
            unauthorized_url,
            enforce_scope=True,
            override_allowed_hosts={"127.0.0.1", "localhost"},
        )
    assert "not in the authorized scope" in str(exc_info.value)


@pytest.mark.asyncio
async def test_scope_validation_accepts_authorized_loopback():
    """Verify target within authorized scope passes pre-flight validation."""
    authorized_url = "http://127.0.0.1:8000/app"
    scope = await validate_recon_target(
        authorized_url,
        enforce_scope=True,
        override_allowed_hosts={"127.0.0.1", "localhost"},
    )
    assert scope.hostname == "127.0.0.1"
    assert scope.port == 8000
    assert scope.is_loopback is True
    assert "127.0.0.1" in scope.resolved_ips

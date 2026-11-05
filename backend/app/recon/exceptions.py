"""Reconnaissance engine exceptions."""

from __future__ import annotations

from typing import Any

from app.core.exceptions import AppError


class ReconError(AppError):
    """Base exception for reconnaissance failures."""

    def __init__(
        self,
        message: str = "Reconnaissance operation failed.",
        code: str = "recon_error",
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, code=code, status_code=status_code, details=details)


class TargetValidationError(ReconError):
    """Raised when a target URL fails format, scheme, or scope validation."""

    def __init__(
        self,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code="target_validation_error",
            status_code=400,
            details=details,
        )


class SSRFBlockedError(ReconError):
    """Raised when an IP address is private, loopback, link-local, or cloud metadata."""

    def __init__(
        self,
        message: str = "Target resolved to a blocked internal or metadata IP address.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code="ssrf_blocked",
            status_code=403,
            details=details,
        )


class DNSResolutionError(ReconError):
    """Raised when hostname DNS resolution fails or times out."""

    def __init__(
        self,
        message: str = "Failed to resolve target hostname.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code="dns_resolution_failed",
            status_code=400,
            details=details,
        )


class RedirectBlockedError(ReconError):
    """Raised when an HTTP redirect violates scope or attempts an SSRF bypass."""

    def __init__(
        self,
        message: str = "Redirect blocked due to scope or security violation.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            code="redirect_blocked",
            status_code=403,
            details=details,
        )

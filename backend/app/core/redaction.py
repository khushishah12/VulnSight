"""Sensitive information redaction utilities for evidence and logs."""

from __future__ import annotations

import re

# Compiled regex patterns for detecting and redacting sensitive data
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Authorization headers (Bearer, Basic, API keys)
    (
        re.compile(r"(?i)(Authorization\s*:\s*)(?:Bearer|Basic)\s+[A-Za-z0-9_\-\.\+/=]+"),
        r"\1[REDACTED_AUTH_TOKEN]",
    ),
    # Password parameters in query strings or form bodies
    (
        re.compile(r"(?i)(password|passwd|pwd|secret|access_token|refresh_token)\s*=\s*[^&\s]+"),
        r"\1=[REDACTED]",
    ),
    # Password in JSON payloads
    (
        re.compile(r'(?i)"(password|passwd|pwd|secret|access_token|refresh_token)"\s*:\s*"[^"]+"'),
        r'"\1": "[REDACTED]"',
    ),
    # Common JWT pattern: eyJ...
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "[REDACTED_JWT_TOKEN]",
    ),
    # AWS Access Key ID
    (
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "[REDACTED_AWS_KEY]",
    ),
    # Generic API Key and Secret patterns (e.g., sk_live_..., api_key=...)
    (
        re.compile(r"(?i)(api[_-]?key|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-\.]{16,64}['\"]?"),
        r"\1=[REDACTED_API_KEY]",
    ),
    # Sensitive Cookie values (session ids)
    (
        re.compile(r"(?i)((?:session|sid|jwt|token|connect\.sid|PHPSESSID|JSESSIONID)\s*=\s*)[^;\s]+"),
        r"\1[REDACTED_SESSION_COOKIE]",
    ),
)


def redact_sensitive_text(text: str) -> tuple[str, bool]:
    """Scrub sensitive credentials, tokens, and keys from technical evidence.

    Returns:
        tuple[str, bool]: (scrubbed_text, was_redacted)
    """
    if not text:
        return text, False

    scrubbed = text
    was_modified = False

    for pattern, replacement in _PATTERNS:
        new_text = pattern.sub(replacement, scrubbed)
        if new_text != scrubbed:
            was_modified = True
            scrubbed = new_text

    return scrubbed, was_modified

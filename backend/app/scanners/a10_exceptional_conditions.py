"""A10:2025 - Mishandling of Exceptional Conditions Scanner Module."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

STACK_TRACE_PATTERNS = (
    # Python
    re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE),
    re.compile(r'File "[^"]+", line \d+, in ', re.IGNORECASE),
    # Java / Spring
    re.compile(r"java\.lang\.[A-Za-z]+Exception", re.IGNORECASE),
    re.compile(r"at org\.springframework\.", re.IGNORECASE),
    re.compile(r"at javax\.servlet\.", re.IGNORECASE),
    # PHP
    re.compile(r"Fatal error: Uncaught ", re.IGNORECASE),
    re.compile(r"Stack trace:\n#0 ", re.IGNORECASE),
    # ASP.NET
    re.compile(r"Server Error in '/' Application\.", re.IGNORECASE),
    re.compile(r"\[NullReferenceException: ", re.IGNORECASE),
    re.compile(r"System\.Web\.HttpUnhandledException", re.IGNORECASE),
    # Node / Express
    re.compile(r"at (?:async )?Function\.Module\._load", re.IGNORECASE),
)

INTERNAL_PATH_REGEX = re.compile(
    r"""(?:[a-zA-Z]:\\(?:Users|inetpub|Windows|app|src|var|home)\\[^\s"'<>]+|/(?:var/www|home/[a-z0-9_-]+|usr/share|opt/app)/[^\s"'<>]+)""",
    re.IGNORECASE,
)


class ExceptionalConditionsScanner(BaseScanner):
    """Scanner for OWASP A10:2025 - Mishandling of Exceptional Conditions."""

    category_id = "A10"
    category_name = "Mishandling of Exceptional Conditions"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # Trigger a deliberately malformed/non-existent route to inspect error handling
        error_probe_url = urljoin(target.canonical_url, "/vulnsight_error_probe_nonexistent_route_404")
        try:
            error_resp = await client.fetch(error_probe_url)
            body = error_resp.body_text
        except Exception:
            body = ""

        # Also inspect the baseline target response body in case it was an error
        bodies_to_inspect = [body]
        if http_data.raw_body:
            bodies_to_inspect.append(http_data.raw_body)

        for text in bodies_to_inspect:
            if not text:
                continue

            # 1. Stack Trace Disclosure
            for pattern in STACK_TRACE_PATTERNS:
                match = pattern.search(text)
                if match:
                    findings.append(
                        FindingDraft(
                            check_id="A10-VERBOSE-STACK-TRACE-DISCLOSURE",
                            owasp_category="A10",
                            title="Verbose Error Stack Trace Disclosure",
                            description=(
                                f"The server returned an unhandled exception or raw stack trace ('{match.group(0)}'). "
                                "Verbose stack traces reveal internal class structures, function names, underlying libraries, "
                                "and file system paths, enabling attackers to pinpoint specific software flaws."
                            ),
                            severity="high",
                            confidence="certain",
                            evidence=[
                                FindingEvidenceDraft(
                                    kind="response",
                                    label="Stack Trace Snippet",
                                    content=f"Matched Trace: {match.group(0)}\nContext: {text[max(0, match.start() - 50):match.end() + 200]}",
                                )
                            ],
                            remediation_summary="Disable debug modes and replace verbose stack traces with generic error views.",
                            remediation_steps=[
                                "Configure your framework (e.g. DEBUG = False in Django/Flask, production mode in Spring/Express).",
                                "Implement global exception handling middleware that logs errors internally and returns uniform sanitized JSON or static HTML error pages.",
                            ],
                            remediation_references=[
                                "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
                            ],
                        )
                    )
                    break

            # 2. Internal File System Path Leakage
            path_match = INTERNAL_PATH_REGEX.search(text)
            if path_match:
                findings.append(
                    FindingDraft(
                        check_id="A10-INTERNAL-FILE-PATH-LEAKAGE",
                        owasp_category="A10",
                        title="Internal File System Path Leakage in Error Response",
                        description=(
                            f"An internal operating system path ('{path_match.group(0)}') was disclosed in the response. "
                            "This exposes server directory layouts and usernames to unauthorized clients."
                        ),
                        severity="low",
                        confidence="firm",
                        evidence=[
                            FindingEvidenceDraft(
                                kind="response",
                                label="Disclosed File Path",
                                content=f"Path Leaked: {path_match.group(0)}",
                            )
                        ],
                        remediation_summary="Sanitize error output to prevent internal directory paths from leaking.",
                        remediation_steps=[
                            "Strip absolute server paths before rendering messages to clients.",
                            "Use custom error pages for 400, 404, and 500 status codes.",
                        ],
                        remediation_references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
                        ],
                    )
                )
                break

        return findings

"""A09:2025 - Security Logging and Alerting Failures Scanner Module."""

from __future__ import annotations

import re

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

TRACING_HEADERS = (
    "x-request-id",
    "x-correlation-id",
    "traceparent",
    "x-amzn-trace-id",
    "x-b3-traceid",
    "request-id",
)

SENSITIVE_LOG_REGEX = re.compile(
    r"""console\.(?:log|debug|info)\s*\([^)]*?(?:password|token|secret|credential|api_?key)[^)]*?\)""",
    re.IGNORECASE,
)


class LoggingAndAlertingScanner(BaseScanner):
    """Scanner for OWASP A09:2025 - Security Logging and Alerting Failures."""

    category_id = "A09"
    category_name = "Security Logging and Alerting Failures"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Missing Request ID / Distributed Tracing Headers
        headers = http_data.headers
        has_tracing = any(h in headers for h in TRACING_HEADERS)

        if not has_tracing:
            findings.append(
                FindingDraft(
                    check_id="A09-MISSING-REQUEST-CORRELATION-ID",
                    owasp_category="A09",
                    title="Missing Request ID / Correlation Tracing Header",
                    description=(
                        "The API response does not include a correlation identifier header "
                        "(e.g. X-Request-ID, Traceparent). Without request tracing, auditing security "
                        "events, incident response, and forensic correlation across distributed logs is significantly impaired."
                    ),
                    severity="info",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Response Headers Checked",
                            content=f"Received headers: {list(headers.keys())}",
                        )
                    ],
                    remediation_summary="Inject unique request correlation IDs into all incoming requests and responses.",
                    remediation_steps=[
                        "Generate a UUID or OpenTelemetry traceparent for every request at the API gateway or reverse proxy.",
                        "Attach the identifier to all application logs and return it via the X-Request-ID response header.",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/",
                    ],
                )
            )

        # 2. Client-Side Logging of Sensitive Keywords
        if http_data.raw_body:
            match = SENSITIVE_LOG_REGEX.search(http_data.raw_body)
            if match:
                findings.append(
                    FindingDraft(
                        check_id="A09-CLIENT-CONSOLE-SENSITIVE-LOGGING",
                        owasp_category="A09",
                        title="Potential Client-Side Console Logging of Sensitive Data",
                        description=(
                            "Detected client-side JavaScript console logging referencing sensitive keywords "
                            f"('{match.group(0)[:60]}...'). Tokens, passwords, or secrets may be exposed in browser developer tools."
                        ),
                        severity="low",
                        confidence="firm",
                        evidence=[
                            FindingEvidenceDraft(
                                kind="text",
                                label="Script Match",
                                content=match.group(0)[:120],
                            )
                        ],
                        remediation_summary="Strip all client-side console logging during production builds.",
                        remediation_steps=[
                            "Configure build minifiers (e.g. Terser / Babel) to strip console.log statements from production bundles.",
                        ],
                        remediation_references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html",
                        ],
                    )
                )

        return findings

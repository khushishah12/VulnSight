"""A07:2025 - Identification and Authentication Failures Scanner Module."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

SESSION_PARAM_REGEX = re.compile(
    r"[?&](session(?:_?id)?|sid|token|auth(?:_?token)?|jwt|access_token)=([a-zA-Z0-9_\-\.]+)",
    re.IGNORECASE,
)


class AuthenticationFailuresScanner(BaseScanner):
    """Scanner for OWASP A07:2025 - Identification and Authentication Failures."""

    category_id = "A07"
    category_name = "Authentication Failures"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Cookies Missing 'HttpOnly' Attribute
        non_httponly = [
            c["name"] for c in http_data.cookies if not c.get("httponly", False)
        ]
        if non_httponly:
            findings.append(
                FindingDraft(
                    check_id="A07-COOKIE-MISSING-HTTPONLY",
                    owasp_category="A07",
                    title="Session / Auth Cookies Missing 'HttpOnly' Flag",
                    description=(
                        f"The following cookies lack the 'HttpOnly' flag: {', '.join(non_httponly)}. "
                        "When HttpOnly is absent, client-side scripts can read document.cookie, "
                        "enabling attackers to steal active session tokens through Cross-Site Scripting (XSS)."
                    ),
                    severity="medium",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Cookie Flags Inspection",
                            content=f"Non-HttpOnly Cookies: {', '.join(non_httponly)}\nDetails: {http_data.cookies}",
                        )
                    ],
                    remediation_summary="Set the HttpOnly flag on all session and authentication cookies.",
                    remediation_steps=[
                        "Ensure Set-Cookie headers include '; HttpOnly'.",
                        "Store client-side non-sensitive preferences in separate cookies or localStorage.",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                    ],
                )
            )

        # 2. Cookies Missing 'SameSite' Attribute
        missing_samesite = [
            c["name"] for c in http_data.cookies if not c.get("samesite")
        ]
        if missing_samesite:
            findings.append(
                FindingDraft(
                    check_id="A07-COOKIE-MISSING-SAMESITE",
                    owasp_category="A07",
                    title="Cookies Missing 'SameSite' Attribute",
                    description=(
                        f"The following cookies do not specify a 'SameSite' attribute: {', '.join(missing_samesite)}. "
                        "Without SameSite (Lax or Strict), browsers may attach these cookies to cross-site requests, "
                        "increasing exposure to Cross-Site Request Forgery (CSRF)."
                    ),
                    severity="low",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="SameSite Attribute Audit",
                            content=f"Cookies without SameSite: {', '.join(missing_samesite)}",
                        )
                    ],
                    remediation_summary="Set SameSite=Lax or SameSite=Strict on all session cookies.",
                    remediation_steps=[
                        "Include '; SameSite=Lax' or '; SameSite=Strict' in all Set-Cookie headers.",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
                    ],
                )
            )

        # 3. Session Identifiers in URL Query Strings
        for ep in endpoints:
            match = SESSION_PARAM_REGEX.search(ep.url)
            if match:
                findings.append(
                    FindingDraft(
                        check_id="A07-SESSION-ID-IN-URL",
                        owasp_category="A07",
                        title=f"Session Identifier Exposed in URL Query String ({ep.path})",
                        description=(
                            f"Endpoint '{ep.path}' accepts or references a session/token parameter ('{match.group(1)}') "
                            "in the URL query string. Session IDs in URLs are logged in web server access logs, "
                            "browser histories, and forwarded in HTTP Referer headers to external links."
                        ),
                        severity="high",
                        confidence="firm",
                        endpoint_id=ep.id,
                        evidence=[
                            FindingEvidenceDraft(
                                kind="text",
                                label="URL Token Exposure",
                                content=f"URL: {ep.url}\nExposed Parameter: {match.group(1)}",
                            )
                        ],
                        remediation_summary="Transmit session tokens exclusively via HTTP headers or secure cookies.",
                        remediation_steps=[
                            "Pass session tokens in the Authorization header (e.g. Bearer token) or HttpOnly cookies.",
                            "Never pass tokens or credentials in URL query strings.",
                        ],
                        remediation_references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
                        ],
                    )
                )
                break

        return findings

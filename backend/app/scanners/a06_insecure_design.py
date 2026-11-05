"""A06:2025 - Insecure Design Scanner Module."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

SENSITIVE_FLOW_PATHS: tuple[str, ...] = (
    "/forgot-password",
    "/reset-password",
    "/api/forgot-password",
    "/api/reset-password",
    "/register",
    "/api/register",
)

CSRF_FIELD_NAMES = frozenset(
    {
        "csrf",
        "_csrf",
        "csrf_token",
        "_csrf_token",
        "csrftoken",
        "authenticity_token",
        "anti_csrf_token",
        "__requestverificationtoken",
    }
)


class InsecureDesignScanner(BaseScanner):
    """Scanner for OWASP A06:2025 - Insecure Design."""

    category_id = "A06"
    category_name = "Insecure Design"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. State-Changing POST Form Missing Anti-CSRF Token
        for form in html_data.forms:
            if form.method == "POST":
                input_names = {inp.name.lower() for inp in form.inputs if inp.name}
                has_csrf = bool(input_names & CSRF_FIELD_NAMES)

                # If this is an action/login/profile form without a CSRF token
                if not has_csrf and not any(k in form.action.lower() for k in ("search", "find", "query")):
                    findings.append(
                        FindingDraft(
                            check_id="A06-STATE-CHANGING-FORM-NO-CSRF",
                            owasp_category="A06",
                            title=f"State-Changing POST Form Missing Anti-CSRF Token ({form.action})",
                            description=(
                                f"A state-changing HTML form submitting to '{form.action}' via POST does not include "
                                "an anti-CSRF token input. If the application relies on cookie authentication, "
                                "attackers can trick authenticated victims into executing unintended actions via Cross-Site Request Forgery."
                            ),
                            severity="medium",
                            confidence="firm",
                            evidence=[
                                FindingEvidenceDraft(
                                    kind="text",
                                    label="Form Inputs Audit",
                                    content=f"Form Action: {form.action}\nMethod: POST\nForm Inputs: {list(input_names)}",
                                )
                            ],
                            remediation_summary="Implement anti-CSRF tokens for all state-changing HTML forms.",
                            remediation_steps=[
                                "Incorporate cryptographically unique, per-session or per-request CSRF tokens into state-changing forms.",
                                "Validate the token on the server side before executing any modifying action.",
                                "Set the SameSite attribute to Lax or Strict on all session cookies.",
                            ],
                            remediation_references=[
                                "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                            ],
                        )
                    )
                    break

        # 2. Rate-Limiting Assessment on Sensitive Business Flows
        for path in SENSITIVE_FLOW_PATHS:
            test_url = urljoin(target.canonical_url, path)
            try:
                resp = await client.fetch(test_url)
                if resp.status_code == 200:
                    headers = resp.headers
                    has_rate_limit_headers = any(
                        h in headers for h in ("ratelimit-limit", "x-ratelimit-limit", "retry-after")
                    )
                    if not has_rate_limit_headers:
                        findings.append(
                            FindingDraft(
                                check_id="A06-MISSING-RATE-LIMITING-SENSITIVE-FLOW",
                                owasp_category="A06",
                                title=f"Missing Rate-Limiting Controls on Sensitive Flow ({path})",
                                description=(
                                    f"The sensitive workflow endpoint '{path}' does not return standard rate-limiting headers "
                                    "(e.g. RateLimit-Limit, Retry-After). Without rate-limiting design controls, "
                                    "this workflow is susceptible to automated credential enumeration, email spamming, or resource exhaustion."
                                ),
                                severity="low",
                                confidence="tentative",
                                evidence=[
                                    FindingEvidenceDraft(
                                        kind="response",
                                        label="Sensitive Flow Headers",
                                        content=f"Endpoint: {path}\nStatus: {resp.status_code}\nHeaders: {dict(resp.headers)}",
                                    )
                                ],
                                remediation_summary="Design and enforce rate limiting on sensitive business flows.",
                                remediation_steps=[
                                    "Implement IP-based and account-based rate limiting on password reset and registration flows.",
                                    "Return HTTP 429 Too Many Requests and a Retry-After header when rate limits are exceeded.",
                                ],
                                remediation_references=[
                                    "https://owasp.org/Top10/A04_2021-Insecure_Design/",
                                ],
                            )
                        )
                        break
            except Exception:
                continue

        return findings

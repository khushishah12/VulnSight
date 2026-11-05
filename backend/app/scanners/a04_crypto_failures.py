"""A04:2025 - Cryptographic Failures Scanner Module."""

from __future__ import annotations

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft


class CryptographicFailuresScanner(BaseScanner):
    """Scanner for OWASP A04:2025 - Cryptographic Failures."""

    category_id = "A04"
    category_name = "Cryptographic Failures"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Cleartext HTTP Transport
        if not http_data.is_https and not target.is_loopback:
            findings.append(
                FindingDraft(
                    check_id="A04-CLEARTEXT-HTTP-TRANSIT",
                    owasp_category="A04",
                    title="Cleartext Unencrypted HTTP Communication",
                    description=(
                        "The application communicates over unencrypted HTTP without TLS encryption. "
                        "All network traffic, including credentials, session tokens, and sensitive data, "
                        "is vulnerable to passive eavesdropping and active Man-in-the-Middle (MitM) interception."
                    ),
                    severity="high",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Protocol Observation",
                            content=f"Target URL: {target.canonical_url}\nScheme: {target.scheme}",
                        )
                    ],
                    remediation_summary="Enforce TLS 1.3 encryption across all environments.",
                    remediation_steps=[
                        "Obtain a valid TLS certificate from a trusted Certificate Authority (e.g. Let's Encrypt).",
                        "Configure HTTP to automatically redirect (301) all requests to HTTPS.",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
                    ],
                )
            )

        # 2. Missing or Weak HSTS (Strict-Transport-Security)
        if http_data.is_https:
            hsts_val = http_data.headers.get("strict-transport-security")
            if not hsts_val:
                findings.append(
                    FindingDraft(
                        check_id="A04-MISSING-HSTS-HEADER",
                        owasp_category="A04",
                        title="Missing HTTP Strict Transport Security (HSTS) Header",
                        description=(
                            "The server communicates over HTTPS but does not send the Strict-Transport-Security header. "
                            "Clients will not enforce HTTPS on subsequent visits, leaving them vulnerable to SSL-stripping attacks."
                        ),
                        severity="medium",
                        confidence="certain",
                        evidence=[
                            FindingEvidenceDraft(
                                kind="text",
                                label="HSTS Absence Proof",
                                content=f"HTTPS headers checked: {list(http_data.headers.keys())}",
                            )
                        ],
                        remediation_summary="Configure the Strict-Transport-Security header.",
                        remediation_steps=[
                            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload to all HTTPS responses.",
                        ],
                        remediation_references=[
                            "https://owasp.org/www-project-secure-headers/#strict-transport-security",
                        ],
                    )
                )

        # 3. Cookies Missing the 'Secure' Flag
        insecure_cookies = [
            c["name"] for c in http_data.cookies if not c.get("secure", False)
        ]
        if insecure_cookies:
            findings.append(
                FindingDraft(
                    check_id="A04-COOKIE-MISSING-SECURE-FLAG",
                    owasp_category="A04",
                    title="Cookies Transmitted Without 'Secure' Attribute",
                    description=(
                        f"The following cookies were set without the 'Secure' attribute: {', '.join(insecure_cookies)}. "
                        "Browsers will transmit these cookies over unencrypted HTTP channels during cleartext requests, "
                        "exposing session identifiers to network interceptors."
                    ),
                    severity="medium",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Cookie Audit Detail",
                            content=f"Insecure Cookies: {', '.join(insecure_cookies)}\nAll Cookies: {http_data.cookies}",
                        )
                    ],
                    remediation_summary="Always set the 'Secure' attribute on cookies.",
                    remediation_steps=[
                        "Ensure all Set-Cookie directives specify '; Secure'.",
                        "Verify your web framework's session cookie configuration (e.g. SESSION_COOKIE_SECURE = True in Django).",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                    ],
                )
            )

        # 4. Password Form Submitting over HTTP
        for form in html_data.forms:
            if form.has_password and form.action.lower().startswith("http://") and not target.is_loopback:
                findings.append(
                    FindingDraft(
                        check_id="A04-PASSWORD-SUBMISSION-OVER-HTTP",
                        owasp_category="A04",
                        title="Password Form Submits Over Insecure HTTP",
                        description=(
                            f"A form containing password credentials submits to cleartext URL '{form.action}'. "
                            "User credentials will be transmitted over the network in plaintext."
                        ),
                        severity="high",
                        confidence="certain",
                        evidence=[
                            FindingEvidenceDraft(
                                kind="text",
                                label="Insecure Form Action",
                                content=f"Action: {form.action}\nMethod: {form.method}\nFields: {[i.name for i in form.inputs]}",
                            )
                        ],
                        remediation_summary="Ensure all authentication and credential forms submit over HTTPS.",
                        remediation_steps=[
                            "Update form action attributes to use HTTPS URLs or relative paths under HTTPS.",
                        ],
                        remediation_references=[
                            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
                        ],
                    )
                )

        return findings

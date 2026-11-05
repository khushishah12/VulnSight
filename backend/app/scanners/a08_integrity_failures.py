"""A08:2025 - Software and Data Integrity Failures Scanner Module."""

from __future__ import annotations

from bs4 import BeautifulSoup

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope, normalize_hostname
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft


class IntegrityFailuresScanner(BaseScanner):
    """Scanner for OWASP A08:2025 - Software and Data Integrity Failures."""

    category_id = "A08"
    category_name = "Software and Data Integrity Failures"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        if not http_data.raw_body:
            return findings

        soup = BeautifulSoup(http_data.raw_body, "html.parser")
        target_host = normalize_hostname(target.hostname)

        # 1. Missing Subresource Integrity (SRI) on External CDN Scripts
        unverified_external_scripts: list[str] = []

        for script in soup.find_all("script"):
            src = script.get("src")
            if not src:
                continue
            src_str = str(src).strip()

            # Check if script is loaded from an external domain
            if src_str.startswith(("http://", "https://", "//")):
                # Check for SRI integrity attribute
                integrity = script.get("integrity")
                if not integrity:
                    unverified_external_scripts.append(src_str)

        if unverified_external_scripts:
            findings.append(
                FindingDraft(
                    check_id="A08-MISSING-SUBRESOURCE-INTEGRITY",
                    owasp_category="A08",
                    title="Third-Party Scripts Loaded Without Subresource Integrity (SRI)",
                    description=(
                        f"Found {len(unverified_external_scripts)} external script(s) loaded without an "
                        "'integrity' attribute (e.g. integrity=\"sha384-...\"). "
                        "If the third-party CDN or external host is compromised or tampered with, "
                        "malicious JavaScript will execute in user browsers without validation."
                    ),
                    severity="medium",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Unverified Script Sources",
                            content="External scripts without SRI:\n" + "\n".join(unverified_external_scripts[:5]),
                        )
                    ],
                    remediation_summary="Add cryptographic Subresource Integrity (SRI) hashes to external script tags.",
                    remediation_steps=[
                        "Generate SRI hashes (e.g. openssl dgst -sha384 -binary file.js | openssl base64 -A).",
                        "Include integrity=\"sha384-...\" and crossorigin=\"anonymous\" on all external <script> and <link> elements.",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/",
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                    ],
                )
            )

        # 2. Insecure Mixed Content Scripts on HTTPS
        if http_data.is_https:
            insecure_scripts = [
                s for s in unverified_external_scripts if s.startswith("http://")
            ]
            if insecure_scripts:
                findings.append(
                    FindingDraft(
                        check_id="A08-MIXED-CONTENT-INSECURE-SCRIPT",
                        owasp_category="A08",
                        title="Mixed Content: Insecure Script Loaded Over Cleartext HTTP",
                        description=(
                            "The application is served over HTTPS but attempts to load executable JavaScript "
                            f"over unencrypted HTTP ({insecure_scripts[0]}). Active network attackers can intercept "
                            "and tamper with the script in transit."
                        ),
                        severity="high",
                        confidence="certain",
                        evidence=[
                            FindingEvidenceDraft(
                                kind="text",
                                label="Insecure Script URLs",
                                content="\n".join(insecure_scripts),
                            )
                        ],
                        remediation_summary="Serve all external assets and scripts exclusively over HTTPS.",
                        remediation_steps=[
                            "Update all script URLs to use https:// schemes or protocol-relative URLs.",
                            "Implement Content-Security-Policy: upgrade-insecure-requests.",
                        ],
                        remediation_references=[
                            "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                        ],
                    )
                )

        return findings

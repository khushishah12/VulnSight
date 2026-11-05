"""A03:2025 - Software Supply Chain Failures Scanner Module."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

KNOWN_OUTDATED_PATTERNS: tuple[tuple[str, str, str, str], ...] = (
    # (Regex, Component Name, Min Safe Version, Advisory)
    (r"jquery[.-](1\.[0-9]+\.[0-9]+|2\.[0-9]+\.[0-9]+|3\.[0-4]\.[0-9]+)", "jQuery", "3.5.0", "CVE-2020-11022 / CVE-2020-11023 (XSS)"),
    (r"angular[.-](1\.[0-7]\.[0-9]+)", "AngularJS (1.x)", "1.8.0+", "End-of-life framework with known prototype pollution and XSS issues"),
    (r"bootstrap[.-]([1-3]\.[0-9]+\.[0-9]+|4\.[0-2]\.[0-9]+)", "Bootstrap", "4.3.1", "CVE-2019-8331 (XSS in tooltip/popover)"),
)

MANIFEST_FILES: tuple[str, ...] = (
    "/package.json",
    "/package-lock.json",
    "/composer.json",
    "/requirements.txt",
)


class SupplyChainScanner(BaseScanner):
    """Scanner for OWASP A03:2025 - Software Supply Chain Failures."""

    category_id = "A03"
    category_name = "Software Supply Chain Failures"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Check for Outdated Frontend Component Versions
        all_scripts = html_data.scripts + html_data.external_scripts
        for script_url in all_scripts:
            for pattern, name, min_ver, advisory in KNOWN_OUTDATED_PATTERNS:
                match = re.search(pattern, script_url, re.IGNORECASE)
                if match:
                    detected_ver = match.group(1)
                    findings.append(
                        FindingDraft(
                            check_id="A03-OUTDATED-FRONTEND-LIBRARY",
                            owasp_category="A03",
                            title=f"Outdated Third-Party Component: {name} {detected_ver}",
                            description=(
                                f"The target loads an outdated version of {name} ({detected_ver}). "
                                f"This component is known to have public vulnerabilities ({advisory}). "
                                f"Minimum recommended version is {min_ver}."
                            ),
                            severity="medium",
                            confidence="firm",
                            evidence=[
                                FindingEvidenceDraft(
                                    kind="text",
                                    label="Script URL Reference",
                                    content=f"Detected Script: {script_url}\nComponent: {name}\nVersion: {detected_ver}",
                                )
                            ],
                            remediation_summary=f"Upgrade {name} to version {min_ver} or newer.",
                            remediation_steps=[
                                f"Replace {name} {detected_ver} with the latest stable release.",
                                "Implement automated dependency auditing (npm audit, Snyk, Dependabot) in CI/CD pipelines.",
                            ],
                            remediation_references=[
                                "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                                "https://osv.dev/",
                            ],
                        )
                    )
                    break

        # 2. Check for Exposed Dependency Manifests
        for manifest_path in MANIFEST_FILES:
            probe_url = urljoin(target.canonical_url, manifest_path)
            try:
                resp = await client.fetch(probe_url)
                if resp.status_code == 200 and resp.body_text:
                    body_sample = resp.body_text[:500].lower()
                    is_manifest = False
                    if "package" in manifest_path and ("dependencies" in body_sample or "version" in body_sample):
                        is_manifest = True
                    elif "composer" in manifest_path and "require" in body_sample:
                        is_manifest = True
                    elif "requirements" in manifest_path and ("==" in body_sample or ">=" in body_sample):
                        is_manifest = True

                    if is_manifest:
                        findings.append(
                            FindingDraft(
                                check_id="A03-EXPOSED-DEPENDENCY-MANIFEST",
                                owasp_category="A03",
                                title=f"Publicly Accessible Dependency Manifest ({manifest_path})",
                                description=(
                                    f"The software dependency manifest '{manifest_path}' is accessible without authentication. "
                                    "Attackers can enumerate exact third-party package names, versions, and supply chain dependencies."
                                ),
                                severity="medium",
                                confidence="certain",
                                evidence=[
                                    FindingEvidenceDraft(
                                        kind="response",
                                        label="Manifest File Content",
                                        content=f"Path: {manifest_path}\nPreview: {resp.body_text[:300]}",
                                    )
                                ],
                                remediation_summary="Remove dependency manifests from public web roots.",
                                remediation_steps=[
                                    "Ensure package.json, composer.json, and requirements.txt are outside the public docroot.",
                                    "Add web server rules blocking access to manifest and lock files.",
                                ],
                                remediation_references=[
                                    "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
                                ],
                            )
                        )
                        break
            except Exception:
                continue

        return findings

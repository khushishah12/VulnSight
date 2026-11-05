"""A01:2025 - Broken Access Control Scanner Module."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

ADMIN_CANDIDATE_PATHS: tuple[str, ...] = (
    "/admin",
    "/admin/",
    "/administrator",
    "/api/admin",
    "/api/v1/admin",
    "/manage",
    "/dashboard/users",
)


class AccessControlScanner(BaseScanner):
    """Scanner for OWASP A01:2025 - Broken Access Control."""

    category_id = "A01"
    category_name = "Broken Access Control"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Check for unauthenticated access to administrative endpoints
        for path in ADMIN_CANDIDATE_PATHS:
            test_url = urljoin(target.canonical_url, path)
            try:
                resp = await client.fetch(test_url)
            except Exception:
                continue

            # If an admin route returns 200 OK without requiring authentication
            if resp.status_code == 200 and resp.body_text:
                body_lower = resp.body_text.lower()
                # Confirm it looks like an actual admin/dashboard view and not a login page
                is_login_page = any(k in body_lower for k in ("sign in", "login", "password", "authenticate"))
                has_admin_content = any(k in body_lower for k in ("admin", "dashboard", "user management", "system settings", "control panel"))

                if has_admin_content and not is_login_page:
                    findings.append(
                        FindingDraft(
                            check_id="A01-UNAUTHENTICATED-ADMIN-PATH",
                            owasp_category="A01",
                            title=f"Unauthenticated Access to Administrative Endpoint ({path})",
                            description=(
                                f"The administrative interface at '{path}' was accessed without credentials "
                                f"and returned HTTP 200 OK with privileged dashboard indicators. "
                                f"Access control checks are either missing or bypassed."
                            ),
                            severity="high",
                            confidence="firm",
                            detection_method="active_path_probe",
                            evidence=[
                                FindingEvidenceDraft(
                                    kind="response",
                                    label="Administrative Response Snippet",
                                    content=f"Status: {resp.status_code}\nPath: {path}\nSnippet: {resp.body_text[:500]}",
                                ),
                            ],
                            remediation_summary="Enforce strict authentication and authorization checks on all administrative routes.",
                            remediation_steps=[
                                "Implement server-side role-based access control (RBAC) middleware for all /admin and privileged paths.",
                                "Deny unauthenticated requests by default with HTTP 401 Unauthorized or 403 Forbidden.",
                                "Do not rely on obscurity or hidden URLs for security.",
                            ],
                            remediation_references=[
                                "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
                            ],
                        )
                    )
                    break

        # 2. Check for HTTP Method Tampering on sensitive endpoints
        for ep in endpoints:
            if any(term in ep.path.lower() for term in ("user", "account", "profile", "setting")):
                try:
                    head_resp = await client.fetch(ep.url, method="HEAD")
                    if head_resp.status_code == 200 and (ep.status_code and ep.status_code in {401, 403}):
                        findings.append(
                            FindingDraft(
                                check_id="A01-METHOD-TAMPERING-BYPASS",
                                owasp_category="A01",
                                title=f"Potential Authorization Bypass via HTTP Method Tampering ({ep.path})",
                                description=(
                                    f"Endpoint '{ep.path}' required authorization under GET (HTTP {ep.status_code}), "
                                    f"but returned HTTP 200 OK when requested via HEAD without credentials. "
                                    f"Authorization rules may be bound to specific verbs rather than the entire resource."
                                ),
                                severity="medium",
                                confidence="tentative",
                                detection_method="active_verb_tampering",
                                endpoint_id=ep.id,
                                evidence=[
                                    FindingEvidenceDraft(
                                        kind="response",
                                        label="HEAD Verb Response",
                                        content=f"HEAD status: {head_resp.status_code}\nHeaders: {head_resp.headers}",
                                    ),
                                ],
                                remediation_summary="Apply authorization policies uniformly across all HTTP verbs.",
                                remediation_steps=[
                                    "Configure web server and application frameworks to enforce authorization globally per path.",
                                    "Explicitly disallow unused HTTP verbs (HEAD, OPTIONS, TRACE) on protected endpoints.",
                                ],
                                remediation_references=[
                                    "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                                ],
                            )
                        )
                        break
                except Exception:
                    continue

        return findings

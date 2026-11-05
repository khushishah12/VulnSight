"""A02:2025 - Security Misconfiguration Scanner Module."""

from __future__ import annotations

from urllib.parse import urljoin

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

SENSITIVE_FILES_TO_PROBE: tuple[str, ...] = (
    "/.env",
    "/.git/HEAD",
    "/docker-compose.yml",
    "/web.config",
)


class SecurityMisconfigurationScanner(BaseScanner):
    """Scanner for OWASP A02:2025 - Security Misconfiguration."""

    category_id = "A02"
    category_name = "Security Misconfiguration"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Missing Security Headers
        missing = http_data.security_headers.missing_headers
        if missing:
            findings.append(
                FindingDraft(
                    check_id="A02-MISSING-SECURITY-HEADERS",
                    owasp_category="A02",
                    title="Missing Defensive HTTP Security Headers",
                    description=(
                        f"The server is missing one or more standard defensive headers: {', '.join(missing)}. "
                        "Without these headers, clients are more susceptible to Clickjacking, cross-site scripting (XSS), "
                        "and MIME-sniffing attacks."
                    ),
                    severity="medium" if "Content-Security-Policy" in missing else "low",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Missing Headers Audit",
                            content=f"Missing: {', '.join(missing)}\nReceived Headers: {http_data.headers}",
                        )
                    ],
                    remediation_summary="Configure standard defensive HTTP response headers across all responses.",
                    remediation_steps=[
                        "Set Content-Security-Policy to restrict valid sources of scripts and resources.",
                        "Set X-Frame-Options: DENY or SAMEORIGIN to prevent framing and Clickjacking.",
                        "Set X-Content-Type-Options: nosniff to prevent browser MIME-type sniffing.",
                        "Set Strict-Transport-Security with max-age=31536000 and includeSubDomains on HTTPS.",
                    ],
                    remediation_references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
                    ],
                )
            )

        # 2. CORS Misconfiguration Check
        test_origin = "https://untrusted-third-party.example.com"
        try:
            cors_resp = await client.fetch(
                target.canonical_url,
                headers={"Origin": test_origin},
            )
            allow_origin = cors_resp.headers.get("access-control-allow-origin")
            allow_creds = cors_resp.headers.get("access-control-allow-credentials", "").lower() == "true"

            if allow_origin == test_origin and allow_creds:
                findings.append(
                    FindingDraft(
                        check_id="A02-PERMISSIVE-CORS-CREDENTIALS",
                        owasp_category="A02",
                        title="Insecure Cross-Origin Resource Sharing (CORS) with Credentials",
                        description=(
                            "The server reflects arbitrary untrusted Origin headers alongside "
                            "Access-Control-Allow-Credentials: true. An external malicious website can "
                            "issue authenticated requests and read private user responses."
                        ),
                        severity="high",
                        confidence="certain",
                        evidence=[
                            FindingEvidenceDraft(
                                kind="response",
                                label="CORS Reflection Proof",
                                content=f"Sent Origin: {test_origin}\nReceived Origin: {allow_origin}\nCredentials: true",
                            )
                        ],
                        remediation_summary="Restrict CORS origins to an explicit, trusted whitelist.",
                        remediation_steps=[
                            "Do not reflect untrusted request Origin headers into Access-Control-Allow-Origin.",
                            "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.",
                            "Maintain an explicit whitelist of authorized domains.",
                        ],
                        remediation_references=[
                            "https://portswigger.net/web-security/cors",
                        ],
                    )
                )
        except Exception:
            pass

        # 3. Check for exposed configuration and VCS files
        for sensitive_path in SENSITIVE_FILES_TO_PROBE:
            probe_url = urljoin(target.canonical_url, sensitive_path)
            try:
                probe_resp = await client.fetch(probe_url)
                if probe_resp.status_code == 200 and probe_resp.body_text:
                    body_sample = probe_resp.body_text[:300].strip()
                    is_valid = False
                    if sensitive_path == "/.env" and ("=" in body_sample and not "<html" in body_sample.lower()):
                        is_valid = True
                    elif sensitive_path == "/.git/HEAD" and ("ref: refs/" in body_sample or len(body_sample) == 40):
                        is_valid = True
                    elif sensitive_path == "/docker-compose.yml" and ("version:" in body_sample or "services:" in body_sample):
                        is_valid = True

                    if is_valid:
                        findings.append(
                            FindingDraft(
                                check_id="A02-EXPOSED-CONFIG-FILE",
                                owasp_category="A02",
                                title=f"Exposed Sensitive Configuration File ({sensitive_path})",
                                description=(
                                    f"The sensitive file '{sensitive_path}' is publicly accessible over HTTP. "
                                    "This exposes server architecture, secrets, environment variables, or source control metadata."
                                ),
                                severity="critical" if sensitive_path in ("/.env", "/.git/HEAD") else "high",
                                confidence="certain",
                                evidence=[
                                    FindingEvidenceDraft(
                                        kind="response",
                                        label="Exposed File Content Preview",
                                        content=f"Path: {sensitive_path}\nStatus: 200 OK\nPreview: {body_sample[:150]}",
                                    )
                                ],
                                remediation_summary="Restrict public web server access to dotfiles and configuration artifacts.",
                                remediation_steps=[
                                    "Configure web server rules to deny access to all hidden files (.*) and configuration files.",
                                    "Ensure build pipelines and deployment scripts do not place .git or .env in the web root.",
                                ],
                                remediation_references=[
                                    "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                                ],
                            )
                        )
            except Exception:
                continue

        # 4. Check for Directory Listing
        if "index of /" in (html_data.title or "").lower() or "parent directory" in html_data.internal_links:
            findings.append(
                FindingDraft(
                    check_id="A02-DIRECTORY-LISTING-ENABLED",
                    owasp_category="A02",
                    title="Web Server Directory Listing Enabled",
                    description=(
                        "The web server has directory indexing enabled. Attackers can view "
                        "and navigate file structures, uncovering backup files, scripts, and endpoints."
                    ),
                    severity="low",
                    confidence="certain",
                    evidence=[
                        FindingEvidenceDraft(
                            kind="text",
                            label="Directory Listing Indicator",
                            content=f"Page Title: {html_data.title}",
                        )
                    ],
                    remediation_summary="Disable directory indexing in the web server configuration.",
                    remediation_steps=[
                        "In Apache: Options -Indexes in httpd.conf or .htaccess.",
                        "In Nginx: autoindex off; in server and location blocks.",
                    ],
                    remediation_references=[
                        "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                    ],
                )
            )

        return findings

"""A05:2025 - Injection Scanner Module (Safe & Non-Destructive Probing)."""

from __future__ import annotations

import html
import re
from urllib.parse import urlencode, urljoin, urlparse, urlsplit, urlunsplit

from app.models.endpoint import DiscoveredEndpoint
from app.recon.client import SafeReconClient
from app.recon.html_recon import HtmlReconData
from app.recon.http_recon import HttpReconData
from app.recon.validator import TargetScope
from app.scanners.base import BaseScanner, FindingDraft, FindingEvidenceDraft

# Benign marker string that cannot execute code or harm databases
SAFE_PROBE_TOKEN = "vsight_safe_probe_77"
SAFE_XSS_TOKEN = "vsight<safe_tag_99>"

SQL_ERROR_PATTERNS = (
    re.compile(r"syntax error at or near", re.IGNORECASE),
    re.compile(r"you have an error in your sql syntax", re.IGNORECASE),
    re.compile(r"unclosed quotation mark before the character string", re.IGNORECASE),
    re.compile(r"quoted string not properly terminated", re.IGNORECASE),
    re.compile(r"sqlite3\.operationalerror", re.IGNORECASE),
    re.compile(r"pg_query\(\): query failed", re.IGNORECASE),
    re.compile(r"ora-[0-9]{5}", re.IGNORECASE),
)


class InjectionScanner(BaseScanner):
    """Scanner for OWASP A05:2025 - Injection."""

    category_id = "A05"
    category_name = "Injection"

    async def scan(
        self,
        target: TargetScope,
        endpoints: list[DiscoveredEndpoint],
        http_data: HttpReconData,
        html_data: HtmlReconData,
        client: SafeReconClient,
    ) -> list[FindingDraft]:
        findings: list[FindingDraft] = []

        # 1. Safe Reflected Input / XSS Testing on discovered forms and query endpoints
        candidate_urls: list[tuple[str, str]] = []  # (url, param_name)

        # Extract search or query inputs from HTML forms
        for form in html_data.forms:
            if form.method.upper() == "GET":
                for inp in form.inputs:
                    if inp.name and inp.input_type in ("text", "search", "q"):
                        candidate_urls.append((form.action, inp.name))

        # Check a sample of discovered endpoints with common query parameters
        if not candidate_urls:
            candidate_urls.append((target.canonical_url, "q"))
            candidate_urls.append((target.canonical_url, "search"))

        for endpoint_url, param_name in candidate_urls[:3]:
            # Test XSS Reflection
            test_query = urlencode({param_name: SAFE_XSS_TOKEN})
            parts = urlsplit(endpoint_url)
            probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", test_query, ""))

            try:
                probe_resp = await client.fetch(probe_url)
                if probe_resp.status_code == 200 and probe_resp.body_text:
                    # If the raw tag <safe_tag_99> appears unencoded in HTML
                    if "<safe_tag_99>" in probe_resp.body_text and "text/html" in probe_resp.content_type:
                        findings.append(
                            FindingDraft(
                                check_id="A05-REFLECTED-XSS-UNENCODED-INPUT",
                                owasp_category="A05",
                                title=f"Reflected Input without Contextual Encoding ({param_name})",
                                description=(
                                    f"The parameter '{param_name}' reflects user-supplied HTML metacharacters (<, >) "
                                    f"directly into the response body without contextual HTML entity encoding (&lt;, &gt;). "
                                    "This indicates vulnerability to Reflected Cross-Site Scripting (XSS)."
                                ),
                                severity="high",
                                confidence="certain",
                                evidence=[
                                    FindingEvidenceDraft(
                                        kind="response",
                                        label="Unencoded HTML Reflection",
                                        content=f"Probe URL: {probe_url}\nReflected Token: <safe_tag_99> found unencoded",
                                    )
                                ],
                                remediation_summary="Apply context-aware output encoding on all user reflections.",
                                remediation_steps=[
                                    "Use context-aware HTML entity encoding (&lt;, &gt;, &quot;, &#x27;) before rendering user input.",
                                    "Adopt modern web frameworks with auto-escaping template engines (e.g. Jinja2, React, Angular).",
                                    "Deploy a Content Security Policy (CSP) with strict-dynamic or nonces.",
                                ],
                                remediation_references=[
                                    "https://owasp.org/Top10/A03_2021-Injection/",
                                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                ],
                            )
                        )
                        break
            except Exception:
                continue

        # 2. Safe SQL Syntax Error Leakage Check
        for endpoint_url, param_name in candidate_urls[:3]:
            # Send single quote probe
            test_query = urlencode({param_name: "'"})
            parts = urlsplit(endpoint_url)
            probe_url = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", test_query, ""))

            try:
                sql_resp = await client.fetch(probe_url)
                if sql_resp.body_text:
                    for pattern in SQL_ERROR_PATTERNS:
                        match = pattern.search(sql_resp.body_text)
                        if match:
                            findings.append(
                                FindingDraft(
                                    check_id="A05-SQL-SYNTAX-ERROR-LEAKAGE",
                                    owasp_category="A05",
                                    title=f"Database Syntax Error Leakage on Input Probe ({param_name})",
                                    description=(
                                        f"Submitting a quotation delimiter to parameter '{param_name}' produced a raw database "
                                        f"syntax error message ('{match.group(0)}'). This strongly indicates unparameterized "
                                        "dynamic SQL concatenation and potential SQL Injection."
                                    ),
                                    severity="critical",
                                    confidence="firm",
                                    evidence=[
                                        FindingEvidenceDraft(
                                            kind="response",
                                            label="Database Error Message Leakage",
                                            content=f"Probe URL: {probe_url}\nMatched SQL Error: {match.group(0)}",
                                        )
                                    ],
                                    remediation_summary="Use parameterized queries / prepared statements for all database access.",
                                    remediation_steps=[
                                        "Never concatenate user input directly into SQL statement strings.",
                                        "Use ORM parameterized queries or prepared statements across all database operations.",
                                        "Disable verbose database error reporting in production.",
                                    ],
                                    remediation_references=[
                                        "https://owasp.org/Top10/A03_2021-Injection/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                    ],
                                )
                            )
                            break
            except Exception:
                continue

        return findings

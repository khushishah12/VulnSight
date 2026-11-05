"""Enterprise PDF Report Generator for VulnSight using ReportLab.

Produces executive and technical assessment deliverables including:
- Executive Summary & Posture Score
- Target & Scope Specifications
- OWASP Top 10 Category Coverage Matrix
- Vulnerability Statistics by Severity
- Detailed Technical Findings & Redacted Evidence
- Transparent Risk Factor Breakdown
- Step-by-Step Remediation Guidance
- Fix Verification Audit History
- Point-in-Time Limitations & Legal Disclaimers
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to draw running footer with total page count."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: list[dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(
                40,
                755,
                "VulnSight Enterprise Security Assessment Deliverable",
            )
            self.drawRightString(572, 755, "CONFIDENTIAL & PROPRIETARY")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(40, 750, 572, 750)

        # Running footer
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawString(
            40,
            30,
            "VulnSight Security Operations · Authorized Target Assessment",
        )
        self.drawRightString(572, 30, page_str)
        self.setStrokeColor(colors.HexColor("#e2e8f0"))
        self.setLineWidth(0.5)
        self.line(40, 38, 572, 38)
        self.restoreState()


def _get_severity_color(severity: str) -> colors.HexColor:
    sev = severity.lower()
    if sev == "critical":
        return colors.HexColor("#be123c")
    elif sev == "high":
        return colors.HexColor("#c2410c")
    elif sev == "medium":
        return colors.HexColor("#b45309")
    elif sev == "low":
        return colors.HexColor("#0369a1")
    return colors.HexColor("#475569")


def _calculate_score(counts: dict[str, int]) -> tuple[int, str]:
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)

    penalty = (crit * 15) + (high * 8) + (med * 3) + (low * 1)
    score = max(0, 100 - penalty)

    if score >= 90:
        grade = "A (Minimal Exposure)"
    elif score >= 75:
        grade = "B (Low Exposure)"
    elif score >= 60:
        grade = "C (Elevated Risk)"
    elif score >= 40:
        grade = "D (Substantial Risk)"
    else:
        grade = "F (Critical Posture)"

    return score, grade


def generate_pdf_report(snapshot: dict[str, Any]) -> bytes:
    """Build a comprehensive, publication-grade PDF deliverable from report snapshot."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=50,
        bottomMargin=50,
    )

    sample_styles = getSampleStyleSheet()

    # Custom typography matching SecOps palette
    styles = {
        "CoverTitle": ParagraphStyle(
            "CoverTitle",
            parent=sample_styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            alignment=TA_LEFT,
        ),
        "CoverSubtitle": ParagraphStyle(
            "CoverSubtitle",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#475569"),
            alignment=TA_LEFT,
        ),
        "SectionHeading": ParagraphStyle(
            "SectionHeading",
            parent=sample_styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True,
        ),
        "SubSectionHeading": ParagraphStyle(
            "SubSectionHeading",
            parent=sample_styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=10.5,
            leading=14,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=8,
            spaceAfter=4,
            keepWithNext=True,
        ),
        "Body": ParagraphStyle(
            "Body",
            parent=sample_styles["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#334155"),
        ),
        "BodyBold": ParagraphStyle(
            "BodyBold",
            parent=sample_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=12,
            textColor=colors.HexColor("#1e293b"),
        ),
        "CodeText": ParagraphStyle(
            "CodeText",
            parent=sample_styles["Normal"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
        ),
        "Disclaimer": ParagraphStyle(
            "Disclaimer",
            parent=sample_styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=7.5,
            leading=11,
            textColor=colors.HexColor("#64748b"),
        ),
        "BadgeText": ParagraphStyle(
            "BadgeText",
            parent=sample_styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            alignment=TA_CENTER,
            textColor=colors.white,
        ),
    }

    elements: list[Any] = []

    scan = snapshot.get("scan", {})
    summary = snapshot.get("summary", {})
    by_severity = summary.get("by_severity", {})
    by_owasp = summary.get("by_owasp_category", {})
    targets = snapshot.get("targets", [])
    findings = snapshot.get("findings", [])

    score, grade = _calculate_score(by_severity)

    # -------------------------------------------------------------------------
    # 1. Header Banner & Title Block
    # -------------------------------------------------------------------------
    elements.append(
        Paragraph("VulnSight Enterprise Security Assessment", styles["CoverTitle"])
    )
    elements.append(
        Paragraph(
            f"Automated OWASP Top 10:2025 Vulnerability Audit & Deliverable Report · {scan.get('name', 'Scan Session')}",
            styles["CoverSubtitle"],
        )
    )
    elements.append(Spacer(1, 8))
    elements.append(
        HRFlowable(
            width="100%",
            thickness=1.5,
            color=colors.HexColor("#059669"),
            spaceBefore=2,
            spaceAfter=12,
        )
    )

    # -------------------------------------------------------------------------
    # 2. Executive Summary & Posture Score Card
    # -------------------------------------------------------------------------
    elements.append(Paragraph("1. Executive Summary", styles["SectionHeading"]))

    score_box_data = [
        [
            Paragraph("<b>Security Posture Score</b>", styles["Body"]),
            Paragraph(
                f"<font size=16 color='#059669'><b>{score} / 100</b></font><br/>"
                f"<b>Grade:</b> {grade}",
                styles["Body"],
            ),
            Paragraph(
                f"<b>Total Vulnerabilities:</b> {len(findings)}<br/>"
                f"<b>Critical / High:</b> {by_severity.get('critical', 0)} / {by_severity.get('high', 0)}<br/>"
                f"<b>Assessment Mode:</b> Non-destructive, safe active probes",
                styles["Body"],
            ),
        ]
    ]

    score_table = Table(score_box_data, colWidths=[150, 160, 222])
    score_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    elements.append(score_table)
    elements.append(Spacer(1, 10))

    exec_text = (
        f"This security assessment was executed on <b>{snapshot.get('generated_at', 'N/A')[:19]} UTC</b> "
        f"against explicitly authorized targets under profile <b>{scan.get('profile', 'full')}</b>. "
        f"The evaluation analyzed web applications and APIs across the OWASP Top 10:2025 categories. "
        f"A total of <b>{len(findings)}</b> findings were detected across <b>{len(targets)}</b> verified target endpoints. "
        f"Remediation workflows, technical evidence, and fix verification instructions are documented below."
    )
    elements.append(Paragraph(exec_text, styles["Body"]))
    elements.append(Spacer(1, 12))

    # -------------------------------------------------------------------------
    # 3. Target and Scan Information
    # -------------------------------------------------------------------------
    elements.append(Paragraph("2. Scope & Target Specifications", styles["SectionHeading"]))

    target_rows = [
        [
            Paragraph("<b>Target URL</b>", styles["BodyBold"]),
            Paragraph("<b>Hostname / Port</b>", styles["BodyBold"]),
            Paragraph("<b>Authorization Ref</b>", styles["BodyBold"]),
            Paragraph("<b>Status</b>", styles["BodyBold"]),
        ]
    ]

    for t in targets:
        target_rows.append(
            [
                Paragraph(t.get("url", "N/A"), styles["CodeText"]),
                Paragraph(f"{t.get('hostname')}:{t.get('port') or 80}", styles["Body"]),
                Paragraph(t.get("authorization_reference") or "Explicit User Scope", styles["Body"]),
                Paragraph("Authorized In-Scope", styles["BodyBold"]),
            ]
        )

    if len(target_rows) == 1:
        target_rows.append(
            [
                Paragraph("No explicit targets recorded", styles["Body"]),
                Paragraph("-", styles["Body"]),
                Paragraph("-", styles["Body"]),
                Paragraph("-", styles["Body"]),
            ]
        )

    target_table = Table(target_rows, colWidths=[220, 110, 112, 90])
    target_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(target_table)
    elements.append(Spacer(1, 12))

    # -------------------------------------------------------------------------
    # 4. Vulnerability Statistics & OWASP Category Matrix
    # -------------------------------------------------------------------------
    elements.append(Paragraph("3. Vulnerability Distribution & OWASP Matrix", styles["SectionHeading"]))

    # Summary table: Severity counts & OWASP breakdown
    sev_rows = [
        [
            Paragraph("<b>Severity</b>", styles["BodyBold"]),
            Paragraph("<b>Count</b>", styles["BodyBold"]),
            Paragraph("<b>Risk Implication</b>", styles["BodyBold"]),
        ],
        [
            Paragraph("<font color='#be123c'><b>CRITICAL</b></font>", styles["Body"]),
            Paragraph(str(by_severity.get("critical", 0)), styles["BodyBold"]),
            Paragraph("Immediate remote exploitability, high impact on confidentiality/integrity", styles["Body"]),
        ],
        [
            Paragraph("<font color='#c2410c'><b>HIGH</b></font>", styles["Body"]),
            Paragraph(str(by_severity.get("high", 0)), styles["BodyBold"]),
            Paragraph("Privilege escalation, unauthorized data access, sensitive leaks", styles["Body"]),
        ],
        [
            Paragraph("<font color='#b45309'><b>MEDIUM</b></font>", styles["Body"]),
            Paragraph(str(by_severity.get("medium", 0)), styles["BodyBold"]),
            Paragraph("Security misconfiguration, permissive headers, defense-in-depth bypass", styles["Body"]),
        ],
        [
            Paragraph("<font color='#0369a1'><b>LOW / INFO</b></font>", styles["Body"]),
            Paragraph(str(by_severity.get("low", 0) + by_severity.get("info", 0)), styles["BodyBold"]),
            Paragraph("Informational indicators, verbose server headers, minor hygiene gaps", styles["Body"]),
        ],
    ]

    sev_table = Table(sev_rows, colWidths=[110, 60, 362])
    sev_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(sev_table)
    elements.append(Spacer(1, 10))

    # OWASP Top 10:2025 Coverage Grid
    owasp_defs = [
        ("A01:2025", "Broken Access Control", by_owasp.get("A01:2025", 0)),
        ("A02:2025", "Security Misconfiguration", by_owasp.get("A02:2025", 0)),
        ("A03:2025", "Software Supply Chain Failures", by_owasp.get("A03:2025", 0)),
        ("A04:2025", "Cryptographic Failures", by_owasp.get("A04:2025", 0)),
        ("A05:2025", "Injection", by_owasp.get("A05:2025", 0)),
        ("A06:2025", "Insecure Design", by_owasp.get("A06:2025", 0)),
        ("A07:2025", "Authentication Failures", by_owasp.get("A07:2025", 0)),
        ("A08:2025", "Software & Data Integrity", by_owasp.get("A08:2025", 0)),
        ("A09:2025", "Security Logging & Alerting", by_owasp.get("A09:2025", 0)),
        ("A10:2025", "Mishandling Exceptional Conditions", by_owasp.get("A10:2025", 0)),
    ]

    owasp_rows = [
        [
            Paragraph("<b>OWASP Category</b>", styles["BodyBold"]),
            Paragraph("<b>Category Name</b>", styles["BodyBold"]),
            Paragraph("<b>Findings Discovered</b>", styles["BodyBold"]),
            Paragraph("<b>Audit Status</b>", styles["BodyBold"]),
        ]
    ]

    for cat_id, name, cnt in owasp_defs:
        owasp_rows.append(
            [
                Paragraph(f"<b>{cat_id}</b>", styles["Body"]),
                Paragraph(name, styles["Body"]),
                Paragraph(str(cnt), styles["BodyBold"]),
                Paragraph("Evaluated (Safe Checks)", styles["Body"]),
            ]
        )

    owasp_table = Table(owasp_rows, colWidths=[90, 230, 112, 100])
    owasp_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    elements.append(owasp_table)
    elements.append(Spacer(1, 14))

    # -------------------------------------------------------------------------
    # 5. Individual Findings & Technical Evidence
    # -------------------------------------------------------------------------
    elements.append(Paragraph("4. Detailed Vulnerability Findings", styles["SectionHeading"]))

    if not findings:
        elements.append(
            Paragraph(
                "<i>No security findings were detected for this scan session. All evaluated categories satisfied safe baseline criteria.</i>",
                styles["Body"],
            )
        )
    else:
        for idx, f in enumerate(findings, start=1):
            sev = f.get("severity", "medium").upper()
            color = _get_severity_color(sev)

            finding_flowables: list[Any] = []

            # Finding Header Block
            hdr_data = [
                [
                    Paragraph(
                        f"<b>Finding #{idx}: {f.get('title', 'Vulnerability Finding')}</b>",
                        styles["BodyBold"],
                    ),
                    Paragraph(
                        f"<font color='{color.hexval()}'><b>{sev}</b></font> · "
                        f"Confidence: {f.get('confidence', 'firm').upper()}",
                        styles["BodyBold"],
                    ),
                ]
            ]
            hdr_table = Table(hdr_data, colWidths=[360, 172])
            hdr_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                        ("BOX", (0, 0), (-1, -1), 1, color),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            finding_flowables.append(hdr_table)

            # Metadata Table
            endpoint = f.get("endpoint")
            endpoint_str = f"{endpoint['method']} {endpoint['url']}" if endpoint else "Scan-wide assessment"
            meta_data = [
                [
                    Paragraph(f"<b>OWASP Category:</b> {f.get('owasp_category', 'N/A')}", styles["Body"]),
                    Paragraph(f"<b>Check ID:</b> {f.get('check_id', 'N/A')}", styles["Body"]),
                ],
                [
                    Paragraph(f"<b>Endpoint:</b> {endpoint_str}", styles["Body"]),
                    Paragraph(f"<b>Status:</b> {f.get('status', 'open').upper()}", styles["Body"]),
                ],
            ]
            meta_table = Table(meta_data, colWidths=[270, 262])
            meta_table.setStyle(
                TableStyle(
                    [
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            finding_flowables.append(meta_table)

            # Description
            finding_flowables.append(Spacer(1, 4))
            finding_flowables.append(Paragraph(f"<b>Description:</b> {f.get('description', '')}", styles["Body"]))

            # Evidence (Redacted)
            ev_list = f.get("evidence", [])
            if ev_list:
                finding_flowables.append(Spacer(1, 4))
                finding_flowables.append(Paragraph("<b>Technical Evidence (Redacted):</b>", styles["BodyBold"]))
                for ev in ev_list:
                    kind = ev.get("kind", "evidence").upper()
                    label = ev.get("label", "Technical Evidence")
                    raw_content = str(ev.get("content", ""))
                    # Truncate content in PDF if excessively long
                    if len(raw_content) > 350:
                        raw_content = raw_content[:350] + "... [truncated in PDF]"
                    sha = ev.get("content_sha256", "N/A")[:16]

                    ev_box = [
                        [
                            Paragraph(f"<b>{kind} - {label}</b> (SHA-256: {sha}...)<br/>"
                                      f"<font face='Courier' size=7>{raw_content}</font>", styles["Body"])
                        ]
                    ]
                    t_ev = Table(ev_box, colWidths=[532])
                    t_ev.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
                                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#94a3b8")),
                                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                                ("TOPPADDING", (0, 0), (-1, -1), 4),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ]
                        )
                    )
                    finding_flowables.append(t_ev)

            # Remediation Guidance
            rem = f.get("remediation")
            if rem:
                finding_flowables.append(Spacer(1, 4))
                rem_text = f"<b>Remediation Roadmap:</b> {rem.get('summary', 'Apply defensive validation and configurations.')}"
                finding_flowables.append(Paragraph(rem_text, styles["Body"]))
                steps = rem.get("steps", [])
                if steps:
                    step_items = "<br/>".join([f"• {s}" for s in steps[:3]])
                    finding_flowables.append(Paragraph(step_items, styles["Body"]))

            # Fix Verification History
            v_runs = f.get("verification_runs", [])
            if v_runs:
                finding_flowables.append(Spacer(1, 4))
                finding_flowables.append(Paragraph("<b>Fix Verification History:</b>", styles["BodyBold"]))
                v_rows = [
                    [
                        Paragraph("<b>Run ID</b>", styles["BodyBold"]),
                        Paragraph("<b>Verification Status</b>", styles["BodyBold"]),
                        Paragraph("<b>Outcome Summary</b>", styles["BodyBold"]),
                        Paragraph("<b>Verified At</b>", styles["BodyBold"]),
                    ]
                ]
                for run in v_runs[:3]:
                    st = run.get("status", "pending").upper()
                    st_col = "#059669" if st in ("FIXED", "PASSED") else "#be123c"
                    v_rows.append(
                        [
                            Paragraph(str(run.get("id", ""))[:8], styles["CodeText"]),
                            Paragraph(f"<font color='{st_col}'><b>{st}</b></font>", styles["Body"]),
                            Paragraph(run.get("result_summary") or "Safe re-probe executed", styles["Body"]),
                            Paragraph(str(run.get("created_at", ""))[:16], styles["Body"]),
                        ]
                    )
                v_table = Table(v_rows, colWidths=[70, 110, 242, 110])
                v_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                            ("TOPPADDING", (0, 0), (-1, -1), 2),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                            ("LEFTPADDING", (0, 0), (-1, -1), 4),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ]
                    )
                )
                finding_flowables.append(v_table)

            finding_flowables.append(Spacer(1, 12))
            elements.append(KeepTogether(finding_flowables))

    # -------------------------------------------------------------------------
    # 6. Limitations and Assessment Disclaimers
    # -------------------------------------------------------------------------
    elements.append(KeepTogether([
        Paragraph("5. Limitations & Assessment Disclaimers", styles["SectionHeading"]),
        Paragraph(
            "<b>1. Point-in-Time Assessment:</b> This deliverable reflects the security state of the target "
            "at the exact timestamp of execution. Subsequent deployments, routing changes, or third-party dependency updates "
            "may introduce new vulnerabilities not recorded in this report.<br/>"
            "<b>2. Safe Non-Destructive Methodology:</b> VulnSight strictly enforces non-destructive probing methods. "
            "Denial-of-service, persistent data tampering, and dangerous exploitation techniques are deliberately avoided. "
            "Complex flaws requiring authentic multi-step business logic or deep internal source code review may require supplemental manual review.<br/>"
            "<b>3. Evidence Redaction & Data Protection:</b> All captured HTTP request/response evidence undergoes automated "
            "sanitization and redaction to eliminate passwords, API tokens, session credentials, and personally identifiable information (PII).<br/>"
            "<b>4. Legal & Authorization Boundary:</b> This assessment was conducted exclusively against targets authorized in writing. "
            "Redistribution or use of findings outside authorized organizational personnel is prohibited.",
            styles["Disclaimer"],
        ),
    ]))

    # Build PDF with dynamic 2-pass running canvas
    doc.build(elements, canvasmaker=NumberedCanvas)
    return buffer.getvalue()

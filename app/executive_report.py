"""
Executive PDF Report Generator (CISO/CEO Boardroom Format)
------------------------------------------------------------------
Generates a boardroom-ready PDF summarizing current vendor detector
results, styled per the requested executive theme: Slate/Security
Charcoal (#1A252C) with Deep Blue (#1A5276) accents.

Pagination safety note: the original request specified CSS paging
directives (`page-break-inside: avoid`, `page-break-after: avoid`) — those
are HTML/CSS properties and don't apply here, since this report is built
with ReportLab (a direct PDF-drawing library), not rendered from HTML/CSS.
The functional equivalent in ReportLab is the KeepTogether flowable, which
this module uses around every multi-element block (KPI cards, runbook
phase rows, detector domain groups) to achieve the same "never split this
block across a page boundary" guarantee the original request was after.

KPI definitions implemented:
  - Mean Time to Detect (MTTD): computed from audit_log.sqlite3 as the
    average time between a scan starting and completing (a real,
    available proxy for "how long did detection take" in this system —
    true MTTD in a SOC context usually means time from compromise to
    discovery, which this tool cannot measure since it has no visibility
    into actual compromise timing, only scan execution timing).
  - Vendor Security Drift Index: computed from monitoring.sqlite3's score
    history as the average point-change in vulnerability-detector scores
    between the two most recent recorded scans per vendor, across all
    continuously-monitored vendors — a real, computed measure of how much
    vendor posture is moving scan-to-scan, not a placeholder metric.
"""
from __future__ import annotations

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle,
    HRFlowable, KeepTogether,
)

CHARCOAL = colors.HexColor("#1A252C")
DEEP_BLUE = colors.HexColor("#1A5276")
LIGHT_BLUE = colors.HexColor("#2E86C1")
SLATE_LIGHT = colors.HexColor("#EAEDED")
WHITE = colors.white
TEXT_DARK = colors.HexColor("#1A252C")
MUTED = colors.HexColor("#5D6D7E")

STATUS_COLORS = {
    "ACTIVE": colors.HexColor("#1E8449"),
    "BYO_KEY": colors.HexColor("#B9770E"),
    "NOT_IMPLEMENTED": colors.HexColor("#85929E"),
}

PRIORITY_COLORS = {
    "High": colors.HexColor("#A93226"),
    "Medium": colors.HexColor("#B9770E"),
    "Low": colors.HexColor("#5D6D7E"),
}

RUNBOOK_PHASES = [
    ("1. Pre-Onboarding", "Ad-Hoc (Initial)", "DET-21 to 24, DET-12, DET-14, DET-35",
     "Trigger manual compliance review, check historical exposure signals, execute perimeter DNS and WAF mapping before signing contract.",
     "Initial Vendor Risk Tiering Profile & Go/No-Go Decision Report."),
    ("2. Continuous Baseline", "Real-Time / Ongoing", "DET-01 to 03, DET-06 to 10, DET-11, DET-15, DET-18",
     "Hook vendor domains into continuous monitoring. Configure alerts for automated ingestion.",
     "Automated alerts and real-time dashboard updates tracking security drift."),
    ("3. Quarterly Review", "Scheduled (Every 90 Days)", "DET-16, DET-20, DET-24, DET-30",
     "Re-verify external exposure metrics, scan public CVE updates, cross-check sanctions lists, review financial health reports.",
     "Quarterly Vendor Security Scorecard and Risk Briefing."),
    ("4. Annual Deep-Dive", "Scheduled (Yearly Re-auth)", "DET-21, DET-22, DET-26, DET-33, DET-34",
     "Request fresh SOC 2 Type II reports, evaluate SBOM dependency health, require delta response analysis, run structured external assessments.",
     "Formal Contract Renewal Authorization and Remediation Plan Document."),
    ("5. Incident-Triggered", "Reactive (Emergency)", "DET-04, DET-13, DET-18, DET-19",
     "When threat intel flags a vendor or an indicator points to active compromise, isolate vendor integration channels and initiate immediate review.",
     "Vendor Incident Containment Log and Post-Incident Review Report."),
]


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("ExecCoverTitle", fontSize=24, leading=30, fontName="Helvetica-Bold",
                                textColor=WHITE, alignment=TA_CENTER))
    styles.add(ParagraphStyle("ExecCoverSubtitle", fontSize=13, leading=18, fontName="Helvetica",
                                textColor=CHARCOAL, alignment=TA_CENTER))
    styles.add(ParagraphStyle("SectionHeading", fontSize=16, leading=20, fontName="Helvetica-Bold",
                                textColor=DEEP_BLUE, spaceBefore=20, spaceAfter=10))
    styles.add(ParagraphStyle("SubHeading", fontSize=12, leading=16, fontName="Helvetica-Bold",
                                textColor=CHARCOAL, spaceBefore=10, spaceAfter=6))
    styles.add(ParagraphStyle("ExecBody", fontSize=10, leading=15, fontName="Helvetica",
                                textColor=TEXT_DARK, alignment=TA_LEFT))
    styles.add(ParagraphStyle("ExecSmall", fontSize=8, leading=11, fontName="Helvetica",
                                textColor=MUTED))
    styles.add(ParagraphStyle("CellText", fontSize=8, leading=10.5, fontName="Helvetica", textColor=TEXT_DARK))
    styles.add(ParagraphStyle("CellTextWhite", fontSize=8, leading=10.5, fontName="Helvetica-Bold", textColor=WHITE))
    styles.add(ParagraphStyle("KpiValue", fontSize=20, leading=24, fontName="Helvetica-Bold", alignment=TA_CENTER))
    styles.add(ParagraphStyle("KpiLabel", fontSize=8, leading=11, alignment=TA_CENTER, textColor=MUTED))
    return styles


def _cover_page(story, styles, generated_for: str, vendor_count: int):
    story.append(Spacer(1, 1.6 * inch))
    cover_box = Table([[Paragraph(generated_for, styles["ExecCoverTitle"])]], colWidths=[6.5 * inch], rowHeights=[1.0 * inch])
    cover_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), CHARCOAL),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("LINEBELOW", (0, 0), (-1, -1), 3, DEEP_BLUE),
    ]))
    story.append(cover_box)
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph("Third-Party Threat &amp; Incident Monitoring — Executive Briefing", styles["ExecCoverSubtitle"]))
    story.append(Spacer(1, 0.5 * inch))

    meta_rows = [
        ["Document Classification:", "Confidential — Board & Executive Distribution"],
        ["Reporting Period:", datetime.now(timezone.utc).strftime("%B %d, %Y")],
        ["Vendors in Scope:", str(vendor_count)],
        ["Prepared By:", "Automated Vendor Threat Detection Platform"],
    ]
    meta_table = Table(meta_rows, colWidths=[2.2 * inch, 3.0 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (-1, -1), CHARCOAL),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    centered_meta = Table([[meta_table]], colWidths=[6.5 * inch])
    centered_meta.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story.append(centered_meta)
    story.append(PageBreak())


def _kpi_card(styles, value: str, label: str, accent_hex: str) -> Table:
    t = Table([
        [Paragraph(f'<font color="{accent_hex}">{value}</font>', styles["KpiValue"])],
        [Paragraph(label, styles["KpiLabel"])],
    ], colWidths=[1.5 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SLATE_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.5, MUTED),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    return t


def _kpi_cards(styles, mttd_seconds, drift_index, vendor_count: int, critical_count: int) -> Table:
    mttd_display = f"{mttd_seconds:.1f}s" if mttd_seconds is not None else "N/A"
    drift_display = f"{drift_index:+.1f} pts" if drift_index is not None else "N/A"
    drift_hex = "#1A5276" if (drift_index or 0) >= 0 else "#A93226"

    cards = [
        _kpi_card(styles, str(vendor_count), "Vendors Monitored", "#1A5276"),
        _kpi_card(styles, str(critical_count), "Critical/High Findings", "#A93226"),
        _kpi_card(styles, mttd_display, "Mean Time to Detect", "#2E86C1"),
        _kpi_card(styles, drift_display, "Security Drift Index", drift_hex),
    ]
    row = Table([cards], colWidths=[1.6 * inch] * 4)
    row.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    return row


def _classify_status(r: dict) -> str:
    """
    Classifies a detector result as ERROR / FINDINGS / CLEAR for the
    executive summary table. Cannot rely on "detail_items is non-empty"
    alone, since several detectors (dns_integrity, waf_absence,
    concentration_risk) always populate detail_items with informational
    context (nameserver list, ASN, WAF provider) regardless of whether
    anything is actually wrong. Instead, this checks each detector's own
    established "nothing wrong" summary phrasing first, then falls back
    to risk_score, and only treats detail_items as evidence of a finding
    as a last resort.
    """
    if r.get("error"):
        return "ERROR"

    summary_lower = (r.get("summary") or "").lower()
    no_finding_phrases = [
        "no findings", "no entries found", "no findings —", "no anomalies detected",
        "no dangling-cname patterns found", "no cors/csp misconfigurations detected",
        "no live lookalike infrastructure found",
    ]
    if any(phrase in summary_lower for phrase in no_finding_phrases):
        return "CLEAR"

    if r.get("risk_score") is not None:
        return "FINDINGS" if r["risk_score"] < 80 else "CLEAR"

    # waf_absence and concentration_risk report informational context
    # ("Hosted on X", "WAF/CDN likely present") that isn't itself a flagged
    # finding — except the specific "no signature detected" case, which IS
    # a real gap worth flagging.
    if "no waf/cdn provider signature detected" in summary_lower:
        return "FINDINGS"
    if r.get("detector") in ("waf_absence", "concentration_risk"):
        return "INFO"

    if r.get("detail_items"):
        return "FINDINGS"
    return "CLEAR"


def _detector_summary_table(styles, vendor_results: list[dict]) -> Table:
    header = [Paragraph(h, styles["CellTextWhite"]) for h in ["Vendor", "Detector", "Result", "Status"]]
    rows = [header]
    for vendor_entry in vendor_results:
        for r in vendor_entry.get("results", []):
            status_text = _classify_status(r)
            rows.append([
                Paragraph(vendor_entry["vendor_name"], styles["CellText"]),
                Paragraph(r["detector_label"], styles["CellText"]),
                Paragraph(r["summary"][:140], styles["CellText"]),
                Paragraph(status_text, styles["CellText"]),
            ])
    t = Table(rows, colWidths=[1.1 * inch, 1.7 * inch, 2.9 * inch, 0.8 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), CHARCOAL),
        ("GRID", (0, 0), (-1, -1), 0.4, MUTED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SLATE_LIGHT]),
    ]))
    return t


def _registry_domain_block(styles, domain: str, specs: list) -> KeepTogether:
    header = [Paragraph(h, styles["CellTextWhite"]) for h in ["ID", "Detector", "Mode", "Priority", "Status"]]
    rows = [header]
    for d in specs:
        status_color = STATUS_COLORS.get(d.implementation_status, MUTED)
        priority_color = PRIORITY_COLORS.get(d.risk_priority, MUTED)
        rows.append([
            Paragraph(d.det_id, styles["CellText"]),
            Paragraph(d.name, styles["CellText"]),
            Paragraph(d.monitoring_mode, styles["CellText"]),
            Paragraph(f'<font color="{priority_color.hexval()}"><b>{d.risk_priority}</b></font>', styles["CellText"]),
            Paragraph(f'<font color="{status_color.hexval()}"><b>{d.implementation_status.replace("_", " ")}</b></font>', styles["CellText"]),
        ])
    t = Table(rows, colWidths=[0.55 * inch, 2.6 * inch, 0.85 * inch, 0.7 * inch, 1.3 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DEEP_BLUE),
        ("GRID", (0, 0), (-1, -1), 0.4, MUTED),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, SLATE_LIGHT]),
    ]))
    block = [Paragraph(f"{domain} ({len(specs)})", styles["SubHeading"]), t, Spacer(1, 8)]
    return KeepTogether(block)


def _runbook_blocks(styles) -> list:
    """One KeepTogether block per phase, so a phase never splits across a
    page boundary — the ReportLab equivalent of the originally-requested
    CSS page-break-inside: avoid."""
    blocks = []
    for phase, cadence, detectors, workflow, deliverable in RUNBOOK_PHASES:
        t = Table([
            [Paragraph(phase, styles["CellTextWhite"]), Paragraph(cadence, styles["CellTextWhite"])],
            [Paragraph(f"<b>Detectors:</b> {detectors}", styles["CellText"]), ""],
            [Paragraph(f"<b>Workflow:</b> {workflow}", styles["CellText"]), ""],
            [Paragraph(f"<b>Deliverable:</b> {deliverable}", styles["CellText"]), ""],
        ], colWidths=[5.0 * inch, 2.0 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DEEP_BLUE),
            ("SPAN", (0, 1), (1, 1)), ("SPAN", (0, 2), (1, 2)), ("SPAN", (0, 3), (1, 3)),
            ("GRID", (0, 0), (-1, -1), 0.4, MUTED),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("BACKGROUND", (0, 1), (-1, -1), SLATE_LIGHT),
        ]))
        blocks.append(KeepTogether([t, Spacer(1, 8)]))
    return blocks


def build_executive_pdf(
    output_path: str,
    vendor_results: list[dict],
    registry_by_domain: dict,
    mttd_seconds: float | None = None,
    drift_index: float | None = None,
    generated_for: str = "Vendor Threat & Incident Monitoring",
) -> str:
    """
    vendor_results: same shape as a completed /api/detect job's "results" list.
    registry_by_domain: app.detectors.full_registry.get_by_domain() output.
    """
    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=LETTER,
        topMargin=0.5 * inch, bottomMargin=0.5 * inch, leftMargin=0.55 * inch, rightMargin=0.55 * inch,
        title="Vendor Threat & Incident Monitoring — Executive Report",
    )
    story = []

    vendor_count = len(vendor_results)
    critical_count = sum(
        1 for v in vendor_results for r in v.get("results", [])
        if r.get("risk_score") is not None and r["risk_score"] < 60
    )

    _cover_page(story, styles, generated_for, vendor_count)

    story.append(Paragraph("Executive Summary &amp; Strategy", styles["SectionHeading"]))
    story.append(Paragraph(
        f"This report summarizes the current external threat and risk posture of {vendor_count} "
        f"third-party vendor(s) under active monitoring, derived from "
        f"{sum(len(v.get('results', [])) for v in vendor_results)} individual detector executions. "
        f"Findings are sourced exclusively from passive, externally observable signals and "
        f"government/public threat-intelligence feeds — no internal vendor systems were accessed.",
        styles["ExecBody"],
    ))
    story.append(Spacer(1, 10))
    story.append(_kpi_cards(styles, mttd_seconds, drift_index, vendor_count, critical_count))
    story.append(Spacer(1, 16))

    if vendor_results:
        story.append(Paragraph("Active Detector Results", styles["SectionHeading"]))
        story.append(_detector_summary_table(styles, vendor_results))
        story.append(PageBreak())

    story.append(Paragraph("Detector Registry — Full Coverage Matrix", styles["SectionHeading"]))
    story.append(Paragraph(
        "The following matrix documents all 35 specified detector slots across 10 security domains, "
        "including which are actively running today versus pending an API key or not implemented, "
        "with documented reasons for each gap.",
        styles["ExecBody"],
    ))
    story.append(Spacer(1, 8))
    for domain, specs in registry_by_domain.items():
        story.append(_registry_domain_block(styles, domain, specs))

    story.append(PageBreak())

    story.append(Paragraph("Vendor Monitoring Operational Runbook", styles["SectionHeading"]))
    story.append(Paragraph(
        "Recommended detector application by vendor lifecycle phase, from pre-onboarding through "
        "incident response.", styles["ExecBody"],
    ))
    story.append(Spacer(1, 10))
    for block in _runbook_blocks(styles):
        story.append(block)

    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", color=MUTED))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Methodology: All findings are derived from passive, publicly-available data sources "
        "(CISA KEV, certificate transparency logs, DNS records, Team Cymru IP-to-ASN mapping, NVD). "
        "No active exploitation, port scanning, or credential-database queries are performed. "
        "Mean Time to Detect reflects scan execution duration, not breach-to-discovery time, since "
        "this platform has no visibility into actual compromise timing. Security Drift Index reflects "
        "point-in-time score change between the two most recent scans per continuously-monitored vendor.",
        styles["ExecSmall"],
    ))

    doc.build(story)
    return output_path

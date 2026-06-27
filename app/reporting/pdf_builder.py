"""
Reporting Engine
-------------------
Builds a dynamic PDF report using ReportLab Platypus:
  - Cover + Executive Summary with score distribution chart
  - Per-vendor breakdown: name, website, score, tier, AI/rule-based narrative
  - Compliance mapping matrix: NIST / ISO 27001 / DORA / GDPR per finding
  - Risk tier color-coding throughout
"""
from __future__ import annotations

import io
import re
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, CondPageBreak, Table, TableStyle,
    HRFlowable, KeepTogether,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie

TIER_COLORS = {
    "Critical Impact": colors.HexColor("#B91C1C"),
    "High Impact": colors.HexColor("#EA580C"),
    "Medium Impact": colors.HexColor("#CA8A04"),
    "Low Impact": colors.HexColor("#16A34A"),
    "Informational": colors.HexColor("#2563EB"),
}

SEVERITY_COLORS = {
    "critical": colors.HexColor("#B91C1C"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#65A30D"),
    "info": colors.HexColor("#2563EB"),
}


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=24, spaceAfter=6))
    styles.add(ParagraphStyle("ReportSubtitle", parent=styles["Normal"], fontSize=11, textColor=colors.grey, alignment=TA_CENTER))
    styles.add(ParagraphStyle("SectionHeading", parent=styles["Heading1"], fontSize=16, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#1E293B")))
    styles.add(ParagraphStyle("VendorHeading", parent=styles["Heading2"], fontSize=14, spaceBefore=14, spaceAfter=4, textColor=colors.HexColor("#0F172A")))
    styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=9.5, leading=14))
    styles.add(ParagraphStyle("Small", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.grey))
    return styles


def _score_distribution_chart(vendor_results: list[dict]) -> Drawing:
    drawing = Drawing(270, 220)
    chart = VerticalBarChart()
    chart.x = 45
    chart.y = 55
    chart.height = 130
    chart.width = 210
    # Truncate to 9 chars + ellipsis (was 12 chars with no ellipsis) — at
    # this chart width, labels longer than ~9 chars collide with their
    # neighbors when angled, since bar spacing is fixed by chart.width
    # divided by vendor count and does not grow with label length.
    names = [(v["name"][:9] + "…") if len(v["name"]) > 9 else v["name"] for v in vendor_results]
    scores = [v["score"] for v in vendor_results]
    chart.data = [scores]
    chart.categoryAxis.categoryNames = names
    # Steeper angle (45 vs 30) trades horizontal spread for vertical, which
    # is the actual constraint here — horizontal space per label shrinks as
    # vendor count grows, but vertical space below the axis does not.
    chart.categoryAxis.labels.angle = 45
    chart.categoryAxis.labels.dy = -8
    chart.categoryAxis.labels.dx = -4
    chart.categoryAxis.labels.fontSize = 7
    chart.categoryAxis.labels.boxAnchor = "ne"
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = 100
    chart.valueAxis.valueStep = 20
    chart.bars[0].fillColor = colors.HexColor("#2563EB")
    # Add visible gaps between bars so adjacent angled labels don't read as
    # touching even when names are similar lengths.
    chart.barSpacing = 4
    chart.groupSpacing = 8
    for i, v in enumerate(vendor_results):
        tier_color = TIER_COLORS.get(v["tier"], colors.grey)
        chart.bars[(0, i)].fillColor = tier_color
    drawing.add(chart)
    return drawing


def _tier_pie_chart(vendor_results: list[dict]) -> Drawing:
    tier_counts: dict[str, int] = {}
    for v in vendor_results:
        tier_counts[v["tier"]] = tier_counts.get(v["tier"], 0) + 1
    drawing = Drawing(220, 200)
    pie = Pie()
    pie.x = 30
    pie.y = 50
    pie.width = 110
    pie.height = 110
    pie.data = list(tier_counts.values())
    pie.labels = None
    pie.slices.strokeWidth = 0.5
    for i, tier_name in enumerate(tier_counts.keys()):
        pie.slices[i].fillColor = TIER_COLORS.get(tier_name, colors.grey)
    drawing.add(pie)
    return drawing


def _tier_legend_table(vendor_results: list[dict], styles) -> Table:
    tier_counts: dict[str, int] = {}
    for v in vendor_results:
        tier_counts[v["tier"]] = tier_counts.get(v["tier"], 0) + 1
    rows = []
    for tier_name, count in tier_counts.items():
        color = TIER_COLORS.get(tier_name, colors.grey)
        rows.append([
            Table([[""]], colWidths=[10], rowHeights=[10],
                  style=TableStyle([("BACKGROUND", (0, 0), (0, 0), color)])),
            Paragraph(f"{tier_name} ({count})", styles["Small"]),
        ])
    t = Table(rows, colWidths=[16, 200])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _tier_badge(tier_label: str, score: int, styles) -> Table:
    color = TIER_COLORS.get(tier_label, colors.grey)
    t = Table([[f"{score}/100", tier_label]], colWidths=[60, 280])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), color),
        ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("FONTNAME", (0, 0), (0, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F1F5F9")),
        ("TEXTCOLOR", (1, 0), (1, 0), color),
        ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
        ("LEFTPADDING", (1, 0), (1, 0), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


# Soft-hyphenation points (U+00AD) for the specific long words that appear
# in this codebase's compliance citation text (NIST/ISO/DORA/GDPR phrases
# in compliance/engine.py). A soft hyphen is invisible unless the layout
# engine actually needs to break the line there, in which case it renders
# as a normal hyphen at a real syllable boundary — e.g. "confidenti-
# ality" instead of an arbitrary "confi/dentiality" or "MEDI/UM" break.
# This is a small, deliberately hardcoded set (not a general hyphenation
# library) because the input is a known, bounded vocabulary of citation
# text, not arbitrary user content — pulling in a hyphenation dependency
# for ~15 fixed words would be more machinery than the problem warrants.
_SOFT_HYPHENS = {
    "confidentiality": "confi\u00adden\u00adti\u00adal\u00adi\u00adty",
    "authentication": "au\u00adthen\u00adti\u00adca\u00adtion",
    "availability": "avail\u00ada\u00adbil\u00adi\u00adty",
    "concentration": "con\u00adcen\u00adtra\u00adtion",
    "configuration": "con\u00adfig\u00adu\u00ada\u00adtion",
    "cryptographic": "cryp\u00adto\u00adgraph\u00adic",
    "cryptography": "cryp\u00adtog\u00adra\u00adphy",
    "decommission": "de\u00adcom\u00admis\u00adsion",
    "establishment": "es\u00adtab\u00adlish\u00adment",
    "firmware": "firm\u00adware",
    "recommendation": "rec\u00adom\u00admen\u00addation",
    "relationships": "re\u00adla\u00adtion\u00adships",
    "requirements": "re\u00adquire\u00adments",
    "transmission": "trans\u00admis\u00adsion",
    "transparency": "trans\u00adpar\u00aden\u00adcy",
    "vulnerabilities": "vul\u00adner\u00ada\u00adbil\u00adi\u00adties",
    "vulnerability": "vul\u00adner\u00ada\u00adbil\u00adi\u00adty",
}


def _hyphenate(text: str) -> str:
    """Replaces any whole-word match (case-insensitive) of a known long
    word with its soft-hyphenated form, leaving everything else
    (capitalization, surrounding punctuation, unrelated text) untouched."""
    def _replace(match: "re.Match") -> str:
        word = match.group(0)
        hyphenated = _SOFT_HYPHENS[word.lower()]
        return hyphenated.upper() if word.isupper() else hyphenated
    pattern = r"\b(" + "|".join(re.escape(w) for w in _SOFT_HYPHENS) + r")\b"
    return re.sub(pattern, _replace, text, flags=re.IGNORECASE)


def _findings_matrix(findings: list, styles) -> Table:
    header = ["Finding", "Sev.", "NIST", "ISO 27001", "DORA", "GDPR"]
    rows = [header]
    for f in findings:
        rows.append([
            Paragraph(_hyphenate(f.finding), styles["Small"]),
            Paragraph(f.severity.upper(), styles["Small"]),
            Paragraph(_hyphenate("<br/>".join(f.nist)) or "—", styles["Small"]),
            Paragraph(_hyphenate("<br/>".join(f.iso27001)) or "—", styles["Small"]),
            Paragraph(_hyphenate("<br/>".join(f.dora)) or "—", styles["Small"]),
            Paragraph(_hyphenate("<br/>".join(f.gdpr)) or "—", styles["Small"]),
        ])
    if len(rows) == 1:
        rows.append([Paragraph("No findings.", styles["Small"])] + ["—"] * 5)

    # Column widths total 525pt (the full usable LETTER-page width after
    # 0.6in margins). Sev. is 50pt specifically because "MEDIUM" at this
    # table's 8pt font plus default 6pt left/right cell padding measures
    # ~44.5pt — 42pt (an earlier attempt at rebalancing) was just under
    # that and still wrapped mid-word ("MEDIU/M"); 50pt gives real headroom.
    # GDPR and ISO 27001 get the largest remaining share since their
    # citation text includes the longest parenthetical phrases (e.g.
    # "(ongoing confidentiality/integrity)").
    t = Table(rows, colWidths=[122, 50, 68, 90, 65, 80], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        # VALIGN changed from TOP to MIDDLE: when one cell in a row wraps
        # to 3-4 lines (e.g. a long NIST/ISO control list) while a sibling
        # cell is a single short word ("HIGH"), top-aligning left the short
        # cell's text stranded at the top of a much taller row with a big
        # empty gap beneath it. Middle-aligning centers every cell's content
        # within the row's actual (tallest-cell-driven) height instead.
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
    ]
    for i, f in enumerate(findings, start=1):
        sev_color = SEVERITY_COLORS.get(f.severity, colors.black)
        style_cmds.append(("TEXTCOLOR", (1, i), (1, i), sev_color))
        style_cmds.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    return t


def build_pdf_report(
    vendor_reports: list[dict],
    output_path: str,
    generated_for: str = "Third-Party Vendor Risk Assessment",
) -> str:
    """
    vendor_reports: list of dicts with keys:
        name, website, domain, score, tier, narrative, findings (list of ComplianceFinding)
    """
    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=LETTER,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        title="Third-Party Vendor Risk Assessment Report",
    )
    story = []

    # --- Cover / Title ---
    story.append(Spacer(1, 60))
    story.append(Paragraph(generated_for, styles["ReportTitle"]))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%B %d, %Y at %H:%M UTC')}",
        styles["ReportSubtitle"],
    ))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Scope: external, passive OSINT-based security posture assessment. "
        "Mapped against NIST SP 800-53 / CSF, ISO/IEC 27001:2022 Annex A, "
        "DORA (EU 2022/2554) Articles 28-30, and GDPR Articles 28/32/44-49.",
        styles["ReportSubtitle"],
    ))
    story.append(Spacer(1, 30))

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
    summary_results = [{"name": v["name"], "score": v["score"], "tier": v["tier"]} for v in vendor_reports]
    avg_score = round(sum(v["score"] for v in summary_results) / len(summary_results)) if summary_results else 0
    story.append(Paragraph(
        f"This report assesses <b>{len(vendor_reports)}</b> vendor(s). "
        f"Average external risk score: <b>{avg_score}/100</b>.",
        styles["Body"],
    ))
    story.append(Spacer(1, 10))

    chart_table = Table(
        [[_score_distribution_chart(summary_results), _tier_pie_chart(summary_results), _tier_legend_table(summary_results, styles)]],
        colWidths=[280, 130, 140],
    )
    chart_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(chart_table)
    story.append(Spacer(1, 10))

    # Summary table of all vendors. Cell content MUST be wrapped in Paragraph
    # objects, not raw strings — ReportLab only wraps Paragraph/Flowable
    # content to the column width; a plain string is measured at its natural
    # width and can visually overflow into the next cell (this was the cause
    # of vendor-name text running into the website column with no space).
    summary_cell_style = ParagraphStyle("SummaryCell", parent=styles["Normal"], fontSize=9, leading=11)
    summary_header_style = ParagraphStyle("SummaryHeader", parent=styles["Normal"], fontSize=9, leading=11, textColor=colors.white, fontName="Helvetica-Bold")

    summary_header = [Paragraph(h, summary_header_style) for h in ["Vendor", "Website", "Score", "Risk Tier"]]
    summary_rows = [summary_header]
    for v in vendor_reports:
        tier_color = TIER_COLORS.get(v["tier"], colors.black)
        tier_style = ParagraphStyle(
            f"TierCell_{v['tier'].replace(' ', '_')}", parent=summary_cell_style,
            textColor=tier_color, fontName="Helvetica-Bold",
        )
        summary_rows.append([
            Paragraph(v["name"], summary_cell_style),
            Paragraph(v["website"], summary_cell_style),
            Paragraph(f"{v['score']}/100", summary_cell_style),
            Paragraph(v["tier"], tier_style),
        ])
    # Widened vendor/website columns (was 120/170) since real vendor names
    # and full https:// URLs routinely exceed those widths; total still
    # fits LETTER page width within the 0.6in margins set on the document.
    summary_table = Table(summary_rows, colWidths=[145, 195, 55, 95], repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]
    summary_table.setStyle(TableStyle(style_cmds))
    story.append(summary_table)
    # Conditional, not unconditional: for a short report (1-2 vendors) the
    # summary table ends well up the page, and forcing PageBreak() here
    # left "Per-Vendor Breakdown" stranded at the top of an otherwise mostly
    # blank page 2 — the same gap pattern fixed below for the Methodology
    # section. CondPageBreak only jumps to a new page if the heading plus a
    # reasonable amount of body content genuinely wouldn't fit.
    story.append(CondPageBreak(3 * inch))

    # --- Per-vendor breakdown ---
    story.append(Paragraph("Per-Vendor Breakdown", styles["SectionHeading"]))
    for v in vendor_reports:
        block = [
            Paragraph(v["name"], styles["VendorHeading"]),
            Paragraph(f'<link href="{v["website"]}">{v["website"]}</link>', styles["Small"]),
            Spacer(1, 6),
            _tier_badge(v["tier"], v["score"], styles),
            Spacer(1, 8),
            Paragraph(v["narrative"], styles["Body"]),
            Spacer(1, 10),
            Paragraph("Compliance Mapping Matrix", ParagraphStyle("sub", parent=styles["Normal"], fontSize=10, fontName="Helvetica-Bold", spaceBefore=4, spaceAfter=4)),
            _findings_matrix(v["findings"], styles),
            Spacer(1, 4),
            HRFlowable(width="100%", color=colors.HexColor("#E2E8F0")),
        ]
        story.append(KeepTogether(block[:5]))
        story.append(block[5])
        story.append(block[6])
        story.append(block[7])
        story.append(block[8])
        story.append(Spacer(1, 16))

    # --- Methodology / disclaimer footer ---
    # Previously this always started with PageBreak(), which forced a fresh
    # page even when the per-vendor section ended with most of a page still
    # blank (e.g. a single-vendor report) — exactly the "huge gap after each
    # section" symptom. CondPageBreak only breaks if the upcoming content
    # genuinely won't fit in the remaining space on the current page, so a
    # short report's methodology section flows directly below the last
    # vendor block instead of jumping to a near-empty new page.
    story.append(CondPageBreak(2.2 * inch))
    story.append(Paragraph("Methodology & Limitations", styles["SectionHeading"]))
    story.append(Paragraph(
        "Scores are derived from a deterministic deduction model starting at 100 points, with "
        "deductions applied per finding based on pre-calibrated severity weights. This is an "
        "external, passive assessment only — it does not include internal network access, "
        "credentialed scanning, social engineering testing, or physical security review. CVE "
        "lookups are best-effort keyword matches against public NVD data and may include false "
        "positives or omissions. Scores reflect a point-in-time snapshot of public-facing posture "
        "and should be supplemented with vendor questionnaires, SOC 2/ISO certificates, and "
        "contractual due diligence per DORA Art. 28(4) and equivalent requirements before final "
        "risk decisions.",
        styles["Body"],
    ))
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "Risk Tier Thresholds: Critical Impact (0-9) · High Impact (10-29) · Medium Impact "
        "(30-59) · Low Impact (60-99) · Informational (100).",
        styles["Small"],
    ))

    doc.build(story)
    return output_path

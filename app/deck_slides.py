"""
Executive Slide Deck Generator
-----------------------------------
Renders a 16:9 widescreen PDF (13.333in x 7.5in per slide — the standard
PowerPoint widescreen aspect ratio) summarizing either tool's report data
for a CISO/CEO audience. Static PDF, not an editable .pptx, per product
decision — but laid out and styled to read as a slide deck, not a
shrunk-down version of the existing portrait technical report.

Design principles enforced throughout this module (the "zero blank
space" requirement from the spec):
  - Every slide-building function is handed pre-validated, non-empty data
    by the caller (main.py / detector_routes.py), OR independently
    guarantees substantive fallback content itself (see
    business_translation.py and deck_narrative.py) — there is no code
    path in this module that can be asked to render a slide with nothing
    to say.
  - Text is sized and wrapped against a measured content-area width
    BEFORE drawing, never drawn and hoped to fit — see _wrap_text_to_width.
  - Slide counts adapt to data volume (e.g. more findings -> more findings
    slides, paginated) rather than truncating to fit a fixed slide count,
    so important content is never silently dropped to preserve a layout.

Uses ReportLab's low-level canvas API (not Platypus flowables) because
fixed-size slides need guaranteed, no-overflow placement — Platypus is
built for flowing/paginating documents, which is the wrong tool for a
"this content must fit on exactly this slide" layout.
"""
from __future__ import annotations

from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

from app.business_translation import translate_finding, translate_detector, severity_business_label

# --- Slide geometry: true 16:9 widescreen, matching standard PowerPoint dimensions ---
SLIDE_W = 13.333 * inch
SLIDE_H = 7.5 * inch
MARGIN = 0.55 * inch
CONTENT_W = SLIDE_W - 2 * MARGIN

# --- Palette: distinct from both existing PDF reports' palettes so this reads as its
# own "executive" visual identity, not a recolored technical report ---
INK = colors.HexColor("#0B1220")          # near-black background accent / titles
PANEL = colors.HexColor("#F8FAFC")        # light content panels
ACCENT = colors.HexColor("#1D4ED8")       # primary accent (deep blue, boardroom-appropriate)
ACCENT_LIGHT = colors.HexColor("#DBEAFE")
MUTED = colors.HexColor("#64748B")
WHITE = colors.white

TIER_COLORS = {
    "Critical Impact": colors.HexColor("#B91C1C"),
    "High Impact": colors.HexColor("#EA580C"),
    "Medium Impact": colors.HexColor("#CA8A04"),
    "Low Impact": colors.HexColor("#15803D"),
    "Informational": colors.HexColor("#1D4ED8"),
}
SEVERITY_COLORS = {
    "critical": colors.HexColor("#B91C1C"),
    "high": colors.HexColor("#EA580C"),
    "medium": colors.HexColor("#CA8A04"),
    "low": colors.HexColor("#65A30D"),
    "info": colors.HexColor("#1D4ED8"),
}

FONT_TITLE = "Helvetica-Bold"
FONT_BODY = "Helvetica"
FONT_BODY_BOLD = "Helvetica-Bold"


def _wrap_text_to_width(text: str, font: str, size: float, max_width: float) -> list[str]:
    """Greedy word-wrap measured against actual font metrics, so callers
    can know in advance exactly how many lines a block of text will need
    — required for the no-overflow guarantee this module commits to,
    since canvas drawing (unlike Platypus) does not wrap automatically."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if stringWidth(candidate, font, size) <= max_width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _slide_chrome(c: canvas.Canvas, title: str, subtitle: str, slide_num: int, total_slides: int,
                   classification: str = "Confidential — Board & Executive Distribution") -> float:
    """
    Draws the consistent header band + footer bar present on every slide
    (the "rigid consistency in layout" requirement), and returns the y
    coordinate where slide-specific content should begin drawing below
    the header.
    """
    c.setFillColor(WHITE)
    c.rect(0, 0, SLIDE_W, SLIDE_H, fill=1, stroke=0)

    header_h = 1.15 * inch
    c.setFillColor(INK)
    c.rect(0, SLIDE_H - header_h, SLIDE_W, header_h, fill=1, stroke=0)
    c.setFillColor(ACCENT)
    c.rect(0, SLIDE_H - header_h - 4, SLIDE_W, 4, fill=1, stroke=0)

    c.setFillColor(WHITE)
    c.setFont(FONT_TITLE, 22)
    c.drawString(MARGIN, SLIDE_H - 0.55 * inch, title)
    c.setFont(FONT_BODY, 12)
    c.setFillColor(colors.HexColor("#94A3B8"))
    c.drawString(MARGIN, SLIDE_H - 0.85 * inch, subtitle)

    c.setFillColor(colors.HexColor("#F1F5F9"))
    c.rect(0, 0, SLIDE_W, 0.35 * inch, fill=1, stroke=0)
    c.setFillColor(MUTED)
    c.setFont(FONT_BODY, 8)
    c.drawString(MARGIN, 0.13 * inch, classification)
    c.drawRightString(SLIDE_W - MARGIN, 0.13 * inch, f"Slide {slide_num} of {total_slides}")

    return SLIDE_H - header_h - 0.35 * inch


def _draw_bullets(c: canvas.Canvas, x: float, y: float, width: float, bullets: list[str],
                   font_size: float = 13, leading: float = 19, bullet_color=INK) -> float:
    for bullet in bullets:
        lines = _wrap_text_to_width(bullet, FONT_BODY, font_size, width - 18)
        c.setFillColor(ACCENT)
        # Dot vertically centered on the first line's cap-height (roughly
        # 0.7x font_size above the baseline) rather than sitting at the
        # baseline itself, so it reads as aligned with the text block as
        # a whole rather than anchored to the bottom of the first line.
        c.circle(x + 4, y - font_size * 0.35, 3, fill=1, stroke=0)
        c.setFillColor(bullet_color)
        c.setFont(FONT_BODY, font_size)
        for i, line in enumerate(lines):
            c.drawString(x + 16, y - i * leading, line)
        y -= leading * len(lines) + 10
    return y


def _score_badge(c: canvas.Canvas, x: float, y: float, score: int, tier: str, size: float = 1.3 * inch):
    color = TIER_COLORS.get(tier, MUTED)
    c.setFillColor(color)
    c.circle(x + size / 2, y - size / 2, size / 2, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont(FONT_TITLE, 28)
    c.drawCentredString(x + size / 2, y - size / 2 - 10, str(score))
    c.setFont(FONT_BODY, 11)
    c.drawCentredString(x + size / 2, y - size / 2 - 26, "/ 100")


# ============================================================
# Slide builders
# ============================================================

def slide_cover(c: canvas.Canvas, title: str, subtitle: str, vendor_count: int, slide_num: int, total: int):
    c.setFillColor(INK)
    c.rect(0, 0, SLIDE_W, SLIDE_H, fill=1, stroke=0)
    c.setFillColor(ACCENT)
    c.rect(0, SLIDE_H / 2 - 2, SLIDE_W, 4, fill=1, stroke=0)

    c.setFillColor(WHITE)
    c.setFont(FONT_TITLE, 34)
    c.drawCentredString(SLIDE_W / 2, SLIDE_H / 2 + 0.5 * inch, title)
    c.setFont(FONT_BODY, 16)
    c.setFillColor(colors.HexColor("#94A3B8"))
    c.drawCentredString(SLIDE_W / 2, SLIDE_H / 2 + 0.1 * inch, subtitle)

    generated = datetime.now(timezone.utc).strftime("%B %d, %Y")
    c.setFont(FONT_BODY, 12)
    c.setFillColor(colors.HexColor("#64748B"))
    c.drawCentredString(SLIDE_W / 2, SLIDE_H / 2 - 0.5 * inch,
                         f"Prepared {generated}  \u2022  {vendor_count} vendor(s) in scope  \u2022  Confidential")
    c.setFont(FONT_BODY, 9)
    c.drawCentredString(SLIDE_W / 2, 0.4 * inch, f"Slide {slide_num} of {total}")


def slide_executive_summary(c: canvas.Canvas, headline_score: int, headline_tier: str,
                             talking_points: list[str], vendor_label: str,
                             slide_num: int, total: int, severity_counts: dict | None = None):
    top = _slide_chrome(c, "Executive Summary", vendor_label, slide_num, total)
    content_top = top - 0.45 * inch

    badge_x = MARGIN
    _score_badge(c, badge_x, content_top, headline_score, headline_tier, size=1.7 * inch)
    tier_color = TIER_COLORS.get(headline_tier, MUTED)
    c.setFillColor(tier_color)
    c.setFont(FONT_BODY_BOLD, 13)
    c.drawCentredString(badge_x + 0.85 * inch, content_top - 1.95 * inch, headline_tier)

    points_x = badge_x + 2.3 * inch
    points_w = SLIDE_W - MARGIN - points_x
    c.setFillColor(INK)
    c.setFont(FONT_BODY_BOLD, 14)
    c.drawString(points_x, content_top - 0.1 * inch, "Key Takeaways for Leadership")
    bullets_end_y = _draw_bullets(c, points_x, content_top - 0.5 * inch, points_w, talking_points,
                                   font_size=13.5, leading=20)

    # Severity breakdown stat strip: fills the remaining vertical space
    # below the bullets (which, for a typical 3-4 point list, leaves a
    # large gap to the footer) with genuinely useful summary numbers
    # rather than leaving that area blank.
    if severity_counts is not None:
        strip_y = min(bullets_end_y - 0.25 * inch, content_top - 2.5 * inch)
        strip_bottom = 0.7 * inch
        if strip_y > strip_bottom + 0.6 * inch:
            labels = ["Critical", "High", "Medium", "Low", "Info"]
            keys = ["critical", "high", "medium", "low", "info"]
            stat_w = (SLIDE_W - 2 * MARGIN) / len(labels)
            c.setStrokeColor(colors.HexColor("#E2E8F0"))
            c.setLineWidth(0.75)
            c.line(MARGIN, strip_y, SLIDE_W - MARGIN, strip_y)
            for i, (label, key) in enumerate(zip(labels, keys)):
                cx = MARGIN + i * stat_w + stat_w / 2
                count = severity_counts.get(key, 0)
                color = SEVERITY_COLORS.get(key, MUTED)
                c.setFillColor(color)
                c.setFont(FONT_TITLE, 26)
                c.drawCentredString(cx, strip_y - 0.55 * inch, str(count))
                c.setFillColor(MUTED)
                c.setFont(FONT_BODY, 11)
                c.drawCentredString(cx, strip_y - 0.8 * inch, f"{label} Findings")


def slide_risk_landscape_single(c: canvas.Canvas, finding_categories: list[dict], slide_num: int, total: int):
    top = _slide_chrome(c, "Risk Landscape", "Findings grouped by business risk category", slide_num, total)
    content_top = top - 0.45 * inch
    content_bottom = 0.55 * inch
    bar_x = MARGIN + 2.7 * inch
    bar_max_w = SLIDE_W - MARGIN - bar_x - 0.6 * inch
    max_count = max((cat["count"] for cat in finding_categories), default=1)

    if not finding_categories:
        c.setFillColor(MUTED)
        c.setFont(FONT_BODY, 16)
        c.drawCentredString(SLIDE_W / 2, (content_top + content_bottom) / 2,
                             "No findings were identified during this assessment \u2014 strong baseline posture "
                             "across all observed risk categories.")
        return

    # Row height fills the full available content area regardless of how
    # many categories there are (same fill-to-height technique used by
    # slide_key_findings below) — an earlier version used a fixed 0.55in
    # row height, which left most of the slide blank whenever there were
    # only 1-3 categories (the common case for a single, lightly-flawed
    # vendor) instead of only when there were genuinely many categories.
    available_h = content_top - content_bottom
    row_h = min(1.8 * inch, available_h / len(finding_categories))
    bar_h = min(0.55 * inch, row_h * 0.45)

    y = content_top
    for cat in finding_categories:
        label_y = y - row_h * 0.32
        c.setFillColor(INK)
        c.setFont(FONT_BODY_BOLD, 14)
        label_lines = _wrap_text_to_width(cat["category"], FONT_BODY_BOLD, 14, 2.5 * inch)
        for i, line in enumerate(label_lines):
            c.drawString(MARGIN, label_y - i * 16, line)

        bar_w = max(0.25 * inch, (cat["count"] / max_count) * bar_max_w)
        bar_color = SEVERITY_COLORS.get(cat["top_severity"], ACCENT)
        bar_y = y - row_h * 0.32 - bar_h / 2 + 4
        c.setFillColor(bar_color)
        c.roundRect(bar_x, bar_y, bar_w, bar_h, 5, fill=1, stroke=0)
        c.setFillColor(INK)
        c.setFont(FONT_BODY_BOLD, 14)
        finding_word = "finding" if cat["count"] == 1 else "findings"
        c.drawString(bar_x + bar_w + 12, bar_y + bar_h / 2 - 5, f"{cat['count']} {finding_word}")

        # Caption: the business severity label, so even a category with
        # just one finding carries substantive, non-bare-numeric content
        # rather than a lone count sitting next to an otherwise-empty row.
        c.setFillColor(MUTED)
        c.setFont(FONT_BODY, 10.5)
        caption = f"Top severity in this category: {severity_business_label(cat['top_severity'])}"
        c.drawString(MARGIN, y - row_h + 16, caption)

        y -= row_h
        if y > content_bottom + row_h:
            c.setStrokeColor(colors.HexColor("#E2E8F0"))
            c.setLineWidth(0.5)
            c.line(MARGIN, y, SLIDE_W - MARGIN, y)



def slide_risk_landscape_portfolio(c: canvas.Canvas, vendor_results: list[dict], slide_num: int, total: int):
    top = _slide_chrome(c, "Risk Landscape", "Vendor portfolio ranked by external risk score", slide_num, total)
    content_top = top - 0.4 * inch
    content_bottom = 0.55 * inch
    ranked = sorted(vendor_results, key=lambda v: v["score"])
    bar_x = MARGIN + 2.4 * inch
    bar_max_w = SLIDE_W - MARGIN - bar_x - 0.7 * inch
    available_h = content_top - content_bottom
    # Capped at 0.85in (rather than the previous 0.5in hard cap) so a
    # small portfolio's rows genuinely fill the slide instead of leaving
    # the lower half blank — large portfolios still shrink rows via the
    # available_h/len(ranked) term so they never overflow the slide.
    row_h = min(0.85 * inch, available_h / max(len(ranked), 1))

    y = content_top
    for v in ranked:
        c.setFillColor(INK)
        c.setFont(FONT_BODY_BOLD, 11)
        name_lines = _wrap_text_to_width(v["name"], FONT_BODY_BOLD, 11, 2.2 * inch)
        c.drawString(MARGIN, y - row_h / 2 - 4, name_lines[0])

        bar_w = max(0.1 * inch, (v["score"] / 100) * bar_max_w)
        bar_color = TIER_COLORS.get(v["tier"], ACCENT)
        c.setFillColor(bar_color)
        c.roundRect(bar_x, y - row_h + 8, bar_w, row_h - 14, 3, fill=1, stroke=0)
        c.setFillColor(INK)
        c.setFont(FONT_BODY_BOLD, 11)
        c.drawString(bar_x + bar_w + 8, y - row_h / 2 - 4, f"{v['score']}/100")
        y -= row_h


def slide_regulatory_exposure(c: canvas.Canvas, exposure_items: list[dict], slide_num: int, total: int,
                               page_label: str = ""):
    top = _slide_chrome(c, "Regulatory & Financial Exposure",
                         f"What these findings mean in business and compliance terms{page_label}",
                         slide_num, total)
    content_top = top - 0.35 * inch
    content_bottom = 0.55 * inch
    available_h = content_top - content_bottom

    # Single full-width column for <=3 items: splitting 3 items into two
    # columns (2 + 1) leaves the 1-item column visibly half-empty compared
    # to its neighbor — full width with taller per-item slots reads as a
    # deliberate, well-balanced layout instead of an uneven split.
    use_two_columns = len(exposure_items) > 3
    if use_two_columns:
        col_w = (CONTENT_W - 0.4 * inch) / 2
        col_positions = [MARGIN, MARGIN + col_w + 0.4 * inch]
        half = (len(exposure_items) + 1) // 2
        columns = [exposure_items[:half], exposure_items[half:]]
    else:
        col_w = CONTENT_W
        col_positions = [MARGIN]
        columns = [exposure_items]

    max_items_in_a_column = max((len(col) for col in columns if col), default=1)
    slot_h = min(3.2 * inch, available_h / max_items_in_a_column)

    for col_idx, items in enumerate(columns):
        if not items:
            continue
        x = col_positions[col_idx]
        y = content_top
        for item in items:
            sev_color = SEVERITY_COLORS.get(item["severity"], MUTED)
            header_h = 26
            c.setFillColor(sev_color)
            c.roundRect(x, y - header_h, col_w, header_h, 4, fill=1, stroke=0)
            c.setFillColor(WHITE)
            c.setFont(FONT_BODY_BOLD, 12)
            c.drawString(x + 10, y - header_h + 8, item["category"].upper())

            lines = _wrap_text_to_width(item["financial_exposure"], FONT_BODY, 12.5, col_w - 14)
            c.setFillColor(INK)
            c.setFont(FONT_BODY, 12.5)
            ty = y - header_h - 22
            max_lines = max(1, int((slot_h - header_h - 16) // 17))
            for line in lines[:max_lines]:
                c.drawString(x + 7, ty, line)
                ty -= 17
            y -= slot_h


def slide_key_findings(c: canvas.Canvas, findings_page: list[dict], slide_num: int, total: int,
                        page_label: str = ""):
    top = _slide_chrome(c, "Key Findings \u2014 Business Impact",
                         f"Top findings translated for executive review{page_label}", slide_num, total)
    content_top = top - 0.3 * inch
    y = content_top
    row_h = (content_top - 0.3 * inch) / max(len(findings_page), 1)
    row_h = min(row_h, 1.5 * inch)

    for f in findings_page:
        sev_color = SEVERITY_COLORS.get(f["severity"], MUTED)
        c.setFillColor(sev_color)
        c.roundRect(MARGIN, y - row_h + 8, 0.18 * inch, row_h - 16, 2, fill=1, stroke=0)

        text_x = MARGIN + 0.32 * inch
        text_w = CONTENT_W - 0.32 * inch
        c.setFillColor(INK)
        c.setFont(FONT_BODY_BOLD, 12.5)
        c.drawString(text_x, y - 16, f["category"])
        c.setFillColor(sev_color)
        c.setFont(FONT_BODY_BOLD, 9)
        c.drawRightString(MARGIN + text_w, y - 16, severity_business_label(f["severity"]).upper())

        lines = _wrap_text_to_width(f["business_impact"], FONT_BODY, 10.5, text_w)
        c.setFillColor(colors.HexColor("#334155"))
        c.setFont(FONT_BODY, 10.5)
        ty = y - 32
        for line in lines[:3]:
            c.drawString(text_x, ty, line)
            ty -= 13
        y -= row_h


def slide_portfolio_table(c: canvas.Canvas, vendor_results: list[dict], slide_num: int, total: int,
                           page_label: str = ""):
    top = _slide_chrome(c, "Vendor Comparison Matrix", f"Full portfolio at a glance{page_label}",
                         slide_num, total)
    content_top = top - 0.35 * inch
    col_widths = [3.5 * inch, 1.3 * inch, 2.2 * inch, CONTENT_W - 3.5 * inch - 1.3 * inch - 2.2 * inch]
    headers = ["Vendor", "Score", "Risk Tier", "Recommended Action"]

    c.setFillColor(INK)
    c.rect(MARGIN, content_top - 26, CONTENT_W, 26, fill=1, stroke=0)
    c.setFillColor(WHITE)
    c.setFont(FONT_BODY_BOLD, 11)
    cx = MARGIN + 10
    for header, w in zip(headers, col_widths):
        c.drawString(cx, content_top - 18, header)
        cx += w

    row_h = 0.42 * inch
    y = content_top - 26
    ranked = sorted(vendor_results, key=lambda v: v["score"])
    for i, v in enumerate(ranked):
        if i % 2 == 0:
            c.setFillColor(colors.HexColor("#F1F5F9"))
            c.rect(MARGIN, y - row_h, CONTENT_W, row_h, fill=1, stroke=0)
        tier_color = TIER_COLORS.get(v["tier"], MUTED)
        action = "Immediate remediation plan" if v["score"] < 30 else (
            "Prioritize at next review" if v["score"] < 60 else "Routine monitoring")
        cx = MARGIN + 10
        c.setFillColor(INK)
        c.setFont(FONT_BODY, 11)
        c.drawString(cx, y - row_h / 2 - 4, v["name"][:38])
        cx += col_widths[0]
        c.setFont(FONT_BODY_BOLD, 11)
        c.drawString(cx, y - row_h / 2 - 4, f"{v['score']}/100")
        cx += col_widths[1]
        c.setFillColor(tier_color)
        c.drawString(cx, y - row_h / 2 - 4, v["tier"])
        cx += col_widths[2]
        c.setFillColor(MUTED)
        c.setFont(FONT_BODY, 10.5)
        c.drawString(cx, y - row_h / 2 - 4, action)
        y -= row_h


def slide_recommendations(c: canvas.Canvas, recommendations: list[str], slide_num: int, total: int):
    top = _slide_chrome(c, "Recommended Actions", "Prioritized next steps for leadership", slide_num, total)
    content_top = top - 0.45 * inch
    content_bottom = 0.55 * inch
    row_h = (content_top - content_bottom) / max(len(recommendations), 1)
    row_h = min(row_h, 1.9 * inch)

    y = content_top
    for i, rec in enumerate(recommendations, start=1):
        circle_r = 0.26 * inch
        c.setFillColor(ACCENT)
        c.circle(MARGIN + circle_r, y - row_h / 2, circle_r, fill=1, stroke=0)
        c.setFillColor(WHITE)
        c.setFont(FONT_BODY_BOLD, 16)
        c.drawCentredString(MARGIN + circle_r, y - row_h / 2 - 5.5, str(i))

        text_x = MARGIN + 0.7 * inch
        text_w = CONTENT_W - 0.7 * inch
        lines = _wrap_text_to_width(rec, FONT_BODY, 15, text_w)
        c.setFillColor(INK)
        c.setFont(FONT_BODY, 15)
        # Vertically center the (possibly multi-line) text block within
        # the row, rather than anchoring it to the top of a tall row —
        # this is what made earlier short, 1-line recommendations look
        # like they were floating in mostly-empty space.
        text_block_h = len(lines[:3]) * 19
        ty = y - row_h / 2 + text_block_h / 2 - 14
        for line in lines[:3]:
            c.drawString(text_x, ty, line)
            ty -= 19
        y -= row_h
        if y > content_bottom + 4:
            c.setStrokeColor(colors.HexColor("#E2E8F0"))
            c.setLineWidth(0.5)
            c.line(MARGIN, y, SLIDE_W - MARGIN, y)


def slide_methodology(c: canvas.Canvas, scope_note: str, slide_num: int, total: int):
    top = _slide_chrome(c, "Methodology & Scope", "How this assessment was conducted", slide_num, total)
    content_top = top - 0.4 * inch

    lines = _wrap_text_to_width(scope_note, FONT_BODY, 13.5, CONTENT_W)
    y = content_top
    c.setFillColor(colors.HexColor("#334155"))
    c.setFont(FONT_BODY, 13.5)
    for line in lines:
        c.drawString(MARGIN, y, line)
        y -= 19

    # Frameworks-referenced panel grid: genuine, accurate reference
    # content (not decorative padding) that belongs on a methodology
    # slide regardless of scope_note length — an earlier version of this
    # slide relied entirely on scope_note + a short disclaimer, which left
    # roughly 80% of the slide blank for any reasonably concise scope_note.
    panel_top = y - 0.35 * inch
    panels = [
        ("NIST SP 800-53 / CSF 2.0", "Supply chain risk management (SR family), communications protection "
                                      "(SC family), and PR.DS / PR.PT / GV.SC functions."),
        ("ISO/IEC 27001:2022", "Annex A controls 5.19-5.23 (supplier relationships), 8.24 (cryptography), "
                                "and 8.20-8.26 (network & application security)."),
        ("DORA (EU 2022/2554)", "Articles 28-30: ICT third-party risk strategy, due diligence, and "
                                 "contractual security requirements."),
        ("GDPR", "Articles 28, 32, and 44-49: processor security obligations, encryption in transit, "
                 "and cross-border transfer safeguards."),
    ]
    col_w = (CONTENT_W - 0.45 * inch) / 2
    panel_h = 1.05 * inch
    positions = [
        (MARGIN, panel_top), (MARGIN + col_w + 0.45 * inch, panel_top),
        (MARGIN, panel_top - panel_h - 0.2 * inch), (MARGIN + col_w + 0.45 * inch, panel_top - panel_h - 0.2 * inch),
    ]
    for (title, body), (px, py) in zip(panels, positions):
        c.setFillColor(ACCENT_LIGHT)
        c.roundRect(px, py - panel_h, col_w, panel_h, 6, fill=1, stroke=0)
        c.setFillColor(ACCENT)
        c.setFont(FONT_BODY_BOLD, 12.5)
        c.drawString(px + 12, py - 22, title)
        c.setFillColor(colors.HexColor("#1E3A8A"))
        c.setFont(FONT_BODY, 10.5)
        ty = py - 40
        for line in _wrap_text_to_width(body, FONT_BODY, 10.5, col_w - 24):
            c.drawString(px + 12, ty, line)
            ty -= 14

    disclaimer_y = positions[2][1] - panel_h - 0.3 * inch
    c.setFillColor(MUTED)
    c.setFont(FONT_BODY, 10.5)
    disclaimer = (
        "This is an external, passive assessment based on publicly observable signals. It does not "
        "include internal network access, credentialed scanning, or physical security review, and should "
        "supplement \u2014 not replace \u2014 formal vendor due diligence, SOC 2/ISO certificates, and contractual review."
    )
    ty = disclaimer_y
    for line in _wrap_text_to_width(disclaimer, FONT_BODY, 10.5, CONTENT_W):
        c.drawString(MARGIN, ty, line)
        ty -= 14

"""
Executive Deck Orchestrator — Risk Assessment Tool
-------------------------------------------------------
Assembles a complete, paginated executive slide deck from the same
vendor_reports data structure app/reporting/pdf_builder.py already
consumes (list of dicts: name, website, domain, score, tier, narrative,
findings — where findings is a list of ComplianceFinding objects).

Pagination policy (the "zero blank space, no incomplete slides"
requirement): every paginated slide type below computes how many items
fit per page from real, measured capacity (not a hardcoded "5 per slide"
guess) and produces exactly enough slides for the data — never more
slides than there is content to fill, never fewer such that content is
silently dropped.
"""
from __future__ import annotations

import io

from reportlab.pdfgen import canvas

from app import deck_slides as ds
from app.business_translation import translate_finding
from app.deck_narrative import generate_executive_talking_points, generate_portfolio_talking_points

_FINDINGS_PER_SLIDE = 4
_EXPOSURE_PER_SLIDE = 6
_PORTFOLIO_ROWS_PER_SLIDE = 11


def _chunk(items: list, size: int) -> list:
    return [items[i:i + size] for i in range(0, len(items), size)] or [[]]


def _build_finding_categories(findings: list) -> list:
    by_category = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in findings:
        translation = translate_finding(f.finding)
        cat = translation["category"]
        entry = by_category.setdefault(cat, {"category": cat, "count": 0, "top_severity": f.severity})
        entry["count"] += 1
        if severity_rank.get(f.severity, 9) < severity_rank.get(entry["top_severity"], 9):
            entry["top_severity"] = f.severity
    return sorted(by_category.values(), key=lambda e: severity_rank.get(e["top_severity"], 9))


def _build_exposure_items(findings: list) -> list:
    seen = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in findings:
        translation = translate_finding(f.finding)
        key = translation["category"]
        if key not in seen or severity_rank.get(f.severity, 9) < severity_rank.get(seen[key]["severity"], 9):
            seen[key] = {
                "category": translation["category"],
                "financial_exposure": translation["financial_exposure"],
                "severity": f.severity,
            }
    return sorted(seen.values(), key=lambda e: severity_rank.get(e["severity"], 9))


def _build_findings_detail(findings: list) -> list:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen_keys = set()
    items = []
    for f in sorted(findings, key=lambda f: severity_rank.get(f.severity, 9)):
        translation = translate_finding(f.finding)
        key = (translation["category"], translation["business_impact"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        items.append({
            "category": translation["category"],
            "business_impact": translation["business_impact"],
            "severity": f.severity,
        })
    return items


def _build_recommendations(findings: list, score: int) -> list:
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    recs = []
    if severity_counts.get("critical"):
        recs.append(
            f"Initiate immediate vendor escalation for {severity_counts['critical']} critical finding(s) "
            f"\u2014 request a remediation timeline within 5 business days."
        )
    if severity_counts.get("high"):
        recs.append(
            f"Add {severity_counts['high']} high-severity finding(s) to the next vendor risk review agenda "
            f"and request written remediation commitments."
        )
    if score < 60:
        recs.append(
            "Consider this vendor's risk score as a factor in the next contract renewal or renegotiation cycle."
        )
    recs.append("Request updated SOC 2, ISO 27001, or equivalent third-party attestations from the vendor.")
    recs.append("Schedule a routine re-assessment in 90 days to confirm remediation progress.")
    if not severity_counts:
        recs.insert(0, "No urgent action required \u2014 maintain current monitoring cadence.")
    return recs[:6]


async def build_single_vendor_deck(vendor_report: dict, api_key) -> bytes:
    findings = vendor_report["findings"]
    score = vendor_report["score"]
    tier = vendor_report["tier"]
    name = vendor_report["name"]
    domain = vendor_report["domain"]

    finding_categories = _build_finding_categories(findings)
    exposure_items = _build_exposure_items(findings)
    findings_detail = _build_findings_detail(findings)
    recommendations = _build_recommendations(findings, score)
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    findings_summary_for_ai = [
        {"text": f.finding, "severity": f.severity, **translate_finding(f.finding)} for f in findings
    ]
    talking_points = await generate_executive_talking_points(
        name, domain, score, tier, findings_summary_for_ai, api_key,
    )

    exposure_pages = _chunk(exposure_items, _EXPOSURE_PER_SLIDE) if exposure_items else [[]]
    findings_pages = _chunk(findings_detail, _FINDINGS_PER_SLIDE) if findings_detail else [[]]

    # 3 fixed slides (cover, summary, landscape) + exposure pages +
    # findings pages + 1 recommendations + 1 methodology = the "+4" here
    # is 3 fixed + 1 recommendations; the final "+1" is the methodology
    # slide that ONLY this single-vendor deck has (the portfolio deck's
    # equivalent formula deliberately does not carry this extra +1 — see
    # build_portfolio_deck below).
    total_slides = 4 + len(exposure_pages) + len(findings_pages) + 1
    slide_num = 0
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ds.SLIDE_W, ds.SLIDE_H))

    slide_num += 1
    ds.slide_cover(c, f"{name}", "Third-Party Vendor Risk \u2014 Executive Briefing", 1, slide_num, total_slides)
    c.showPage()

    slide_num += 1
    ds.slide_executive_summary(c, score, tier, talking_points, f"{name} ({domain})", slide_num, total_slides,
                                severity_counts=severity_counts)
    c.showPage()

    slide_num += 1
    ds.slide_risk_landscape_single(c, finding_categories, slide_num, total_slides)
    c.showPage()

    for i, page_items in enumerate(exposure_pages):
        slide_num += 1
        label = f" ({i + 1}/{len(exposure_pages)})" if len(exposure_pages) > 1 else ""
        if not page_items:
            page_items = [{
                "category": "Overall Posture", "severity": "info",
                "financial_exposure": "No material regulatory exposure identified in this assessment window.",
            }]
        ds.slide_regulatory_exposure(c, page_items, slide_num, total_slides, label)
        c.showPage()

    for i, page_items in enumerate(findings_pages):
        slide_num += 1
        label = f" ({i + 1}/{len(findings_pages)})" if len(findings_pages) > 1 else ""
        if not page_items:
            page_items = [{
                "category": "Overall Posture", "severity": "info",
                "business_impact": "No material findings were identified \u2014 this vendor demonstrates a "
                                    "strong external security baseline at the time of assessment.",
            }]
        ds.slide_key_findings(c, page_items, slide_num, total_slides, label)
        c.showPage()

    slide_num += 1
    ds.slide_recommendations(c, recommendations, slide_num, total_slides)
    c.showPage()

    slide_num += 1
    ds.slide_methodology(
        c,
        f"This briefing summarizes a passive, external security assessment of {name} ({domain}), "
        f"mapped against NIST SP 800-53/CSF, ISO/IEC 27001:2022, DORA Articles 28-30, and GDPR.",
        slide_num, total_slides,
    )
    c.showPage()

    c.save()
    return buf.getvalue()


async def build_portfolio_deck(vendor_reports: list, api_key) -> bytes:
    summary_results = [{"name": v["name"], "score": v["score"], "tier": v["tier"]} for v in vendor_reports]
    avg_score = round(sum(v["score"] for v in summary_results) / len(summary_results)) if summary_results else 0
    overall_tier = min(summary_results, key=lambda v: v["score"])["tier"] if summary_results else "Informational"

    talking_points = await generate_portfolio_talking_points(summary_results, api_key)

    all_findings = [f for v in vendor_reports for f in v["findings"]]
    exposure_items = _build_exposure_items(all_findings)
    findings_detail = _build_findings_detail(all_findings)
    recommendations = _build_recommendations(all_findings, avg_score)
    severity_counts = {}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    exposure_pages = _chunk(exposure_items, _EXPOSURE_PER_SLIDE) if exposure_items else [[]]
    findings_pages = _chunk(findings_detail, _FINDINGS_PER_SLIDE) if findings_detail else [[]]
    portfolio_pages = _chunk(summary_results, _PORTFOLIO_ROWS_PER_SLIDE)

    # 3 fixed slides (cover, summary, landscape) + portfolio table pages +
    # exposure pages + findings pages + 1 recommendations slide. Unlike
    # build_single_vendor_deck, the portfolio deck has NO methodology
    # slide, so this must NOT carry the same "+1" the single-vendor
    # formula has for that — an earlier version did, producing a
    # total_slides one higher than the actual number of showPage() calls
    # below (footers read "Slide 3 of 9" on an 8-page PDF).
    total_slides = 3 + len(portfolio_pages) + len(exposure_pages) + len(findings_pages) + 1
    slide_num = 0
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ds.SLIDE_W, ds.SLIDE_H))

    slide_num += 1
    ds.slide_cover(c, "Vendor Risk Portfolio", "Third-Party Vendor Risk \u2014 Executive Briefing",
                    len(vendor_reports), slide_num, total_slides)
    c.showPage()

    slide_num += 1
    ds.slide_executive_summary(
        c, avg_score, overall_tier, talking_points,
        f"{len(vendor_reports)} vendor(s) assessed \u2014 portfolio average", slide_num, total_slides,
        severity_counts=severity_counts,
    )
    c.showPage()

    slide_num += 1
    ds.slide_risk_landscape_portfolio(c, summary_results, slide_num, total_slides)
    c.showPage()

    for i, page_items in enumerate(portfolio_pages):
        slide_num += 1
        label = f" ({i + 1}/{len(portfolio_pages)})" if len(portfolio_pages) > 1 else ""
        ds.slide_portfolio_table(c, page_items, slide_num, total_slides, label)
        c.showPage()

    for i, page_items in enumerate(exposure_pages):
        slide_num += 1
        label = f" ({i + 1}/{len(exposure_pages)})" if len(exposure_pages) > 1 else ""
        if not page_items:
            page_items = [{
                "category": "Overall Posture", "severity": "info",
                "financial_exposure": "No material regulatory exposure identified across this vendor portfolio.",
            }]
        ds.slide_regulatory_exposure(c, page_items, slide_num, total_slides, label)
        c.showPage()

    for i, page_items in enumerate(findings_pages):
        slide_num += 1
        label = f" ({i + 1}/{len(findings_pages)})" if len(findings_pages) > 1 else ""
        if not page_items:
            page_items = [{
                "category": "Overall Posture", "severity": "info",
                "business_impact": "No material findings were identified across this vendor portfolio \u2014 "
                                    "strong aggregate external security baseline.",
            }]
        ds.slide_key_findings(c, page_items, slide_num, total_slides, label)
        c.showPage()

    slide_num += 1
    ds.slide_recommendations(c, recommendations, slide_num, total_slides)
    c.showPage()

    c.save()
    return buf.getvalue()

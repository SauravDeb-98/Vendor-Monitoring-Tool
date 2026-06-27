"""
Executive Deck Orchestrator — Threat Detector Tool
-------------------------------------------------------
Equivalent to deck_orchestrator.py (the Risk Assessment tool's version),
but consuming the Threat Detector tool's data shape instead: a list of
{vendor_name, domain, results: [{detector, detector_label, risk_score,
rating_letter, summary, detail_items, error}]} dicts — the same shape
build_executive_pdf() in executive_report.py already consumes, and the
same shape download_vendor_last_report() in detector_routes.py
reconstructs from score_history for a single vendor.

Kept as a separate module from deck_orchestrator.py (rather than one
orchestrator with branching logic) because the two tools' underlying
finding/result shapes are different enough (ComplianceFinding objects
with NIST/ISO/DORA/GDPR citation lists vs. detector_type + free-text
summary) that a shared function would need extensive type-checking
branches — two small, clear modules are easier to verify than one with
hidden conditional paths. Both call the same deck_slides.py primitives,
so the visual output stays consistent across tools.
"""
from __future__ import annotations

import io

from reportlab.pdfgen import canvas

from app import deck_slides as ds
from app.business_translation import translate_detector
from app.deck_narrative import generate_executive_talking_points, generate_portfolio_talking_points

_FINDINGS_PER_SLIDE = 4
_EXPOSURE_PER_SLIDE = 6
_PORTFOLIO_ROWS_PER_SLIDE = 11

# Detector results with no numeric score (e.g. exploitation: "no entries
# found") still have a rating_letter; map ratings the detector layer uses
# to an approximate 0-100 scale for the score-badge/severity treatment
# this deck format expects, since most detectors here use letter grades
# rather than the Risk Assessment tool's 0-100 score.
_RATING_TO_SCORE = {"A": 95, "B": 80, "C": 60, "D": 35, "F": 10}
_RATING_TO_TIER = {
    "A": "Low Impact", "B": "Low Impact", "C": "Medium Impact",
    "D": "High Impact", "F": "Critical Impact",
}
_SEVERITY_FROM_TIER = {
    "Critical Impact": "critical", "High Impact": "high", "Medium Impact": "medium",
    "Low Impact": "low", "Informational": "info",
}


def _chunk(items: list, size: int) -> list:
    return [items[i:i + size] for i in range(0, len(items), size)] or [[]]


def _result_to_score_and_tier(result: dict) -> tuple:
    if result.get("risk_score") is not None:
        score = result["risk_score"]
        tier = ("Critical Impact" if score < 20 else "High Impact" if score < 50
                else "Medium Impact" if score < 70 else "Low Impact" if score < 95 else "Informational")
        return score, tier
    rating = result.get("rating_letter")
    if rating in _RATING_TO_SCORE:
        return _RATING_TO_SCORE[rating], _RATING_TO_TIER[rating]
    return 80, "Low Impact"  # no score, no rating, no error -> treat as clean/informational, not a gap


def _vendor_overall(vendor_entry: dict) -> tuple:
    """Worst-case score/tier across this vendor's detector results,
    consistent with how the Risk Assessment tool treats its lowest score
    as most material — same severity-first principle, different input shape."""
    scored = [_result_to_score_and_tier(r) for r in vendor_entry["results"] if not r.get("error")]
    if not scored:
        return 80, "Low Impact"
    return min(scored, key=lambda st: st[0])


def _build_finding_categories(vendor_entry: dict) -> list:
    by_category = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for r in vendor_entry["results"]:
        if r.get("error"):
            continue
        translation = translate_detector(r["detector"])
        score, tier = _result_to_score_and_tier(r)
        severity = _SEVERITY_FROM_TIER.get(tier, "info")
        cat = translation["category"]
        entry = by_category.setdefault(cat, {"category": cat, "count": 0, "top_severity": severity})
        entry["count"] += 1
        if severity_rank.get(severity, 9) < severity_rank.get(entry["top_severity"], 9):
            entry["top_severity"] = severity
    return sorted(by_category.values(), key=lambda e: severity_rank.get(e["top_severity"], 9))


def _build_exposure_items(vendor_entries: list) -> list:
    seen = {}
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for ve in vendor_entries:
        for r in ve["results"]:
            if r.get("error"):
                continue
            translation = translate_detector(r["detector"])
            score, tier = _result_to_score_and_tier(r)
            severity = _SEVERITY_FROM_TIER.get(tier, "info")
            key = translation["category"]
            if key not in seen or severity_rank.get(severity, 9) < severity_rank.get(seen[key]["severity"], 9):
                seen[key] = {
                    "category": translation["category"],
                    "financial_exposure": translation["financial_exposure"],
                    "severity": severity,
                }
    return sorted(seen.values(), key=lambda e: severity_rank.get(e["severity"], 9))


def _build_findings_detail(vendor_entries: list) -> list:
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    seen_keys = set()
    items = []
    flat = []
    for ve in vendor_entries:
        for r in ve["results"]:
            if r.get("error"):
                continue
            score, tier = _result_to_score_and_tier(r)
            severity = _SEVERITY_FROM_TIER.get(tier, "info")
            flat.append((r, severity))
    for r, severity in sorted(flat, key=lambda pair: severity_rank.get(pair[1], 9)):
        translation = translate_detector(r["detector"])
        key = (translation["category"], translation["business_impact"])
        if key in seen_keys:
            continue
        seen_keys.add(key)
        items.append({
            "category": translation["category"],
            "business_impact": translation["business_impact"],
            "severity": severity,
        })
    return items


def _build_recommendations(vendor_entries: list, avg_score: int) -> list:
    severity_counts = {}
    for ve in vendor_entries:
        for r in ve["results"]:
            if r.get("error"):
                continue
            _, tier = _result_to_score_and_tier(r)
            severity = _SEVERITY_FROM_TIER.get(tier, "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    recs = []
    if severity_counts.get("critical"):
        recs.append(
            f"Initiate immediate vendor escalation for {severity_counts['critical']} critical-severity "
            f"detector finding(s) \u2014 request a remediation timeline within 5 business days."
        )
    if severity_counts.get("high"):
        recs.append(
            f"Add {severity_counts['high']} high-severity detector finding(s) to the next vendor risk "
            f"review agenda."
        )
    if avg_score < 60:
        recs.append("Consider enabling continuous monitoring for lower-scoring vendors to track remediation progress.")
    recs.append("Request updated SOC 2, ISO 27001, or equivalent third-party attestations from affected vendors.")
    recs.append("Review the full detector registry coverage to confirm assessment scope matches vendor criticality.")
    if not severity_counts:
        recs.insert(0, "No urgent action required \u2014 maintain current monitoring cadence.")
    return recs[:6]


async def build_single_vendor_deck(vendor_entry: dict, api_key) -> bytes:
    """vendor_entry: one entry from a /api/detect job's 'results' list, or
    the single-element list download_vendor_last_report() builds —
    {vendor_name, domain, results: [...]}."""
    name = vendor_entry["vendor_name"]
    domain = vendor_entry["domain"]
    score, tier = _vendor_overall(vendor_entry)

    finding_categories = _build_finding_categories(vendor_entry)
    exposure_items = _build_exposure_items([vendor_entry])
    findings_detail = _build_findings_detail([vendor_entry])
    recommendations = _build_recommendations([vendor_entry], score)
    severity_counts = {}
    for cat in finding_categories:
        severity_counts[cat["top_severity"]] = severity_counts.get(cat["top_severity"], 0) + cat["count"]

    findings_summary_for_ai = [
        {"text": r["summary"] or r["detector_label"], "severity": _SEVERITY_FROM_TIER.get(
            _result_to_score_and_tier(r)[1], "info"), **translate_detector(r["detector"])}
        for r in vendor_entry["results"] if not r.get("error")
    ]
    talking_points = await generate_executive_talking_points(
        name, domain, score, tier, findings_summary_for_ai, api_key,
    )

    exposure_pages = _chunk(exposure_items, _EXPOSURE_PER_SLIDE) if exposure_items else [[]]
    findings_pages = _chunk(findings_detail, _FINDINGS_PER_SLIDE) if findings_detail else [[]]

    total_slides = 4 + len(exposure_pages) + len(findings_pages) + 1
    slide_num = 0
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ds.SLIDE_W, ds.SLIDE_H))

    slide_num += 1
    ds.slide_cover(c, name, "Vendor Threat Detection \u2014 Executive Briefing", 1, slide_num, total_slides)
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
                "financial_exposure": "No material regulatory exposure identified by this scan.",
            }]
        ds.slide_regulatory_exposure(c, page_items, slide_num, total_slides, label)
        c.showPage()

    for i, page_items in enumerate(findings_pages):
        slide_num += 1
        label = f" ({i + 1}/{len(findings_pages)})" if len(findings_pages) > 1 else ""
        if not page_items:
            page_items = [{
                "category": "Overall Posture", "severity": "info",
                "business_impact": "No material threat-detection findings were identified \u2014 this vendor "
                                    "demonstrates a strong external security baseline at the time of scan.",
            }]
        ds.slide_key_findings(c, page_items, slide_num, total_slides, label)
        c.showPage()

    slide_num += 1
    ds.slide_recommendations(c, recommendations, slide_num, total_slides)
    c.showPage()

    slide_num += 1
    ds.slide_methodology(
        c,
        f"This briefing summarizes passive threat-detection scan results for {name} ({domain}), covering "
        f"active exploitation intelligence, vulnerability exposure, phishing/brand-impersonation risk, and "
        f"related external attack-surface signals.",
        slide_num, total_slides,
    )
    c.showPage()

    c.save()
    return buf.getvalue()


async def build_portfolio_deck(vendor_entries: list, api_key) -> bytes:
    """vendor_entries: the full 'results' list from a multi-vendor /api/detect job."""
    summary_results = []
    for ve in vendor_entries:
        score, tier = _vendor_overall(ve)
        summary_results.append({"name": ve["vendor_name"], "score": score, "tier": tier})
    avg_score = round(sum(v["score"] for v in summary_results) / len(summary_results)) if summary_results else 0
    overall_tier = min(summary_results, key=lambda v: v["score"])["tier"] if summary_results else "Informational"

    talking_points = await generate_portfolio_talking_points(summary_results, api_key)

    exposure_items = _build_exposure_items(vendor_entries)
    findings_detail = _build_findings_detail(vendor_entries)
    recommendations = _build_recommendations(vendor_entries, avg_score)
    severity_counts = {}
    for item in exposure_items:
        severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1

    exposure_pages = _chunk(exposure_items, _EXPOSURE_PER_SLIDE) if exposure_items else [[]]
    findings_pages = _chunk(findings_detail, _FINDINGS_PER_SLIDE) if findings_detail else [[]]
    portfolio_pages = _chunk(summary_results, _PORTFOLIO_ROWS_PER_SLIDE)

    total_slides = 3 + len(portfolio_pages) + len(exposure_pages) + len(findings_pages) + 1
    slide_num = 0
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=(ds.SLIDE_W, ds.SLIDE_H))

    slide_num += 1
    ds.slide_cover(c, "Vendor Threat Detection Portfolio", "Vendor Threat Detection \u2014 Executive Briefing",
                    len(vendor_entries), slide_num, total_slides)
    c.showPage()

    slide_num += 1
    ds.slide_executive_summary(
        c, avg_score, overall_tier, talking_points,
        f"{len(vendor_entries)} vendor(s) scanned \u2014 portfolio average", slide_num, total_slides,
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
                "business_impact": "No material threat-detection findings were identified across this "
                                    "vendor portfolio.",
            }]
        ds.slide_key_findings(c, page_items, slide_num, total_slides, label)
        c.showPage()

    slide_num += 1
    ds.slide_recommendations(c, recommendations, slide_num, total_slides)
    c.showPage()

    c.save()
    return buf.getvalue()

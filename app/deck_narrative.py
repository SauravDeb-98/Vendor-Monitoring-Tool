"""
Executive Deck Narrative Generator
--------------------------------------
Hybrid narrative generation for the executive slide deck: AI-enhanced via
the visitor's own optional Claude API key (same BYO-key mechanism already
used for PDF report narratives in ai_analysis.py), with a deterministic,
rule-based fallback so every slide always has substantive content.

This mirrors ai_analysis.py's exact pattern deliberately: try Claude if a
key is present, catch ANY exception and silently fall back to deterministic
text, never let deck generation fail or produce a blank/placeholder slide
because of an AI-side problem (bad key, rate limit, network failure,
empty response). The deck's "zero blank space" requirement makes this
fallback discipline non-negotiable, not just a nice-to-have.
"""
from __future__ import annotations

import httpx

from app.business_translation import translate_finding, translate_detector, severity_business_label

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"


async def generate_executive_talking_points(
    vendor_name: str,
    domain: str,
    score: int,
    tier_label: str,
    findings_summary: list[dict],
    api_key: str | None,
) -> list[str]:
    """
    Returns 3-5 short, board-ready talking points (each a single sentence
    or short clause, meant for a bulleted slide — NOT paragraph prose like
    the PDF narrative). findings_summary: list of dicts with at least
    {"text": str, "severity": str, "category": str} — already business-
    translated, so the AI prompt asks for tightening/prioritizing
    language, not inventing the underlying risk categorization itself
    (that categorization stays deterministic and auditable either way).
    """
    if api_key:
        try:
            points = await _call_claude_for_talking_points(
                vendor_name, domain, score, tier_label, findings_summary, api_key,
            )
            if points:
                return points
        except Exception:
            pass  # fall through to deterministic talking points below
    return _fallback_talking_points(vendor_name, domain, score, tier_label, findings_summary)


async def _call_claude_for_talking_points(
    vendor_name, domain, score, tier_label, findings_summary, api_key: str,
) -> list[str]:
    findings_text = "\n".join(
        f"- [{f['severity'].upper()}] {f['category']}: {f['text']}"
        for f in findings_summary
    ) or "No material findings — strong posture."

    prompt = (
        f"You are briefing a CEO and CISO on third-party vendor risk. Vendor: {vendor_name} "
        f"({domain}). Risk score: {score}/100, tier: {tier_label}.\n"
        f"Findings (already categorized by business risk area):\n{findings_text}\n\n"
        f"Write exactly 4 short executive talking points for a board slide, in this style:\n"
        f"- Each point is one sentence, plain business language, no jargon, no acronyms unless "
        f"universally known (e.g. GDPR is fine, SC-8 is not).\n"
        f"- Lead with business/financial/regulatory consequence, not technical mechanism.\n"
        f"- Do not invent findings beyond what's listed above.\n"
        f"- Output ONLY the 4 points, one per line, no numbering, no markdown, no preamble."
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 350,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        result = "\n".join(text_blocks).strip()
        lines = [ln.strip(" -•\t") for ln in result.split("\n") if ln.strip()]
        if not lines:
            raise ValueError("Empty response from AI")
        return lines[:5]


def _fallback_talking_points(vendor_name, domain, score, tier_label, findings_summary) -> list[str]:
    """
    Deterministic talking points built directly from the same
    business-translated findings, ordered by severity. Always returns at
    least 3 points (even for a clean scan) — see the no-findings branch —
    so this can never produce a sparse or blank slide on its own.
    """
    if not findings_summary:
        return [
            f"{vendor_name} currently shows a strong external security posture with no material "
            f"findings, scoring {score}/100 ({tier_label}).",
            "No immediate board-level action required for this vendor relationship.",
            "Recommend routine re-assessment on a quarterly cycle to maintain this assurance level.",
        ]

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(findings_summary, key=lambda f: severity_order.get(f["severity"], 5))

    points = [
        f"{vendor_name} scores {score}/100 ({tier_label}) on external security posture, based on "
        f"{len(findings_summary)} finding(s) across {len({f['category'] for f in findings_summary})} "
        f"risk categories.",
    ]
    top = ordered[0]
    points.append(f"Most material concern — {top['category']}: {top['business_impact']}")
    if len(ordered) > 1:
        second = ordered[1]
        points.append(f"Also notable — {second['category']}: {second['business_impact']}")
    critical_or_high = [f for f in ordered if f["severity"] in ("critical", "high")]
    if critical_or_high:
        points.append(
            f"{len(critical_or_high)} finding(s) carry {severity_business_label(critical_or_high[0]['severity']).lower()} "
            f"— recommend remediation timeline as a condition of contract renewal."
        )
    else:
        points.append("No critical or high-severity findings — remaining items are routine remediation tracking.")
    return points


async def generate_portfolio_talking_points(
    vendor_results: list[dict],
    api_key: str | None,
) -> list[str]:
    """
    Multi-vendor (bulk-import) equivalent: 4-5 talking points summarizing
    the whole portfolio's risk posture, not any single vendor. Same
    hybrid AI/fallback pattern as generate_executive_talking_points.
    vendor_results: list of {name, score, tier} dicts.
    """
    if api_key:
        try:
            points = await _call_claude_for_portfolio_points(vendor_results, api_key)
            if points:
                return points
        except Exception:
            pass
    return _fallback_portfolio_points(vendor_results)


async def _call_claude_for_portfolio_points(vendor_results: list[dict], api_key: str) -> list[str]:
    vendor_lines = "\n".join(f"- {v['name']}: {v['score']}/100 ({v['tier']})" for v in vendor_results)
    avg = round(sum(v["score"] for v in vendor_results) / len(vendor_results)) if vendor_results else 0

    prompt = (
        f"You are briefing a CEO and CISO on a third-party vendor risk portfolio of "
        f"{len(vendor_results)} vendors, average score {avg}/100.\n"
        f"Vendor scores:\n{vendor_lines}\n\n"
        f"Write exactly 4 short executive talking points for a board slide summarizing portfolio-wide "
        f"risk, in this style:\n"
        f"- Each point is one sentence, plain business language, no jargon.\n"
        f"- Mention specific vendor names only for the worst performers, by name.\n"
        f"- Lead with business/financial/regulatory consequence, not technical detail.\n"
        f"- Output ONLY the 4 points, one per line, no numbering, no markdown, no preamble."
    )

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            ANTHROPIC_API_URL,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": ANTHROPIC_MODEL,
                "max_tokens": 350,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        result = "\n".join(text_blocks).strip()
        lines = [ln.strip(" -•\t") for ln in result.split("\n") if ln.strip()]
        if not lines:
            raise ValueError("Empty response from AI")
        return lines[:5]


def _fallback_portfolio_points(vendor_results: list[dict]) -> list[str]:
    if not vendor_results:
        return [
            "No vendors were included in this assessment batch.",
            "Add vendors to the inventory to generate a portfolio risk summary.",
            "This deck will repopulate automatically once vendor data is available.",
        ]

    avg_score = round(sum(v["score"] for v in vendor_results) / len(vendor_results))
    critical_vendors = [v for v in vendor_results if v["score"] <= 20]
    high_vendors = [v for v in vendor_results if 21 <= v["score"] <= 50]
    strong_vendors = [v for v in vendor_results if v["score"] >= 80]

    points = [
        f"This assessment covered {len(vendor_results)} vendor(s) with an average external risk "
        f"score of {avg_score}/100.",
    ]
    if critical_vendors:
        points.append(
            f"{len(critical_vendors)} vendor(s) fall into the Critical Impact tier and warrant immediate "
            f"board attention: {', '.join(v['name'] for v in critical_vendors[:5])}."
        )
    if high_vendors:
        points.append(
            f"{len(high_vendors)} vendor(s) fall into the High Impact tier and should be prioritized for "
            f"remediation discussions at the next vendor review cycle: {', '.join(v['name'] for v in high_vendors[:5])}."
        )
    if not critical_vendors and not high_vendors:
        points.append("No vendors in this batch fall into the Critical or High Impact risk tiers.")
    if strong_vendors:
        points.append(
            f"{len(strong_vendors)} vendor(s) demonstrate strong external security posture, requiring only "
            f"routine periodic re-assessment."
        )
    points.append(
        "Recommend formalizing remediation timelines with lower-scoring vendors as a condition of "
        "continued engagement or contract renewal."
    )
    return points

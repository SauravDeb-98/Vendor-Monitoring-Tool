"""
AI Analysis Module
--------------------
Optional layer that turns raw scan + compliance findings into human-readable
narrative for the PDF report. If the visitor supplies their own Claude API
key (entered in the UI for that session only — never persisted or logged),
this calls the Anthropic Messages API to write the narrative. If no key is
supplied, a deterministic rule-based narrative generator produces equivalent
(if less fluent) prose so the tool is fully functional without any key.

Privacy: the API key is read from the per-request payload only, used for a
single call, and discarded. It is never written to disk, never logged, and
never stored server-side beyond the lifetime of the request.
"""
from __future__ import annotations

import httpx

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_MODEL = "claude-sonnet-4-6"


async def generate_vendor_narrative(
    vendor_name: str,
    domain: str,
    score: int,
    tier_label: str,
    findings: list,
    api_key: str | None,
) -> str:
    if api_key:
        try:
            return await _call_claude(vendor_name, domain, score, tier_label, findings, api_key)
        except Exception as exc:
            # Fall back silently to deterministic narrative on any AI failure
            # (bad key, rate limit, network) — the report must still generate.
            return _fallback_narrative(vendor_name, domain, score, tier_label, findings) + \
                f"\n\n[Note: AI-enhanced narrative unavailable this run ({type(exc).__name__}); showing rule-based summary.]"
    return _fallback_narrative(vendor_name, domain, score, tier_label, findings)


async def _call_claude(vendor_name, domain, score, tier_label, findings, api_key: str) -> str:
    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.finding} (NIST: {', '.join(f.nist) or 'n/a'}; "
        f"ISO 27001: {', '.join(f.iso27001) or 'n/a'}; DORA: {', '.join(f.dora) or 'n/a'}; "
        f"GDPR: {', '.join(f.gdpr) or 'n/a'})"
        for f in findings
    ) or "No material findings — external posture appears strong."

    prompt = (
        f"You are a third-party risk analyst writing one paragraph for a vendor risk report.\n"
        f"Vendor: {vendor_name} ({domain})\n"
        f"Risk score: {score}/100 — Tier: {tier_label}\n"
        f"Findings:\n{findings_text}\n\n"
        f"Write a concise (3-5 sentence) professional risk narrative summarizing this vendor's "
        f"external security posture, the most material compliance gaps, and a brief recommendation. "
        f"Be factual and specific to the findings above. Do not invent findings not listed. "
        f"Plain prose, no markdown headers."
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
                "max_tokens": 400,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        result = "\n".join(text_blocks).strip()
        if not result:
            raise ValueError("Empty response from AI")
        return result


def _fallback_narrative(vendor_name, domain, score, tier_label, findings) -> str:
    if not findings:
        return (
            f"{vendor_name} ({domain}) shows a strong external security posture with no material "
            f"findings identified during this scan, resulting in a score of {score}/100 "
            f"({tier_label}). Routine periodic re-assessment is recommended to maintain assurance."
        )

    critical = [f for f in findings if f.severity == "critical"]
    high = [f for f in findings if f.severity == "high"]
    other = [f for f in findings if f.severity in ("medium", "low", "info")]

    parts = [
        f"{vendor_name} ({domain}) received a risk score of {score}/100, placing it in the "
        f"{tier_label} tier."
    ]
    if critical:
        parts.append(
            f"Critical concerns include: {'; '.join(f.finding for f in critical)}. "
            f"These represent severe gaps requiring immediate remediation and vendor engagement."
        )
    if high:
        parts.append(f"High-impact gaps were also observed: {'; '.join(f.finding for f in high)}.")
    if other:
        parts.append(
            f"Additional lower-severity observations: {'; '.join(f.finding for f in other[:4])}"
            f"{' (additional items in matrix below).' if len(other) > 4 else '.'}"
        )
    parts.append(
        "Recommend prioritizing remediation in severity order and requesting updated compliance "
        "attestations from the vendor before contract renewal."
    )
    return " ".join(parts)


def generate_executive_summary(vendor_results: list[dict], api_key: str | None) -> str:
    """vendor_results: list of {name, domain, score, tier} dicts for the whole batch."""
    avg_score = round(sum(v["score"] for v in vendor_results) / len(vendor_results)) if vendor_results else 0
    critical_vendors = [v for v in vendor_results if v["score"] <= 20]
    high_vendors = [v for v in vendor_results if 21 <= v["score"] <= 50]

    summary = (
        f"This assessment covered {len(vendor_results)} vendor(s) with an average risk score of "
        f"{avg_score}/100. "
    )
    if critical_vendors:
        summary += (
            f"{len(critical_vendors)} vendor(s) fall into the Critical Impact tier and require "
            f"immediate attention: {', '.join(v['name'] for v in critical_vendors)}. "
        )
    if high_vendors:
        summary += (
            f"{len(high_vendors)} vendor(s) fall into the High Impact tier: "
            f"{', '.join(v['name'] for v in high_vendors)}. "
        )
    if not critical_vendors and not high_vendors:
        summary += "No vendors fell into the Critical or High Impact tiers in this run."
    return summary

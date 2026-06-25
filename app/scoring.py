"""
Scoring & Risk Tier Engine
----------------------------
Algorithm (deterministic deduction model, chosen over an opaque ML score so
every point lost is traceable to a specific, citable control failure):

  1. Start at a perfect baseline of 100.
  2. For every ComplianceFinding produced by the compliance engine, subtract
     its pre-calibrated weight (weights already reflect severity: critical
     findings like missing HTTPS or high-severity CVEs cost the most;
     informational gaps cost the least).
  3. Clamp the result to [0, 100].
  4. Map the final score to a risk tier using a 5-tier scheme that mirrors
     industry-standard CVSS v3.x severity banding (Critical 90-100%, High
     70-89%, Medium 40-69%, Low 0.1-39%, None 0%), inverted because this
     tool scores security POSTURE (higher = safer) rather than vulnerability
     SEVERITY (higher = worse). The proportional band widths are preserved;
     only the direction is flipped, and "None" becomes "Informational" at
     a perfect 100.

This keeps scoring fully explainable: "vendor X scored 62 because of
findings A (-25), B (-15), C (-7) ..." rather than an unexplainable model
output, which matters when this report needs to survive an audit.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RiskTier:
    label: str
    range_label: str


TIERS = [
    (0, 9, RiskTier("Critical Impact", "0-9")),
    (10, 29, RiskTier("High Impact", "10-29")),
    (30, 59, RiskTier("Medium Impact", "30-59")),
    (60, 99, RiskTier("Low Impact", "60-99")),
    (100, 100, RiskTier("Informational", "100")),
]


def classify_tier(score: int) -> RiskTier:
    for low, high, tier in TIERS:
        if low <= score <= high:
            return tier
    return RiskTier("Unknown", "n/a")


def compute_score(findings: list) -> tuple[int, RiskTier]:
    """findings: list of ComplianceFinding (must have .weight)."""
    total_deduction = sum(f.weight for f in findings)
    score = max(0, min(100, 100 - total_deduction))
    tier = classify_tier(score)
    return score, tier


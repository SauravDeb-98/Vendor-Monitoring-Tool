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
  4. Map the final score to a risk tier using the user-specified thresholds.
     The 71-79 range is an intentional dead zone per the brief; scores
     landing there are flagged for manual analyst review rather than
     silently rounded into a neighboring tier.

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
    (0, 20, RiskTier("Critical Impact", "0-20")),
    (21, 50, RiskTier("High Impact", "21-50")),
    (51, 70, RiskTier("Medium Impact", "51-70")),
    (71, 79, RiskTier("Unassigned — Manual Review Required", "71-79")),
    (80, 95, RiskTier("Low Impact", "80-95")),
    (96, 100, RiskTier("Informational", "96-100")),
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

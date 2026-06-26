"""
Detector Registry & Standard Result Schema
----------------------------------------------
Defines the canonical DetectorRunResult shape that all three detector
modules get adapted into, so the dashboard/export layer can render any
combination of detectors uniformly without per-detector special-casing.

Available detectors:
  - exploitation: Active Exploitation & Advisory Detector (CISA KEV)
  - vulnerability: Vulnerability & Exploit Scanner (existing passive scan)
  - phishing: Phishing & Brand Impersonation Detector (CT log lookalikes)

Note there are 3 detectors, not the 4 originally specified. "Data Breach"
and "Incident & Ransomware Tracker" were merged into the single
"exploitation" detector and renamed to describe what it actually measures
(confirmed active exploitation via CISA KEV), since building true
breach/dark-web/ransomware-extortion detection would require querying
credential-dump databases or dark-web content — a capability this
codebase deliberately does not implement. See exploitation.py's module
docstring for the full rationale.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class DetectorType(str, Enum):
    EXPLOITATION = "exploitation"
    VULNERABILITY = "vulnerability"
    PHISHING = "phishing"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    DNS_INTEGRITY = "dns_integrity"
    WAF_ABSENCE = "waf_absence"
    CORS_CSP = "cors_csp"
    CONCENTRATION_RISK = "concentration_risk"


DETECTOR_LABELS = {
    DetectorType.EXPLOITATION: "Active Exploitation & Advisory Detector",
    DetectorType.VULNERABILITY: "Vulnerability & Exploit Scanner",
    DetectorType.PHISHING: "Phishing & Brand Impersonation Detector",
    DetectorType.SUBDOMAIN_TAKEOVER: "Subdomain Takeover Monitor",
    DetectorType.DNS_INTEGRITY: "DNS Hijacking & Shadow DNS Detector",
    DetectorType.WAF_ABSENCE: "Web Application Firewall (WAF) Absence Detector",
    DetectorType.CORS_CSP: "CORS & Content Security Policy (CSP) Auditor",
    DetectorType.CONCENTRATION_RISK: "Fourth-Party Concentration Infrastructure Mapping",
}

DETECTOR_DESCRIPTIONS = {
    DetectorType.EXPLOITATION: (
        "Checks CISA's Known Exploited Vulnerabilities (KEV) catalog for confirmed, "
        "actively-exploited CVEs and ransomware-campaign links associated with the vendor."
    ),
    DetectorType.VULNERABILITY: (
        "Passive external scan: TLS/certificate health, HTTP security headers, "
        "DNS email-authentication records, and publicly disclosed CVEs."
    ),
    DetectorType.PHISHING: (
        "Generates plausible lookalike/typosquat domains and checks public certificate "
        "transparency logs for evidence of live infrastructure impersonating the vendor's brand."
    ),
    DetectorType.SUBDOMAIN_TAKEOVER: (
        "Checks CT-log-discovered subdomains for dangling CNAME records pointing at "
        "decommissioned third-party cloud services — a classic subdomain-takeover signal."
    ),
    DetectorType.DNS_INTEGRITY: (
        "Snapshots authoritative nameservers (for change detection under continuous "
        "monitoring) and flags unusually large or random-looking subdomain volume."
    ),
    DetectorType.WAF_ABSENCE: (
        "Checks response headers for known WAF/CDN provider signatures to estimate "
        "whether a web application firewall is likely in front of the vendor's site."
    ),
    DetectorType.CORS_CSP: (
        "Audits Content-Security-Policy strength and CORS configuration for wildcard "
        "or overly permissive cross-origin policies."
    ),
    DetectorType.CONCENTRATION_RISK: (
        "Identifies the vendor's underlying hosting/CDN provider via real ASN lookup, "
        "to surface when multiple vendors share the same fourth-party infrastructure."
    ),
}

ALL_DETECTOR_TYPES = [
    DetectorType.EXPLOITATION, DetectorType.VULNERABILITY, DetectorType.PHISHING,
    DetectorType.SUBDOMAIN_TAKEOVER, DetectorType.DNS_INTEGRITY, DetectorType.WAF_ABSENCE,
    DetectorType.CORS_CSP, DetectorType.CONCENTRATION_RISK,
]


@dataclass
class DetectorRunResult:
    """Canonical shape every detector's output gets adapted into for the dashboard."""
    detector: DetectorType
    vendor_name: str
    domain: str
    risk_score: int | None  # 0-100, None if this detector doesn't produce a numeric score
    rating_letter: str | None  # A-F letter grade, derived from risk_score where applicable
    summary: str  # one-line human-readable summary, e.g. "Detected 2 KEV entries, 1 ransomware-linked"
    detail_items: list[dict] = field(default_factory=list)  # detector-specific structured findings
    error: str | None = None


def score_to_letter_grade(score: int) -> str:
    """Maps the existing 0-100 posture score to a letter grade for dashboard display,
    matching this app's 5-tier scheme (see app/scoring.py): higher score = safer."""
    if score >= 96:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 60:
        return "C"
    if score >= 30:
        return "D"
    if score >= 10:
        return "E"
    return "F"

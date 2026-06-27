"""
Business Risk Translation Engine
-----------------------------------
Translates technical security findings (from either the Risk Assessment
tool's ComplianceFinding objects or the Threat Detector's detector result
summaries) into business, regulatory, and financial risk language suitable
for a CISO/CEO-level executive slide deck — the core requirement behind
the "translate deep technical jargon into business impact" instruction.

Design: a deterministic, pattern-matched lookup table (NOT a general NLP
classifier) because the input vocabulary is bounded and known — every
finding string this tool can produce comes from a fixed, enumerable set
of conditions in compliance/engine.py and the eight detector modules in
app/detectors/. Pattern matching (substring / regex on stable prefixes)
rather than exact-string lookup, because several findings embed a dynamic
value (a day count, a CVE count, a specific missing header name) that
varies per scan but doesn't change which business-risk category applies.

This module deliberately has NO network calls and NO AI dependency: it is
the guaranteed-available fallback fallback that the hybrid generation mode
(see deck_narrative.py) degrades to whenever no API key is supplied or an
AI call fails, ensuring the slide deck can ALWAYS be generated with
substantive, non-blank business framing — never a placeholder.
"""
from __future__ import annotations

import re

# Each entry: (compiled pattern matched against the finding text, business
# translation dict). Patterns are checked in order; first match wins, so
# more specific patterns are listed before their more general fallbacks.
_FINDING_TRANSLATIONS: list[tuple[re.Pattern, dict]] = [
    (re.compile(r"vendor domain unreachable", re.I), {
        "business_impact": "The vendor's public-facing infrastructure could not be reached during assessment, "
                            "preventing verification of their security controls entirely.",
        "financial_exposure": "Due diligence cannot be completed or evidenced to auditors or regulators until "
                               "connectivity is restored — a documentation gap in itself under DORA Art. 28.",
        "category": "Availability & Due Diligence",
    }),
    (re.compile(r"does not enforce https|no valid tls", re.I), {
        "business_impact": "Customer and business data sent to this vendor may travel unencrypted, exposing it "
                            "to interception on any network path between your organization and the vendor.",
        "financial_exposure": "A confirmed unencrypted-transit incident triggers mandatory breach notification "
                               "under GDPR Art. 33/34 (fines up to €20M or 4% of global revenue) and breaches "
                               "DORA Art. 30(2)(b) contractual security requirements.",
        "category": "Data-in-Transit Protection",
    }),
    (re.compile(r"tls certificate failed validation", re.I), {
        "business_impact": "The vendor's encryption certificate is invalid or untrusted, meaning encrypted "
                            "connections to them cannot be cryptographically verified as genuine.",
        "financial_exposure": "Undermines the encryption assurance required for GDPR Art. 32(1)(a) and DORA "
                               "Art. 30(2)(b); an auditor would flag this as a control failure, not a finding "
                               "to note and move past.",
        "category": "Data-in-Transit Protection",
    }),
    (re.compile(r"tls certificate expires soon", re.I), {
        "business_impact": "The vendor's encryption certificate is approaching expiration. If it lapses before "
                            "renewal, the connection will fail or downgrade to an insecure state without warning.",
        "financial_exposure": "A lapsed certificate causing a service outage or silent downgrade is an "
                               "operational-resilience gap reportable under DORA's ICT risk management "
                               "requirements (Art. 28-30) if it affects a critical or important function.",
        "category": "Data-in-Transit Protection",
    }),
    (re.compile(r"outdated tls protocol", re.I), {
        "business_impact": "The vendor is using an outdated encryption protocol with known cryptographic "
                            "weaknesses, reducing the real-world strength of data protection in transit.",
        "financial_exposure": "Fails the 'state of the art' encryption standard expected under GDPR Art. 32(1)(a) "
                               "and would be flagged in a SOC 2 or ISO 27001 audit as a cryptography control gap "
                               "(ISO 27001 A.8.24).",
        "category": "Data-in-Transit Protection",
    }),
    (re.compile(r"missing security header: strict-transport-security", re.I), {
        "business_impact": "Browsers connecting to this vendor are not forced into encrypted mode by default, "
                            "leaving a window for attackers to silently downgrade connections to plaintext.",
        "financial_exposure": "A man-in-the-middle compromise enabled by this gap would constitute a reportable "
                               "personal-data breach under GDPR Art. 33, with the vendor's lapse becoming your "
                               "organization's liability under shared processor obligations (Art. 28).",
        "category": "Web Application Security",
    }),
    (re.compile(r"missing security header: content-security-policy", re.I), {
        "business_impact": "The vendor's web application lacks a key browser-side defense against injected "
                            "malicious scripts, increasing the risk of customer-facing data theft or session "
                            "hijacking on their platform.",
        "financial_exposure": "A resulting client-side data theft incident affecting shared customers would "
                               "trigger joint breach-notification obligations and contractual indemnity disputes "
                               "under DORA Art. 30(2)(b).",
        "category": "Web Application Security",
    }),
    (re.compile(r"missing security header", re.I), {
        "business_impact": "The vendor's web application is missing a recommended browser-security control, "
                            "modestly widening the attack surface available to an external attacker.",
        "financial_exposure": "Individually low-severity, but auditors aggregate these gaps as evidence of "
                               "immature secure-development practice under ISO 27001 A.8.26.",
        "category": "Web Application Security",
    }),
    (re.compile(r"no spf record|no dmarc record|dmarc policy set to .none.|no dkim record", re.I), {
        "business_impact": "Email sent appearing to originate from this vendor's domain cannot be reliably "
                            "verified as authentic, making it easier for attackers to impersonate the vendor in "
                            "phishing campaigns targeting your employees or customers.",
        "financial_exposure": "A successful business-email-compromise attack exploiting this gap is a leading "
                               "cause of wire-fraud losses industry-wide, and falls under GDPR Art. 32(1)(b) "
                               "ongoing-confidentiality obligations the vendor has not met.",
        "category": "Email Authentication & Anti-Phishing",
    }),
    (re.compile(r"large exposed subdomain footprint", re.I), {
        "business_impact": "The vendor exposes an unusually large number of subdomains publicly, expanding the "
                            "attack surface an adversary can probe for forgotten, unpatched, or misconfigured "
                            "systems.",
        "financial_exposure": "Each unmanaged subdomain is a potential subdomain-takeover or data-exposure "
                               "incident; ISO 27001 A.8.9 (configuration management) treats unmanaged asset "
                               "sprawl as a documented control failure.",
        "category": "Attack Surface Management",
    }),
    (re.compile(r"high/critical severity cve", re.I), {
        "business_impact": "Publicly disclosed, high-severity software vulnerabilities are associated with this "
                            "vendor's technology stack — the kind of weakness ransomware operators specifically "
                            "scan for and exploit at scale.",
        "financial_exposure": "An exploited critical CVE at a vendor handling your data is a foreseeable risk "
                               "once publicly disclosed; failure to require timely patching breaches DORA Art. "
                               "28-30 ICT third-party risk obligations and weakens any subrogation argument in "
                               "a cyber-insurance claim.",
        "category": "Vulnerability & Patch Management",
    }),
    (re.compile(r"lower-severity cve", re.I), {
        "business_impact": "Lower-severity, publicly known software vulnerabilities are associated with this "
                            "vendor — not immediately critical, but evidence of a patching cadence worth "
                            "confirming contractually.",
        "financial_exposure": "Accumulating unpatched lower-severity CVEs is exactly the pattern regulators and "
                               "auditors flag as inadequate vulnerability management under ISO 27001 A.8.8.",
        "category": "Vulnerability & Patch Management",
    }),
]

# Threat Detector detector_type -> business translation, since that tool's
# results are keyed by detector type + a free-text summary rather than by
# the same ComplianceFinding pattern set used above.
_DETECTOR_TRANSLATIONS: dict[str, dict] = {
    "exploitation": {
        "business_impact": "This checks whether the vendor's known technologies appear on CISA's catalog of "
                            "vulnerabilities with confirmed real-world exploitation, including active "
                            "ransomware campaigns.",
        "financial_exposure": "A vendor on this list represents an active, not theoretical, threat — incident "
                               "response and breach-notification costs scale sharply once exploitation is "
                               "confirmed in the wild rather than merely possible.",
        "category": "Active Exploitation Exposure",
    },
    "vulnerability": {
        "business_impact": "Aggregates the vendor's encryption health, software vulnerabilities, and web "
                            "security configuration into a single posture signal.",
        "financial_exposure": "This is the same category of evidence auditors and cyber-insurers request when "
                               "underwriting third-party risk — a weak score here directly affects insurability "
                               "and audit findings.",
        "category": "Overall Technical Posture",
    },
    "phishing": {
        "business_impact": "Detects lookalike or typosquatted domains that could be used to impersonate this "
                            "vendor in phishing campaigns targeting your employees or shared customers.",
        "financial_exposure": "Brand-impersonation attacks against a known vendor relationship are a common "
                               "precursor to invoice fraud and credential theft, with average wire-fraud losses "
                               "in the hundreds of thousands of dollars per incident industry-wide.",
        "category": "Brand & Phishing Risk",
    },
    "subdomain_takeover": {
        "business_impact": "Checks for abandoned DNS records pointing to deprovisioned cloud resources, which "
                            "an attacker can claim and use to host malicious content under the vendor's "
                            "trusted domain.",
        "financial_exposure": "A successful subdomain takeover lets an attacker serve malware or phishing pages "
                               "from a domain your systems and employees already trust, bypassing normal "
                               "phishing defenses entirely.",
        "category": "Attack Surface Management",
    },
    "dns_integrity": {
        "business_impact": "Monitors for DNS hijacking or unauthorized nameserver changes that could redirect "
                            "traffic intended for the vendor to attacker-controlled infrastructure.",
        "financial_exposure": "DNS hijacking is a single point of failure that can silently redirect all "
                               "traffic, email, and data intended for the vendor — a single successful attack "
                               "compromises every downstream interaction at once.",
        "category": "Attack Surface Management",
    },
    "waf_absence": {
        "business_impact": "Checks whether the vendor has a Web Application Firewall or equivalent protection "
                            "in front of their public-facing applications.",
        "financial_exposure": "Absence of this baseline control is a standard finding in vendor security "
                               "questionnaires and SOC 2 audits; its absence here may itself trigger contractual "
                               "remediation clauses.",
        "category": "Web Application Security",
    },
    "cors_csp": {
        "business_impact": "Checks browser-security configuration that limits how the vendor's application can "
                            "be embedded or scripted by other sites, a key defense against client-side data "
                            "theft.",
        "financial_exposure": "Gaps here are routinely exploited in supply-chain-style attacks against shared "
                               "customers, where a flaw at the vendor is leveraged to attack your users directly.",
        "category": "Web Application Security",
    },
    "concentration_risk": {
        "business_impact": "Identifies whether this vendor shares critical infrastructure (cloud provider, CDN, "
                            "DNS provider) with other vendors in your portfolio, creating correlated failure risk.",
        "financial_exposure": "Regulators increasingly require mapping of fourth-party concentration risk (DORA "
                               "Art. 29) — an outage at a shared infrastructure provider can take down multiple "
                               "vendors simultaneously, multiplying business impact beyond any single contract.",
        "category": "Concentration & Resilience Risk",
    },
}

_DEFAULT_TRANSLATION = {
    "business_impact": "This finding represents a deviation from standard security baseline configuration "
                        "for externally-facing systems.",
    "financial_exposure": "Individually modest, but contributes to the vendor's overall risk score used in "
                           "contractual and audit decisions.",
    "category": "General Security Posture",
}


def translate_finding(finding_text: str) -> dict:
    """
    Returns {business_impact, financial_exposure, category} for a
    ComplianceFinding's finding text (Risk Assessment tool). Falls back to
    a generic-but-substantive translation (never an empty/placeholder
    result) if no specific pattern matches, since an unmatched finding
    must never produce a blank slide.
    """
    for pattern, translation in _FINDING_TRANSLATIONS:
        if pattern.search(finding_text):
            return translation
    return _DEFAULT_TRANSLATION


def translate_detector(detector_type: str) -> dict:
    """Same purpose as translate_finding, keyed by Threat Detector
    detector_type string instead of free-text finding."""
    return _DETECTOR_TRANSLATIONS.get(detector_type, _DEFAULT_TRANSLATION)


SEVERITY_BUSINESS_LABEL = {
    "critical": "Board-Level Urgency",
    "high": "Executive Attention Required",
    "medium": "Operational Risk — Track to Resolution",
    "low": "Minor — Routine Remediation",
    "info": "Informational",
}


def severity_business_label(severity: str) -> str:
    return SEVERITY_BUSINESS_LABEL.get(severity.lower(), "Operational Risk — Track to Resolution")

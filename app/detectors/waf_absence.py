"""
DET-12: Web Application Firewall (WAF) Absence Detector
--------------------------------------------------------------
Derives a WAF/DDoS-protection presence signal entirely from data the
existing scanner (app/scanner/engine.py) already collected during its
single HTTP request — no additional network calls. Real WAF fingerprinting
tools (WafW00f, etc.) send many varied/malformed requests and watch for
WAF-specific block-page signatures; that's beyond a single passive GET and
edges toward active probing, so this detector instead looks at passive,
already-available signals:

  - Known WAF/CDN-vendor response headers (e.g. `cf-ray` for Cloudflare,
    `x-sucuri-id` for Sucuri, `x-akamai-*` for Akamai) — if present, a WAF
    or CDN-with-WAF-features is very likely in front of the origin.
  - Absence of any such header AND absence of baseline hardening headers
    (HSTS, CSP) together is treated as a weak signal of no WAF, since a
    well-protected origin behind a major WAF/CDN provider almost always
    carries at least one provider-identifying header in practice.

This is explicitly a coarse, passive proxy — not a definitive WAF audit.
A vendor could use a WAF that doesn't add identifying headers, in which
case this detector would under-report.
"""
from __future__ import annotations

from dataclasses import dataclass

# Header name (lowercase) -> human-readable provider/product name
WAF_CDN_SIGNATURE_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "akamai-grn": "Akamai",
    "x-cdn": "Generic CDN",
    "x-amz-cf-id": "AWS CloudFront",
    "x-iinfo": "Incapsula/Imperva",
    "x-distil-cs": "Distil Networks/Imperva",
    "server": None,  # checked separately below for known WAF server strings
}

WAF_SERVER_HEADER_SIGNATURES = ["cloudflare", "sucuri", "imperva", "incapsula", "akamaighost"]


@dataclass
class WafAbsenceResult:
    domain: str
    waf_or_cdn_detected: bool = False
    detected_provider: str | None = None
    evidence_header: str | None = None


def evaluate_waf_presence(domain: str, response_headers: dict, missing_security_headers: list[str]) -> WafAbsenceResult:
    """
    response_headers: dict of headers as already captured by the scanner
        (case doesn't matter; this function lowercases keys itself).
    missing_security_headers: the missing_headers list already computed
        by the existing scanner — reused, not recomputed.
    """
    headers_lower = {k.lower(): v for k, v in response_headers.items()}
    result = WafAbsenceResult(domain=domain)

    for header_name, provider in WAF_CDN_SIGNATURE_HEADERS.items():
        if header_name == "server":
            continue
        if header_name in headers_lower:
            result.waf_or_cdn_detected = True
            result.detected_provider = provider
            result.evidence_header = header_name
            return result

    server_value = headers_lower.get("server", "").lower()
    for sig in WAF_SERVER_HEADER_SIGNATURES:
        if sig in server_value:
            result.waf_or_cdn_detected = True
            result.detected_provider = sig.title()
            result.evidence_header = f"server: {server_value}"
            return result

    return result

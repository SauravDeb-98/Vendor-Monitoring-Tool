"""
Detector Orchestrator
-------------------------
Runs one or more selected detectors for a single vendor in parallel,
then adapts each detector's native output into the standard
DetectorRunResult shape via each module's to_standard_result().

Several detectors (vulnerability, subdomain_takeover, dns_integrity,
waf_absence, cors_csp, concentration_risk) all depend on the SAME base
passive scan (app/scanner/engine.py's ScanResult — TLS, headers, DNS,
CT-log subdomains). Rather than each detector independently re-running
that scan (which would multiply external API calls — NVD, crt.sh — by
6x for no benefit), this orchestrator runs the base scan exactly ONCE per
vendor and feeds all six lightweight detectors from that single result.
Only exploitation (CISA KEV) and phishing (independent typosquat
generation + crt.sh queries on DIFFERENT candidate domains) genuinely
need their own separate work.

This is the single entry point the API layer and the continuous
monitoring worker both call, so ad-hoc scans and scheduled monitoring
runs share identical detector logic.
"""
from __future__ import annotations

import asyncio

from app.detectors.registry import DetectorType, DetectorRunResult, ALL_DETECTOR_TYPES
from app.detectors import exploitation, vulnerability, phishing
from app.detectors import subdomain_takeover, dns_integrity, waf_absence, cors_csp, concentration_risk
from app.scanner.engine import scan_vendor
from app import detector_cache

# Detectors that derive from the single shared base scan rather than
# performing their own independent network work.
_SCAN_DERIVED_TYPES = {
    DetectorType.VULNERABILITY, DetectorType.SUBDOMAIN_TAKEOVER, DetectorType.DNS_INTEGRITY,
    DetectorType.WAF_ABSENCE, DetectorType.CORS_CSP, DetectorType.CONCENTRATION_RISK,
}
# Detectors that need their own independent work (not derivable from the base scan).
_INDEPENDENT_TYPES = {DetectorType.EXPLOITATION, DetectorType.PHISHING}


def _adapt_subdomain_takeover(raw) -> DetectorRunResult:
    if raw.error:
        summary = f"Could not complete check: {raw.error}"
    elif not raw.findings:
        summary = f"No dangling-CNAME patterns found ({raw.subdomains_checked} subdomain(s) checked)."
    else:
        summary = f"{len(raw.findings)} subdomain(s) with dangling-CNAME-pattern CNAMEs found — verify with the named provider."
    return DetectorRunResult(
        detector=DetectorType.SUBDOMAIN_TAKEOVER, vendor_name="", domain=raw.domain,
        risk_score=None, rating_letter=None, summary=summary,
        detail_items=[{"subdomain": f.subdomain, "cname_target": f.cname_target, "matched_service": f.matched_service} for f in raw.findings],
        error=raw.error,
    )


def _adapt_dns_integrity(raw) -> DetectorRunResult:
    parts = []
    if raw.nameserver_change_detected:
        parts.append("Nameserver change detected since last scan")
    if raw.random_looking_subdomain_count:
        parts.append(f"{raw.random_looking_subdomain_count} random-looking subdomain(s) of {raw.subdomain_count} total")
    summary = "; ".join(parts) if parts else f"No anomalies detected ({len(raw.nameservers)} nameserver(s) on record)."
    detail_items = [{"nameservers": raw.nameservers, "subdomain_count": raw.subdomain_count,
                      "random_looking_count": raw.random_looking_subdomain_count,
                      "nameserver_change_detected": raw.nameserver_change_detected}]
    return DetectorRunResult(
        detector=DetectorType.DNS_INTEGRITY, vendor_name="", domain=raw.domain,
        risk_score=None, rating_letter=None, summary=summary, detail_items=detail_items, error=raw.error,
    )


def _adapt_waf_absence(raw) -> DetectorRunResult:
    if raw.waf_or_cdn_detected:
        summary = f"WAF/CDN likely present ({raw.detected_provider}, evidence: {raw.evidence_header})."
    else:
        summary = "No WAF/CDN provider signature detected in response headers — may indicate no WAF, or a WAF that doesn't expose identifying headers."
    return DetectorRunResult(
        detector=DetectorType.WAF_ABSENCE, vendor_name="", domain=raw.domain,
        risk_score=None, rating_letter=None, summary=summary,
        detail_items=[{"waf_or_cdn_detected": raw.waf_or_cdn_detected, "provider": raw.detected_provider, "evidence": raw.evidence_header}],
        error=None,
    )


def _adapt_cors_csp(raw) -> DetectorRunResult:
    if not raw.findings:
        summary = "No CORS/CSP misconfigurations detected."
    else:
        high = [f for f in raw.findings if f.severity == "high"]
        summary = f"{len(raw.findings)} finding(s)" + (f", {len(high)} high-severity" if high else "")
    return DetectorRunResult(
        detector=DetectorType.CORS_CSP, vendor_name="", domain=raw.domain,
        risk_score=None, rating_letter=None, summary=summary,
        detail_items=[{"finding": f.finding, "severity": f.severity} for f in raw.findings],
        error=None,
    )


def _adapt_concentration_risk(raw) -> DetectorRunResult:
    if raw.error:
        summary = f"Could not complete check: {raw.error}"
    elif raw.detected_provider:
        summary = f"Hosted on {raw.detected_provider} ({raw.evidence})."
    else:
        summary = "Could not determine hosting provider via ASN lookup, reverse DNS, or header signatures."
    return DetectorRunResult(
        detector=DetectorType.CONCENTRATION_RISK, vendor_name="", domain=raw.domain,
        risk_score=None, rating_letter=None, summary=summary,
        detail_items=[{"resolved_ips": raw.resolved_ips, "asn": raw.asn, "asn_organization": raw.asn_organization,
                        "detected_provider": raw.detected_provider, "evidence": raw.evidence}],
        error=raw.error,
    )


async def _run_scan_derived_detectors(
    vendor_name: str, domain: str, selected: set[DetectorType],
) -> dict[DetectorType, DetectorRunResult]:
    """Runs the single shared base scan once, then derives results for
    every selected scan-derived detector type from it."""
    out: dict[DetectorType, DetectorRunResult] = {}
    try:
        scan = await scan_vendor(vendor_name, domain)
    except Exception as exc:
        error_result = lambda dt: DetectorRunResult(
            detector=dt, vendor_name=vendor_name, domain=domain, risk_score=None, rating_letter=None,
            summary=f"Base scan failed: {type(exc).__name__}", detail_items=[], error=type(exc).__name__,
        )
        return {dt: error_result(dt) for dt in selected if dt in _SCAN_DERIVED_TYPES}

    if DetectorType.VULNERABILITY in selected:
        from app.compliance.engine import evaluate_compliance, deduplicate_and_cap
        from app.scoring import compute_score
        findings = deduplicate_and_cap(evaluate_compliance(scan))
        score, tier = compute_score(findings)
        from app.detectors.registry import score_to_letter_grade
        tier_label = tier.label if tier else "Unknown"
        summary = (f"No findings — strong external posture (score {score}/100, {tier_label})." if not findings
                    else f"{len(findings)} finding(s); score {score}/100 ({tier_label}).")
        out[DetectorType.VULNERABILITY] = DetectorRunResult(
            detector=DetectorType.VULNERABILITY, vendor_name=vendor_name, domain=domain,
            risk_score=score, rating_letter=score_to_letter_grade(score), summary=summary,
            detail_items=[{"finding": f.finding, "severity": f.severity, "nist": f.nist, "iso27001": f.iso27001,
                            "dora": f.dora, "gdpr": f.gdpr, "recommendation": f.recommendation} for f in findings],
            error=None,
        )

    if DetectorType.SUBDOMAIN_TAKEOVER in selected:
        raw = await subdomain_takeover.run_subdomain_takeover_check(domain, scan.subdomain_sprawl)
        result = _adapt_subdomain_takeover(raw)
        result.vendor_name = vendor_name
        out[DetectorType.SUBDOMAIN_TAKEOVER] = result

    if DetectorType.DNS_INTEGRITY in selected:
        raw = await dns_integrity.run_dns_integrity_check(domain, scan.subdomain_sprawl)
        result = _adapt_dns_integrity(raw)
        result.vendor_name = vendor_name
        out[DetectorType.DNS_INTEGRITY] = result

    if DetectorType.WAF_ABSENCE in selected:
        raw = waf_absence.evaluate_waf_presence(domain, scan.raw_headers, scan.missing_headers)
        result = _adapt_waf_absence(raw)
        result.vendor_name = vendor_name
        out[DetectorType.WAF_ABSENCE] = result

    if DetectorType.CORS_CSP in selected:
        raw = cors_csp.evaluate_cors_csp(domain, scan.raw_headers)
        result = _adapt_cors_csp(raw)
        result.vendor_name = vendor_name
        out[DetectorType.CORS_CSP] = result

    if DetectorType.CONCENTRATION_RISK in selected:
        raw = await concentration_risk.run_concentration_check(domain, scan.raw_headers)
        result = _adapt_concentration_risk(raw)
        result.vendor_name = vendor_name
        out[DetectorType.CONCENTRATION_RISK] = result

    return out


async def _run_one_independent(detector_type: DetectorType, vendor_name: str, domain: str) -> DetectorRunResult:
    try:
        if detector_type == DetectorType.EXPLOITATION:
            raw = await exploitation.run_exploitation_detector(vendor_name, domain)
            return exploitation.to_standard_result(raw)
        elif detector_type == DetectorType.PHISHING:
            raw = await phishing.run_phishing_detector(vendor_name, domain)
            return phishing.to_standard_result(raw)
        else:
            raise ValueError(f"Not an independent detector type: {detector_type}")
    except Exception as exc:
        return DetectorRunResult(
            detector=detector_type, vendor_name=vendor_name, domain=domain, risk_score=None, rating_letter=None,
            summary=f"Detector failed to run: {type(exc).__name__}", detail_items=[], error=str(type(exc).__name__),
        )


async def run_detectors_for_vendor(
    vendor_name: str,
    domain: str,
    detector_types: list[DetectorType] | None = None,
    use_cache: bool = True,
) -> list[DetectorRunResult]:
    """
    detector_types=None or empty means "all detectors" — runs every
    available detector in parallel.

    use_cache=True (default, for ad-hoc scans) reuses any cached result
    for the same (domain, detector) within the last 24 hours. Continuous
    monitoring's scheduler passes use_cache=False to always get a fresh
    data point on each scheduled run.
    """
    selected = set(detector_types) if detector_types else set(ALL_DETECTOR_TYPES)
    results: dict[DetectorType, DetectorRunResult] = {}
    to_fetch: set[DetectorType] = set()

    if use_cache:
        for dt in selected:
            cached = detector_cache.get_cached(domain, dt)
            if cached is not None:
                results[dt] = cached
            else:
                to_fetch.add(dt)
    else:
        to_fetch = set(selected)

    scan_derived_to_fetch = to_fetch & _SCAN_DERIVED_TYPES
    independent_to_fetch = to_fetch & _INDEPENDENT_TYPES

    tasks = []
    if scan_derived_to_fetch:
        tasks.append(_run_scan_derived_detectors(vendor_name, domain, scan_derived_to_fetch))
    for dt in independent_to_fetch:
        tasks.append(_run_one_independent(dt, vendor_name, domain))

    fetched = await asyncio.gather(*tasks) if tasks else []
    for item in fetched:
        if isinstance(item, dict):
            results.update(item)
        else:  # a single DetectorRunResult from an independent detector
            results[item.detector] = item

    if use_cache:
        for dt, result in results.items():
            if dt in to_fetch:
                detector_cache.set_cached(domain, dt, result)

    # Preserve the order the caller requested (or registry order for "all").
    ordered = detector_types if detector_types else ALL_DETECTOR_TYPES
    return [results[dt] for dt in ordered if dt in results]


async def run_detectors_for_vendors(
    vendors: list,  # list of objects with .name and .domain
    detector_types: list[DetectorType] | None = None,
    concurrency: int = 4,
    use_cache: bool = True,
) -> dict[str, list[DetectorRunResult]]:
    """Runs the selected detector(s) across multiple vendors, bounded by
    concurrency to avoid hammering external APIs on large batch uploads.
    Returns {domain: [DetectorRunResult, ...]}."""
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[DetectorRunResult]] = {}

    async def _bounded(v):
        async with semaphore:
            results[v.domain] = await run_detectors_for_vendor(v.name, v.domain, detector_types, use_cache=use_cache)

    await asyncio.gather(*(_bounded(v) for v in vendors))
    return results

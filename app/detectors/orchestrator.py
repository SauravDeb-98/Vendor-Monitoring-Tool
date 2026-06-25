"""
Detector Orchestrator
-------------------------
Runs one or more selected detectors for a single vendor in parallel
(asyncio.gather), then adapts each detector's native output into the
standard DetectorRunResult shape via each module's to_standard_result().

This is the single entry point the API layer and the continuous
monitoring worker both call, so ad-hoc scans and scheduled monitoring
runs share identical detector logic.
"""
from __future__ import annotations

import asyncio

from app.detectors.registry import DetectorType, DetectorRunResult, ALL_DETECTOR_TYPES
from app.detectors import exploitation, vulnerability, phishing
from app import detector_cache


async def _run_one(detector_type: DetectorType, vendor_name: str, domain: str, use_cache: bool = True) -> DetectorRunResult:
    if use_cache:
        cached = detector_cache.get_cached(domain, detector_type)
        if cached is not None:
            return cached

    try:
        if detector_type == DetectorType.EXPLOITATION:
            raw = await exploitation.run_exploitation_detector(vendor_name, domain)
            result = exploitation.to_standard_result(raw)
        elif detector_type == DetectorType.VULNERABILITY:
            raw = await vulnerability.run_vulnerability_detector(vendor_name, domain)
            result = vulnerability.to_standard_result(raw)
        elif detector_type == DetectorType.PHISHING:
            raw = await phishing.run_phishing_detector(vendor_name, domain)
            result = phishing.to_standard_result(raw)
        else:
            raise ValueError(f"Unknown detector type: {detector_type}")
    except Exception as exc:
        # Defensive: a single detector's unexpected failure should not take
        # down the whole batch — surface it as an error result instead.
        return DetectorRunResult(
            detector=detector_type,
            vendor_name=vendor_name,
            domain=domain,
            risk_score=None,
            rating_letter=None,
            summary=f"Detector failed to run: {type(exc).__name__}",
            detail_items=[],
            error=str(type(exc).__name__),
        )

    if use_cache:
        detector_cache.set_cached(domain, detector_type, result)
    return result


async def run_detectors_for_vendor(
    vendor_name: str,
    domain: str,
    detector_types: list[DetectorType] | None = None,
    use_cache: bool = True,
) -> list[DetectorRunResult]:
    """
    detector_types=None or empty means "all detectors" — runs every
    available detector in parallel, per the requirement that selecting
    "All Detectors" triggers a single parallel query batch rather than
    sequential per-detector calls.

    use_cache=True (default, for ad-hoc scans) reuses any cached result
    for the same (domain, detector) within the last 24 hours. Continuous
    monitoring's scheduler passes use_cache=False to always get a fresh
    data point on each scheduled run.
    """
    selected = detector_types if detector_types else ALL_DETECTOR_TYPES
    tasks = [_run_one(dt, vendor_name, domain, use_cache=use_cache) for dt in selected]
    return await asyncio.gather(*tasks)


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

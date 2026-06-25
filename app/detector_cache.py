"""
Ad-Hoc Scan Result Cache
-----------------------------
Caches detector results for 24 hours, keyed by (domain, detector_type),
so repeated ad-hoc lookups of the same vendor within that window reuse
the prior result instead of re-querying external APIs (NVD, CISA KEV,
crt.sh) — per the spec's requirement to optimize API token/quota usage.

This is a simple in-memory cache (a dict with TTL checks), not a
persistent store — it resets on server restart, which is an acceptable
tradeoff for a cost/quota optimization rather than a correctness
requirement. Continuous monitoring's score HISTORY (a different thing —
the time-series trend data) is persisted separately in monitoring.sqlite3
via app/monitoring/store.py and is not affected by this cache.

Note: this cache is intentionally bypassed for continuous-monitoring
scheduled runs (app/monitoring/scheduler.py calls the orchestrator
directly), since the entire point of continuous monitoring is to capture
a fresh data point on each scheduled run — caching would defeat that.
"""
from __future__ import annotations

import time

from app.detectors.registry import DetectorRunResult, DetectorType

CACHE_TTL_SECONDS = 24 * 60 * 60  # 24 hours

_cache: dict[tuple[str, str], tuple[float, DetectorRunResult]] = {}


def _cache_key(domain: str, detector_type: DetectorType) -> tuple[str, str]:
    return (domain.lower(), detector_type.value)


def get_cached(domain: str, detector_type: DetectorType) -> DetectorRunResult | None:
    key = _cache_key(domain, detector_type)
    entry = _cache.get(key)
    if entry is None:
        return None
    cached_at, result = entry
    if time.time() - cached_at > CACHE_TTL_SECONDS:
        del _cache[key]
        return None
    return result


def set_cached(domain: str, detector_type: DetectorType, result: DetectorRunResult) -> None:
    key = _cache_key(domain, detector_type)
    _cache[key] = (time.time(), result)


def clear_expired() -> int:
    """Removes expired entries; returns count removed. Not required for
    correctness (get_cached already checks TTL lazily) but keeps memory
    bounded for a long-running process with many distinct vendors over time."""
    now = time.time()
    expired_keys = [k for k, (cached_at, _r) in _cache.items() if now - cached_at > CACHE_TTL_SECONDS]
    for k in expired_keys:
        del _cache[k]
    return len(expired_keys)


def cache_stats() -> dict:
    return {"total_entries": len(_cache)}

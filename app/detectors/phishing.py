"""
Phishing & Brand Impersonation Detector
-------------------------------------------
Passively detects potential lookalike/typosquat domains targeting a
vendor's brand, using only public data sources:

  1. Generates a set of plausible typosquat variants of the vendor's real
     domain (character substitution, omission, transposition, common
     homoglyphs, hyphenation, and popular TLD swaps).
  2. Checks which variants actually exist by querying public Certificate
     Transparency logs (crt.sh) — if a certificate has been issued for a
     lookalike domain, that's public, verifiable evidence the domain is
     live and was provisioned for HTTPS, which is a real (if imperfect)
     signal of active or potential phishing infrastructure.
  3. For variants found to exist, performs a lightweight passive HTTP
     check (reachable? redirects to the real vendor domain? — the latter
     is common for legitimately-owned defensive registrations, which this
     module flags as lower priority than an unrelated live site).

This is entirely passive: no active probing beyond a standard HTTPS GET,
no WHOIS brute-forcing, no scanning of registrar databases. It will
under-report (many real phishing domains never get a certificate, or use
domains not derivable from simple pattern rules) and can over-report
(some flagged variants may be unrelated, legitimately-registered domains
that happen to match a pattern, or the vendor's own defensive
registrations) — results should be treated as leads for human review,
not confirmed-malicious findings.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx

CRTSH_API = "https://crt.sh/"
HTTP_TIMEOUT = httpx.Timeout(8.0, connect=5.0)

HOMOGLYPHS = {
    "o": ["0"], "i": ["1", "l"], "l": ["1", "i"], "e": ["3"],
    "a": ["4", "@"], "s": ["5"], "g": ["9"],
}

COMMON_TLD_SWAPS = ["net", "org", "co", "io", "info", "biz", "cc"]


@dataclass
class LookalikeDomainFinding:
    candidate_domain: str
    pattern_type: str  # e.g. "character_substitution", "tld_swap", "hyphenation"
    certificate_found: bool
    reachable: bool = False
    redirects_to_real_domain: bool = False


@dataclass
class PhishingDetectorResult:
    vendor_name: str
    real_domain: str
    candidates_checked: int = 0
    findings: list[LookalikeDomainFinding] = field(default_factory=list)
    inconclusive_count: int = 0  # candidates where the certificate check itself failed
    error: str | None = None


def _split_domain(domain: str) -> tuple[str, str]:
    """Returns (name, tld) e.g. 'example.com' -> ('example', 'com')."""
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return domain, ""


def _generate_candidates(domain: str) -> list[tuple[str, str]]:
    """Returns list of (candidate_domain, pattern_type)."""
    name, tld = _split_domain(domain)
    if not name or not tld:
        return []

    candidates: set[tuple[str, str]] = set()

    # Character substitution via homoglyphs
    for i, ch in enumerate(name):
        for sub in HOMOGLYPHS.get(ch, []):
            variant = name[:i] + sub + name[i + 1:]
            candidates.add((f"{variant}.{tld}", "character_substitution"))

    # Character omission (drop one character)
    for i in range(len(name)):
        if len(name) > 3:  # avoid degenerate very-short names
            variant = name[:i] + name[i + 1:]
            candidates.add((f"{variant}.{tld}", "character_omission"))

    # Adjacent character transposition
    for i in range(len(name) - 1):
        variant = name[:i] + name[i + 1] + name[i] + name[i + 2:]
        candidates.add((f"{variant}.{tld}", "transposition"))

    # Character doubling (common typo)
    for i, ch in enumerate(name):
        variant = name[:i] + ch + ch + name[i + 1:]
        candidates.add((f"{variant}.{tld}", "character_doubling"))

    # Hyphenation insertion (common phishing pattern: "vendor-secure.com")
    candidates.add((f"{name}-secure.{tld}", "hyphenation_suffix"))
    candidates.add((f"{name}-login.{tld}", "hyphenation_suffix"))
    candidates.add((f"{name}-verify.{tld}", "hyphenation_suffix"))
    candidates.add((f"secure-{name}.{tld}", "hyphenation_prefix"))

    # TLD swaps
    for alt_tld in COMMON_TLD_SWAPS:
        if alt_tld != tld:
            candidates.add((f"{name}.{alt_tld}", "tld_swap"))

    return sorted(candidates)


async def _check_certificate_exists(client: httpx.AsyncClient, domain: str) -> bool | None:
    """Returns True/False for a successful check, or None if the check
    itself failed (e.g. network error) — distinct from a successful check
    that found no certificate, so callers can tell the difference between
    "confirmed absent" and "could not determine"."""
    try:
        resp = await client.get(CRTSH_API, params={"q": domain, "output": "json"}, timeout=10)
        if resp.status_code == 200:
            if not resp.text.strip():
                return False
            entries = resp.json()
            return len(entries) > 0
        return None  # non-200 response: inconclusive, not "confirmed absent"
    except Exception:
        return None


async def _check_reachability(client: httpx.AsyncClient, domain: str, real_domain: str) -> tuple[bool, bool]:
    """Returns (reachable, redirects_to_real_domain)."""
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{domain}", follow_redirects=True, timeout=8)
            final_host = str(resp.url.host or "").lower()
            redirects_to_real = real_domain.lower() in final_host
            return True, redirects_to_real
        except httpx.HTTPError:
            continue
    return False, False


async def run_phishing_detector(vendor_name: str, real_domain: str, max_candidates_to_check: int = 40) -> PhishingDetectorResult:
    result = PhishingDetectorResult(vendor_name=vendor_name, real_domain=real_domain)
    try:
        candidates = _generate_candidates(real_domain)[:max_candidates_to_check]
        result.candidates_checked = len(candidates)

        async with httpx.AsyncClient(headers={"User-Agent": "VendorRiskScanner/1.0 (passive OSINT)"}) as client:
            semaphore = asyncio.Semaphore(8)

            async def _check_one(candidate_domain: str, pattern_type: str) -> tuple[LookalikeDomainFinding | None, bool]:
                """Returns (finding_or_none, was_inconclusive)."""
                async with semaphore:
                    cert_found = await _check_certificate_exists(client, candidate_domain)
                    if cert_found is None:
                        return None, True  # inconclusive — couldn't determine
                    if not cert_found:
                        return None, False  # confirmed: no certificate exists
                    reachable, redirects_to_real = await _check_reachability(client, candidate_domain, real_domain)
                    finding = LookalikeDomainFinding(
                        candidate_domain=candidate_domain,
                        pattern_type=pattern_type,
                        certificate_found=True,
                        reachable=reachable,
                        redirects_to_real_domain=redirects_to_real,
                    )
                    return finding, False

            tasks = [_check_one(d, p) for d, p in candidates]
            outcomes = await asyncio.gather(*tasks, return_exceptions=False)
            result.findings = [f for f, _inconclusive in outcomes if f is not None]
            result.inconclusive_count = sum(1 for _f, inconclusive in outcomes if inconclusive)

            if result.candidates_checked > 0 and result.inconclusive_count == result.candidates_checked:
                result.error = (
                    "Certificate transparency lookup (crt.sh) was unreachable for all candidates — "
                    "results are inconclusive, not a confirmed absence of lookalike domains."
                )

        # Sort: live + not redirecting to the real domain (highest concern) first
        result.findings.sort(key=lambda f: (not f.reachable, f.redirects_to_real_domain))
    except Exception as exc:
        result.error = f"Phishing detector error: {type(exc).__name__}"
    return result


def to_standard_result(result: PhishingDetectorResult) -> "DetectorRunResult":
    from app.detectors.registry import DetectorRunResult, DetectorType

    if result.error and not result.findings:
        summary = result.error
    elif not result.findings:
        summary = f"No live lookalike infrastructure found ({result.candidates_checked} candidate domains checked)."
    else:
        concerning = [f for f in result.findings if f.reachable and not f.redirects_to_real_domain]
        summary = f"{len(result.findings)} lookalike domain(s) with certificates found"
        if concerning:
            summary += f"; {len(concerning)} live and NOT redirecting to the real vendor site"

    return DetectorRunResult(
        detector=DetectorType.PHISHING,
        vendor_name=result.vendor_name,
        domain=result.real_domain,
        risk_score=None,
        rating_letter=None,
        summary=summary,
        detail_items=[
            {
                "candidate_domain": f.candidate_domain,
                "pattern_type": f.pattern_type,
                "certificate_found": f.certificate_found,
                "reachable": f.reachable,
                "redirects_to_real_domain": f.redirects_to_real_domain,
            }
            for f in result.findings
        ],
        error=result.error if result.findings else None,  # don't double-surface total-failure error as both summary and error
    )

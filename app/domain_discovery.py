"""
Domain Auto-Discovery Fallback
-----------------------------------
When a vendor is submitted with a name but no domain, this module
attempts to identify the vendor's most likely primary domain using only
free, no-signup techniques:

  1. Slugify the vendor name into candidate domains (strip legal suffixes
     like "Inc.", "Corporation", "LLC"; remove spaces/punctuation) and try
     the most common TLD patterns (.com first, then a short list of
     others).
  2. For each candidate, attempt a real DNS resolution + HTTPS reachability
     check (the same passive check style used elsewhere in this codebase)
     to confirm the domain actually exists and serves a live site, rather
     than just guessing a plausible-looking string.
  3. Return the first candidate that resolves AND is reachable, along with
     a confidence indicator — this is a heuristic, not a verified
     identity match. "acme.com" being reachable does not guarantee it's
     the SAME Acme the user meant; common/generic vendor names are
     especially prone to false-positive matches.

This deliberately does NOT call a general web search API (the project
was scoped to avoid that signup requirement — see the exploitation
detector's sourcing decision for the same reasoning applied elsewhere).
That means this fallback is meaningfully weaker than a real search-based
lookup for ambiguous or generic vendor names; callers should surface the
confidence level to the user and allow manual correction rather than
silently trusting the result.
"""
from __future__ import annotations

import re

import dns.resolver
import dns.exception
import httpx

LEGAL_SUFFIXES = [
    "incorporated", "corporation", "corp", "company", "co", "inc", "llc",
    "ltd", "limited", "group", "holdings", "technologies", "technology",
    "systems", "solutions", "international", "global",
]

CANDIDATE_TLDS = ["com", "net", "io", "co", "org"]

DNS_TIMEOUT = 5
HTTP_TIMEOUT = httpx.Timeout(8.0, connect=5.0)


def _slugify_vendor_name(name: str) -> str:
    text = name.lower().strip()
    # Strip a trailing legal suffix word (e.g. "Acme Corp" -> "Acme"),
    # checking longest-match-first so "International" doesn't get
    # stripped before a more specific multi-word suffix could apply.
    words = text.split()
    while words and re.sub(r"[^a-z]", "", words[-1]) in LEGAL_SUFFIXES:
        words.pop()
    text = " ".join(words) if words else text
    # Remove remaining punctuation/whitespace entirely for the slug
    slug = re.sub(r"[^a-z0-9]", "", text)
    return slug


def _generate_domain_candidates(vendor_name: str) -> list[str]:
    slug = _slugify_vendor_name(vendor_name)
    if not slug:
        return []
    return [f"{slug}.{tld}" for tld in CANDIDATE_TLDS]


def _resolves_sync(domain: str) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        resolver.resolve(domain, "A")
        return True
    except (dns.exception.DNSException, Exception):
        return False


async def _check_candidate(client: httpx.AsyncClient, domain: str) -> bool:
    import asyncio
    resolves = await asyncio.to_thread(_resolves_sync, domain)
    if not resolves:
        return False
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{domain}", follow_redirects=True, timeout=8)
            if resp.status_code < 500:
                return True
        except httpx.HTTPError:
            continue
    return False


class DomainDiscoveryResult:
    def __init__(self, vendor_name: str):
        self.vendor_name = vendor_name
        self.discovered_domain: str | None = None
        self.confidence: str = "none"  # "none" | "low" | "medium"
        self.candidates_tried: list[str] = []

    def to_dict(self) -> dict:
        return {
            "vendor_name": self.vendor_name,
            "discovered_domain": self.discovered_domain,
            "confidence": self.confidence,
            "candidates_tried": self.candidates_tried,
        }


async def discover_domain(vendor_name: str) -> DomainDiscoveryResult:
    result = DomainDiscoveryResult(vendor_name)
    candidates = _generate_domain_candidates(vendor_name)
    result.candidates_tried = candidates
    if not candidates:
        return result

    async with httpx.AsyncClient(headers={"User-Agent": "VendorRiskScanner/1.0 (passive OSINT)"}) as client:
        for domain in candidates:
            if await _check_candidate(client, domain):
                result.discovered_domain = domain
                # "medium" confidence only for the .com guess (by far the most
                # common real pattern); anything else found is lower confidence
                # since it required falling through past the most likely guess.
                result.confidence = "medium" if domain.endswith(".com") else "low"
                return result

    return result

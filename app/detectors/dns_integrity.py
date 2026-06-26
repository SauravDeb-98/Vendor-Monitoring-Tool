"""
DET-09: DNS Hijacking & Shadow DNS Detector
------------------------------------------------
Passive checks for two signals associated with DNS hijacking / shadow DNS:

  1. Authoritative nameserver (NS) record snapshot — recorded so a future
     re-scan (continuous monitoring) can detect an unexpected NS change,
     which is a meaningful signal since legitimate NS changes are rare and
     deliberate, while hijacking often involves silently swapping NS
     records to attacker-controlled infrastructure.
  2. Subdomain volume from Certificate Transparency logs (reusing the
     existing CT-log data from app/scanner/engine.py, no extra query) —
     a sudden large burst of newly-issued certificates for random-looking
     subdomains is a recognized shadow-DNS/wildcard-abuse pattern.

This detector's NS-change detection only becomes meaningful over time
(comparing today's NS records to a previous scan's recorded NS records),
which is why it's most useful under continuous monitoring rather than a
single ad-hoc scan — an ad-hoc run only establishes the current baseline.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

DNS_TIMEOUT = 5

# A crude heuristic for "random-looking" subdomain labels: long runs of
# consonant-heavy or digit-heavy strings that don't resemble a typical
# human-chosen subdomain name (www, api, mail, etc.). This is intentionally
# conservative — it will under-flag rather than over-flag, since a false
# "shadow DNS" alert is more disruptive than a missed one.
_RANDOM_LABEL_RE = re.compile(r"^[a-z0-9]{12,}$")


@dataclass
class DnsIntegrityResult:
    domain: str
    nameservers: list[str] = field(default_factory=list)
    previous_nameservers: list[str] | None = None  # supplied by caller for comparison, e.g. from monitoring store
    nameserver_change_detected: bool = False
    subdomain_count: int = 0
    random_looking_subdomain_count: int = 0
    error: str | None = None


def _resolve_ns_sync(domain: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, "NS")
        return sorted(str(r.target).rstrip(".").lower() for r in answers)
    except (dns.exception.DNSException, Exception):
        return []


def _looks_random(subdomain: str, domain: str) -> bool:
    label = subdomain[: -(len(domain) + 1)] if subdomain.endswith("." + domain) else subdomain
    label = label.split(".")[0]  # only the leftmost label
    return bool(_RANDOM_LABEL_RE.match(label))


async def run_dns_integrity_check(
    domain: str,
    subdomain_sprawl: list[str],
    previous_nameservers: list[str] | None = None,
) -> DnsIntegrityResult:
    result = DnsIntegrityResult(domain=domain, previous_nameservers=previous_nameservers)
    try:
        result.nameservers = await asyncio.to_thread(_resolve_ns_sync, domain)
        if previous_nameservers is not None and result.nameservers:
            if set(result.nameservers) != set(previous_nameservers):
                result.nameserver_change_detected = True

        result.subdomain_count = len(subdomain_sprawl)
        result.random_looking_subdomain_count = sum(
            1 for s in subdomain_sprawl if _looks_random(s, domain)
        )
    except Exception as exc:
        result.error = f"DNS integrity check failed: {type(exc).__name__}"
    return result

"""
DET-08: Subdomain Takeover Monitor
---------------------------------------
Checks subdomains discovered via Certificate Transparency logs (reusing
app/scanner/engine.py's existing subdomain_sprawl data, so this does not
duplicate that CT-log query) for CNAME records pointing at known
third-party cloud service patterns that are commonly abandoned/decommissioned
— the classic "dangling CNAME" subdomain-takeover signal. A subdomain
whose CNAME points to e.g. *.s3.amazonaws.com or *.herokuapp.com only
represents real risk if that specific target is no longer claimed; this
detector flags the pattern as "worth verifying," not a confirmed takeover,
since confirming an actual unclaimed resource would require provider-
specific API calls (e.g. asking AWS whether a given S3 bucket exists) that
are out of scope here.

Passive only: a CNAME lookup is a standard DNS query, the same kind a
browser performs when resolving any hostname.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import dns.resolver
import dns.exception

# Service-fingerprint suffixes commonly associated with subdomain takeover
# advisories. Not exhaustive; covers the most frequently cited services.
TAKEOVER_PRONE_PATTERNS = [
    ("s3.amazonaws.com", "AWS S3"),
    ("herokuapp.com", "Heroku"),
    ("herokudns.com", "Heroku"),
    ("azurewebsites.net", "Azure App Service"),
    ("blob.core.windows.net", "Azure Blob Storage"),
    ("cloudapp.net", "Azure"),
    ("github.io", "GitHub Pages"),
    ("ghost.io", "Ghost"),
    ("readme.io", "ReadMe"),
    ("surge.sh", "Surge"),
    ("bitbucket.io", "Bitbucket"),
    ("wordpress.com", "WordPress"),
    ("fastly.net", "Fastly"),
    ("pantheonsite.io", "Pantheon"),
    ("zendesk.com", "Zendesk"),
    ("shopify.com", "Shopify"),
    ("unbouncepages.com", "Unbounce"),
    ("statuspage.io", "Statuspage"),
]

DNS_TIMEOUT = 5


@dataclass
class TakeoverFinding:
    subdomain: str
    cname_target: str
    matched_service: str


@dataclass
class SubdomainTakeoverResult:
    domain: str
    subdomains_checked: int = 0
    findings: list[TakeoverFinding] = field(default_factory=list)
    error: str | None = None


def _resolve_cname_sync(subdomain: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(subdomain, "CNAME")
        if answers:
            return str(answers[0].target).rstrip(".").lower()
    except (dns.exception.DNSException, Exception):
        return None
    return None


async def run_subdomain_takeover_check(domain: str, subdomain_sprawl: list[str]) -> SubdomainTakeoverResult:
    """
    subdomain_sprawl: the list already discovered by the existing CT-log
    check in app/scanner/engine.py — passed in rather than re-queried, so
    this detector adds zero additional external API calls for the CT-log
    portion of its work.
    """
    result = SubdomainTakeoverResult(domain=domain)
    if not subdomain_sprawl:
        return result

    # Cap how many we check to keep this bounded for domains with very
    # large subdomain footprints.
    candidates = subdomain_sprawl[:25]
    result.subdomains_checked = len(candidates)

    async def _check_one(subdomain: str) -> TakeoverFinding | None:
        cname = await asyncio.to_thread(_resolve_cname_sync, subdomain)
        if not cname:
            return None
        for pattern, service_name in TAKEOVER_PRONE_PATTERNS:
            if cname.endswith(pattern):
                return TakeoverFinding(subdomain=subdomain, cname_target=cname, matched_service=service_name)
        return None

    try:
        outcomes = await asyncio.gather(*(_check_one(s) for s in candidates))
        result.findings = [f for f in outcomes if f is not None]
    except Exception as exc:
        result.error = f"Subdomain takeover check failed: {type(exc).__name__}"

    return result

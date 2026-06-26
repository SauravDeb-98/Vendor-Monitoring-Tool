"""
DET-25: Fourth-Party Concentration Infrastructure Mapping
----------------------------------------------------------------
Identifies which underlying infrastructure provider(s) a vendor's domain
actually resolves to, using only free, no-key, passive signals:

  1. PRIMARY: Team Cymru's free public IP-to-ASN mapping service
     (https://www.team-cymru.com/ip-asn-mapping), queried via its DNS
     interface — the same query pattern used by widely-deployed tools
     like cymruwhois. This resolves an IP to its real BGP-announced ASN
     and the organization name that owns that ASN (e.g. "CLOUDFLARENET -
     Cloudflare, Inc."), which is the actual ground-truth answer to "who
     hosts this," verified directly against known ASNs for major
     providers (Cloudflare AS13335, Fastly AS54113, GitHub AS36459) during
     development of this detector.
  2. FALLBACK: reverse DNS (PTR) on the resolved IP, for the rare case the
     Cymru DNS service is unreachable.
  3. FALLBACK: known CDN/cloud provider signature response headers
     (reuses DET-12's WAF detector patterns), for cases where neither of
     the above resolves a provider.

This is "concentration mapping," not a full ASN/BGP-level analysis tool —
it answers a real, useful question ("which vendors in this batch share
the same underlying cloud/CDN provider, creating correlated outage or
breach risk") using only free public infrastructure, at the cost of being
coarser than a dedicated commercial IP-intelligence database.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

import dns.resolver
import dns.reversename
import dns.exception

DNS_TIMEOUT = 5

PTR_PROVIDER_PATTERNS = [
    ("amazonaws.com", "AWS"),
    ("googleusercontent.com", "Google Cloud"),
    ("google.com", "Google Cloud"),
    ("azure.com", "Microsoft Azure"),
    ("microsoft.com", "Microsoft Azure"),
    ("cloudflare.com", "Cloudflare"),
    ("fastly.net", "Fastly"),
    ("akamai", "Akamai"),
    ("akamaiedge.net", "Akamai"),
    ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Linode/Akamai"),
    ("ovh.net", "OVH"),
    ("hetzner", "Hetzner"),
]


@dataclass
class ConcentrationResult:
    domain: str
    resolved_ips: list[str] = field(default_factory=list)
    asn: str | None = None
    asn_organization: str | None = None
    detected_provider: str | None = None
    evidence: str | None = None
    error: str | None = None


def _resolve_a_records_sync(domain: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, "A")
        return [str(r) for r in answers]
    except (dns.exception.DNSException, Exception):
        return []


def _reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _lookup_asn_sync(ip: str) -> tuple[str | None, str | None]:
    """Returns (asn, organization_name) via Team Cymru's free DNS-based
    IP-to-ASN service, or (None, None) if the lookup fails."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        query = f"{_reverse_ip(ip)}.origin.asn.cymru.com"
        answers = resolver.resolve(query, "TXT")
        if not answers:
            return None, None
        # Format: "ASN | BGP Prefix | CC | Registry | Allocated"
        txt = answers[0].strings[0].decode() if answers[0].strings else ""
        parts = [p.strip() for p in txt.split("|")]
        asn = parts[0] if parts else None
        if not asn:
            return None, None

        org_query = f"AS{asn}.asn.cymru.com"
        org_answers = resolver.resolve(org_query, "TXT")
        org_txt = org_answers[0].strings[0].decode() if org_answers[0].strings else ""
        # Format: "ASN | CC | Registry | Allocated | AS Name"
        org_parts = [p.strip() for p in org_txt.split("|")]
        org_name = org_parts[-1] if len(org_parts) >= 5 else None
        return asn, org_name
    except (dns.exception.DNSException, Exception):
        return None, None


def _reverse_dns_sync(ip: str) -> str | None:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        rev_name = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev_name, "PTR")
        if answers:
            return str(answers[0]).rstrip(".").lower()
    except (dns.exception.DNSException, Exception):
        return None
    return None


async def run_concentration_check(domain: str, raw_headers: dict | None = None) -> ConcentrationResult:
    result = ConcentrationResult(domain=domain)
    try:
        result.resolved_ips = await asyncio.to_thread(_resolve_a_records_sync, domain)
        if not result.resolved_ips:
            return result

        primary_ip = result.resolved_ips[0]

        # PRIMARY: Team Cymru ASN lookup — the actual ground-truth signal.
        asn, org_name = await asyncio.to_thread(_lookup_asn_sync, primary_ip)
        if asn and org_name:
            result.asn = asn
            result.asn_organization = org_name
            result.detected_provider = org_name
            result.evidence = f"ASN AS{asn} ({org_name}) via Team Cymru IP-to-ASN mapping"
            return result

        # FALLBACK 1: reverse DNS.
        ptr = await asyncio.to_thread(_reverse_dns_sync, primary_ip)
        if ptr:
            for pattern, provider_name in PTR_PROVIDER_PATTERNS:
                if pattern in ptr:
                    result.detected_provider = provider_name
                    result.evidence = f"Reverse DNS: {ptr}"
                    return result

        # FALLBACK 2: header-based signature (reuses WAF detector's patterns).
        if raw_headers:
            from app.detectors.waf_absence import evaluate_waf_presence
            waf_result = evaluate_waf_presence(domain, raw_headers, [])
            if waf_result.waf_or_cdn_detected:
                result.detected_provider = waf_result.detected_provider
                result.evidence = f"Response header: {waf_result.evidence_header}"
    except Exception as exc:
        result.error = f"Concentration check failed: {type(exc).__name__}"
    return result


def cluster_vendors_by_provider(results: list[ConcentrationResult]) -> dict[str, list[str]]:
    """Groups domains by detected_provider. Returns {provider_name: [domain, ...]}.
    Domains with no detected provider are grouped under 'Unknown'."""
    clusters: dict[str, list[str]] = {}
    for r in results:
        key = r.detected_provider or "Unknown"
        clusters.setdefault(key, []).append(r.domain)
    return clusters

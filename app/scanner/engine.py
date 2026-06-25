"""
OSINT & Scanning Engine
------------------------
Performs PASSIVE external reconnaissance only:
  - HTTPS reachability + security response headers
  - TLS/SSL certificate inspection (validity, expiry, protocol via handshake)
  - DNS records: SPF, DKIM (common selectors), DMARC, MX
  - Certificate Transparency lookups (crt.sh) for cert hygiene/subdomain sprawl
  - Public CVE lookups (NVD) keyed on vendor/product name, best-effort

Deliberately NOT included: port scanning, banner grabbing, vulnerability
exploitation, or any active probing of vendor infrastructure beyond a
standard HTTPS GET/HEAD a normal browser would perform. This keeps the tool
within passive-OSINT / publicly-exposed-data bounds.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx
import dns.resolver
import dns.exception

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CRTSH_API = "https://crt.sh/"

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
]

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]

HTTP_TIMEOUT = httpx.Timeout(10.0, connect=6.0)


@dataclass
class ScanResult:
    domain: str
    reachable: bool = False
    https_enforced: bool = False
    status_code: int | None = None
    headers_present: dict[str, bool] = field(default_factory=dict)
    missing_headers: list[str] = field(default_factory=list)
    tls_version: str | None = None
    tls_cert_valid: bool | None = None
    tls_cert_expires_days: int | None = None
    tls_error: str | None = None
    spf_present: bool = False
    spf_record: str | None = None
    dmarc_present: bool = False
    dmarc_policy: str | None = None
    dkim_present: bool = False
    mx_present: bool = False
    cert_transparency_count: int | None = None
    subdomain_sprawl: list[str] = field(default_factory=list)
    cves_found: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def _check_http(client: httpx.AsyncClient, domain: str, result: ScanResult) -> None:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            resp = await client.get(url, follow_redirects=True)
            result.reachable = True
            result.status_code = resp.status_code
            if scheme == "https":
                result.https_enforced = True
            headers_lower = {k.lower(): v for k, v in resp.headers.items()}
            for h in SECURITY_HEADERS:
                present = h in headers_lower
                result.headers_present[h] = present
                if not present:
                    result.missing_headers.append(h)
            return
        except httpx.HTTPError as exc:
            result.errors.append(f"{scheme.upper()} request failed: {type(exc).__name__}")
            continue
    if not result.reachable:
        result.errors.append("Domain unreachable over HTTP/HTTPS")


def _check_tls_sync(domain: str) -> dict:
    out = {"tls_version": None, "tls_cert_valid": None, "tls_cert_expires_days": None, "tls_error": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                out["tls_version"] = ssock.version()
                cert = ssock.getpeercert()
                out["tls_cert_valid"] = True
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    out["tls_cert_expires_days"] = (expiry - datetime.now(timezone.utc)).days
    except ssl.SSLCertVerificationError as exc:
        out["tls_cert_valid"] = False
        out["tls_error"] = f"Certificate verification failed: {exc.verify_message if hasattr(exc, 'verify_message') else exc}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        out["tls_error"] = f"TLS connection failed: {type(exc).__name__}"
    return out


async def _check_tls(domain: str, result: ScanResult) -> None:
    try:
        data = await asyncio.to_thread(_check_tls_sync, domain)
        result.tls_version = data["tls_version"]
        result.tls_cert_valid = data["tls_cert_valid"]
        result.tls_cert_expires_days = data["tls_cert_expires_days"]
        if data["tls_error"]:
            result.tls_error = data["tls_error"]
    except Exception as exc:  # defensive: never let TLS check crash the scan
        result.tls_error = f"TLS check error: {exc}"


def _resolve_txt_sync(name: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(name, "TXT")
        return ["".join(r.strings[0:1] and [s.decode() for s in r.strings]) for r in answers]
    except (dns.exception.DNSException, Exception):
        return []


def _resolve_mx_sync(domain: str) -> bool:
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        return len(answers) > 0
    except (dns.exception.DNSException, Exception):
        return False


async def _check_dns(domain: str, result: ScanResult) -> None:
    spf_txts = await asyncio.to_thread(_resolve_txt_sync, domain)
    for txt in spf_txts:
        if txt.lower().startswith("v=spf1"):
            result.spf_present = True
            result.spf_record = txt
            break

    dmarc_txts = await asyncio.to_thread(_resolve_txt_sync, f"_dmarc.{domain}")
    for txt in dmarc_txts:
        if txt.lower().startswith("v=dmarc1"):
            result.dmarc_present = True
            for part in txt.split(";"):
                part = part.strip()
                if part.lower().startswith("p="):
                    result.dmarc_policy = part.split("=", 1)[1].strip()
            break

    for selector in DKIM_SELECTORS:
        dkim_txts = await asyncio.to_thread(_resolve_txt_sync, f"{selector}._domainkey.{domain}")
        if any("v=dkim1" in t.lower() or "k=rsa" in t.lower() or "p=" in t.lower() for t in dkim_txts):
            result.dkim_present = True
            break

    result.mx_present = await asyncio.to_thread(_resolve_mx_sync, domain)


async def _check_certificate_transparency(client: httpx.AsyncClient, domain: str, result: ScanResult) -> None:
    try:
        resp = await client.get(CRTSH_API, params={"q": f"%.{domain}", "output": "json"}, timeout=15)
        if resp.status_code == 200 and resp.text.strip():
            entries = resp.json()
            result.cert_transparency_count = len(entries)
            subs = set()
            for e in entries:
                for n in str(e.get("name_value", "")).split("\n"):
                    n = n.strip().lower()
                    if n and n != domain and n.endswith(domain):
                        subs.add(n)
            result.subdomain_sprawl = sorted(subs)[:25]
    except Exception as exc:
        result.errors.append(f"Certificate transparency lookup failed: {type(exc).__name__}")


async def _check_cves(client: httpx.AsyncClient, vendor_name: str, result: ScanResult) -> None:
    """Best-effort public CVE lookup by vendor/product keyword via NVD API."""
    try:
        keyword = vendor_name.split()[0]
        resp = await client.get(
            NVD_CVE_API,
            params={"keywordSearch": keyword, "resultsPerPage": 5},
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("vulnerabilities", [])[:5]:
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                severity = None
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        severity = metrics[key][0].get("cvssData", {}).get("baseSeverity") or metrics[key][0].get("baseSeverity")
                        break
                result.cves_found.append({
                    "id": cve.get("id"),
                    "severity": severity or "UNKNOWN",
                    "published": cve.get("published", "")[:10],
                })
        elif resp.status_code == 403:
            result.errors.append("NVD CVE API rate-limited (no API key) — skipped")
    except Exception as exc:
        result.errors.append(f"CVE lookup failed: {type(exc).__name__}")


async def scan_vendor(vendor_name: str, domain: str) -> ScanResult:
    result = ScanResult(domain=domain)
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": "VendorRiskScanner/1.0 (passive OSINT)"}) as client:
        await _check_http(client, domain, result)
        await asyncio.gather(
            _check_tls(domain, result),
            _check_dns(domain, result),
            _check_certificate_transparency(client, domain, result),
            _check_cves(client, vendor_name, result),
            return_exceptions=False,
        )
    return result


async def scan_vendors(vendors: list, concurrency: int = 4) -> dict:
    """vendors: list of Vendor objects with .name and .domain. Returns {domain: ScanResult}."""
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, ScanResult] = {}

    async def _bounded(v):
        async with semaphore:
            results[v.domain] = await scan_vendor(v.name, v.domain)

    await asyncio.gather(*(_bounded(v) for v in vendors))
    return results

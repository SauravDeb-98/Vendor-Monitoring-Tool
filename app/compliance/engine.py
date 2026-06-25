"""
Compliance Mapping Engine
---------------------------
Maps raw scan findings to control failures/passes across four frameworks:

  NIST SP 800-53 Rev 5 (SR family - Supply Chain Risk Management; SC family
    for comms protection) and NIST CSF 2.0 (PR.DS, PR.PT, GV.SC)
  ISO/IEC 27001:2022 Annex A (A.5.19-5.23 supplier relationships; A.8.24
    cryptography; A.8.20-8.23 network/web security)
  DORA (EU 2022/2554) Articles 28-30 - ICT third-party risk strategy,
    due diligence, contractual security requirements
  GDPR Articles 28, 32, 44-49 - processor security obligations, encryption
    in transit, cross-border transfer safeguards

This is a rules engine: each scan finding is checked against a condition;
failing conditions produce a finding with severity weight (used by the
scoring engine) and the specific control citations it violates.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ComplianceFinding:
    finding: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    weight: int  # points deducted from 100, consumed by scoring engine
    nist: list[str] = field(default_factory=list)
    iso27001: list[str] = field(default_factory=list)
    dora: list[str] = field(default_factory=list)
    gdpr: list[str] = field(default_factory=list)
    recommendation: str = ""


def evaluate_compliance(scan) -> list[ComplianceFinding]:
    """scan: ScanResult from scanner.engine. Returns list of ComplianceFinding."""
    findings: list[ComplianceFinding] = []

    # --- Reachability ---
    if not scan.reachable:
        findings.append(ComplianceFinding(
            finding="Vendor domain unreachable during scan window",
            severity="high", weight=15,
            nist=["CSF GV.SC-07 (third-party monitoring)"],
            iso27001=["A.5.22 (monitoring of supplier services)"],
            dora=["Art. 28(4) (ongoing due diligence)"],
            gdpr=[],
            recommendation="Verify vendor availability and re-scan; confirm service continuity with vendor directly.",
        ))
        return findings  # downstream checks are meaningless if unreachable

    # --- HTTPS enforcement ---
    if not scan.https_enforced:
        findings.append(ComplianceFinding(
            finding="Site does not enforce HTTPS (no valid TLS on port 443 or HTTPS redirect failed)",
            severity="critical", weight=25,
            nist=["SC-8 (transmission confidentiality/integrity)", "SC-13 (cryptographic protection)"],
            iso27001=["A.8.24 (use of cryptography)"],
            dora=["Art. 30(2)(b) (ICT security requirements in contracts)"],
            gdpr=["Art. 32(1)(a) (encryption of personal data in transit)"],
            recommendation="Enforce HTTPS with HTTP→HTTPS redirect (HSTS) on all public endpoints.",
        ))

    # --- TLS certificate ---
    if scan.tls_cert_valid is False:
        findings.append(ComplianceFinding(
            finding="TLS certificate failed validation",
            severity="critical", weight=20,
            nist=["SC-8", "SC-12 (cryptographic key establishment/management)"],
            iso27001=["A.8.24 (use of cryptography)"],
            dora=["Art. 30(2)(b)"],
            gdpr=["Art. 32(1)(a)"],
            recommendation="Renew/reissue certificate from a trusted CA; verify full chain is served correctly.",
        ))
    elif scan.tls_cert_expires_days is not None and scan.tls_cert_expires_days < 30:
        findings.append(ComplianceFinding(
            finding=f"TLS certificate expires soon ({scan.tls_cert_expires_days} days)",
            severity="medium", weight=8,
            nist=["SC-12"],
            iso27001=["A.8.24"],
            dora=["Art. 28(4)"],
            gdpr=[],
            recommendation="Renew certificate well ahead of expiry; automate renewal (e.g. ACME/Let's Encrypt).",
        ))

    if scan.tls_version and scan.tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        findings.append(ComplianceFinding(
            finding=f"Outdated TLS protocol negotiated: {scan.tls_version}",
            severity="high", weight=15,
            nist=["SC-8", "SC-13"],
            iso27001=["A.8.24"],
            dora=["Art. 30(2)(b)"],
            gdpr=["Art. 32(1)(a)"],
            recommendation="Disable legacy TLS versions; require TLS 1.2 minimum, prefer TLS 1.3.",
        ))

    # --- Security headers ---
    header_weights = {
        "strict-transport-security": ("high", 8),
        "content-security-policy": ("medium", 6),
        "x-content-type-options": ("low", 3),
        "x-frame-options": ("low", 3),
        "referrer-policy": ("info", 2),
        "permissions-policy": ("info", 2),
    }
    for header in scan.missing_headers:
        sev, w = header_weights.get(header, ("low", 3))
        nist_refs = ["SC-8"]
        if header == "content-security-policy":
            nist_refs.append("SI-7 (software/firmware integrity)")
        findings.append(ComplianceFinding(
            finding=f"Missing security header: {header}",
            severity=sev, weight=w,
            nist=nist_refs,
            iso27001=["A.8.26 (application security requirements)"],
            dora=["Art. 30(2)(b)"],
            gdpr=["Art. 32(1)(b) (ongoing confidentiality/integrity)"],
            recommendation=f"Configure '{header}' response header per OWASP Secure Headers guidance.",
        ))

    # --- Email authentication (SPF/DKIM/DMARC) — proxy for anti-phishing/BEC posture ---
    if not scan.spf_present:
        findings.append(ComplianceFinding(
            finding="No SPF record found",
            severity="medium", weight=7,
            nist=["SC-20 (secure name/address resolution)", "SI-8 (spam protection)"],
            iso27001=["A.5.23 (information security for cloud services)", "A.8.24"],
            dora=["Art. 30(2)(b)"],
            gdpr=["Art. 32(1)(b)"],
            recommendation="Publish an SPF TXT record authorizing legitimate sending sources.",
        ))
    if not scan.dmarc_present:
        findings.append(ComplianceFinding(
            finding="No DMARC record found",
            severity="medium", weight=7,
            nist=["SC-20", "SI-8"],
            iso27001=["A.5.23", "A.8.24"],
            dora=["Art. 30(2)(b)"],
            gdpr=["Art. 32(1)(b)"],
            recommendation="Publish a DMARC record (start with p=quarantine, move to p=reject) to prevent domain spoofing.",
        ))
    elif scan.dmarc_policy == "none":
        findings.append(ComplianceFinding(
            finding="DMARC policy set to 'none' (monitoring only, not enforced)",
            severity="low", weight=4,
            nist=["SI-8"],
            iso27001=["A.5.23"],
            dora=[],
            gdpr=[],
            recommendation="Move DMARC policy from 'none' to 'quarantine' or 'reject' once SPF/DKIM alignment is confirmed.",
        ))
    if not scan.dkim_present:
        findings.append(ComplianceFinding(
            finding="No DKIM record found at common selectors",
            severity="low", weight=4,
            nist=["SI-8"],
            iso27001=["A.5.23"],
            dora=[],
            gdpr=[],
            recommendation="Enable DKIM signing for outbound mail; publish selector records.",
        ))

    # --- Certificate transparency / attack surface ---
    if scan.subdomain_sprawl and len(scan.subdomain_sprawl) > 15:
        findings.append(ComplianceFinding(
            finding=f"Large exposed subdomain footprint ({len(scan.subdomain_sprawl)} subdomains observed in CT logs)",
            severity="medium", weight=6,
            nist=["CM-8 (system component inventory)", "RA-5 (vulnerability monitoring)"],
            iso27001=["A.5.9 (inventory of information and assets)", "A.8.9 (configuration management)"],
            dora=["Art. 28(4) (concentration/dependency risk)"],
            gdpr=[],
            recommendation="Inventory and decommission stale subdomains; reduce externally exposed attack surface.",
        ))

    # --- CVEs ---
    if scan.cves_found:
        high_sev = [c for c in scan.cves_found if c.get("severity") in ("CRITICAL", "HIGH")]
        if high_sev:
            findings.append(ComplianceFinding(
                finding=f"{len(high_sev)} HIGH/CRITICAL severity CVE(s) publicly associated with vendor/product name",
                severity="critical", weight=20,
                nist=["RA-5 (vulnerability scanning)", "SR-3 (supply chain controls)"],
                iso27001=["A.8.8 (management of technical vulnerabilities)"],
                dora=["Art. 28(4)", "Art. 29 (concentration/ICT risk)"],
                gdpr=["Art. 32(1)(d) (regular testing of security measures)"],
                recommendation="Confirm patch status with vendor for identified CVEs; request remediation evidence.",
            ))
        else:
            findings.append(ComplianceFinding(
                finding=f"{len(scan.cves_found)} lower-severity CVE(s) publicly associated with vendor/product name",
                severity="low", weight=5,
                nist=["RA-5", "SR-3"],
                iso27001=["A.8.8"],
                dora=["Art. 28(4)"],
                gdpr=[],
                recommendation="Track CVE remediation status as part of ongoing vendor monitoring.",
            ))

    return findings


def deduplicate_and_cap(findings: list[ComplianceFinding], max_deduction: int = 100) -> list[ComplianceFinding]:
    """Sort by severity weight descending; caller sums weights for scoring."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: (severity_order.get(f.severity, 5), -f.weight))

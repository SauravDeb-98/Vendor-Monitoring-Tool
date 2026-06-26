"""
DET-14: CORS & Content Security Policy (CSP) Auditor
-----------------------------------------------------------
Evaluates two header-based security controls from the same single passive
HTTP response the existing scanner already retrieves (via the new
raw_headers field added to ScanResult):

  - Content-Security-Policy: already flagged as present/absent by the
    existing scanner; this detector adds a basic QUALITY check on top of
    mere presence — flags a CSP that's present but uses wildcard or
    overly permissive directives (e.g. `default-src *` or `script-src
    'unsafe-inline'` with no nonce/hash), since a present-but-weak CSP is
    a different and more nuanced finding than simply "missing."
  - Access-Control-Allow-Origin (CORS): flags a wildcard `*` CORS policy,
    which permits any origin to make cross-origin requests — a real and
    commonly-flagged misconfiguration, especially when combined with
    Access-Control-Allow-Credentials: true (a combination most browsers
    actually reject, but some server configurations still attempt it,
    which itself indicates a misconfigured/copy-pasted security policy).

This reuses the existing single GET request's headers; no new network
call is made.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CorsCspFinding:
    finding: str
    severity: str  # "high" | "medium" | "low" | "info"


@dataclass
class CorsCspAuditResult:
    domain: str
    csp_present: bool = False
    cors_header_present: bool = False
    cors_allows_any_origin: bool = False
    findings: list[CorsCspFinding] = field(default_factory=list)


def _csp_has_weak_directive(csp_value: str) -> list[str]:
    weak_patterns = []
    csp_lower = csp_value.lower()
    if "default-src *" in csp_lower or "default-src: *" in csp_lower:
        weak_patterns.append("default-src allows any origin (*)")
    if "script-src *" in csp_lower:
        weak_patterns.append("script-src allows any origin (*) — permits loading scripts from anywhere")
    if "unsafe-inline" in csp_lower and "script-src" in csp_lower:
        weak_patterns.append("script-src allows 'unsafe-inline', which defeats much of CSP's XSS protection")
    if "unsafe-eval" in csp_lower:
        weak_patterns.append("allows 'unsafe-eval', permitting dynamic code execution patterns CSP is meant to restrict")
    return weak_patterns


def evaluate_cors_csp(domain: str, raw_headers: dict) -> CorsCspAuditResult:
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}
    result = CorsCspAuditResult(domain=domain)

    csp_value = headers_lower.get("content-security-policy")
    result.csp_present = csp_value is not None
    if csp_value:
        for weak in _csp_has_weak_directive(csp_value):
            result.findings.append(CorsCspFinding(finding=f"Weak CSP directive: {weak}", severity="medium"))
    else:
        result.findings.append(CorsCspFinding(finding="No Content-Security-Policy header present", severity="medium"))

    cors_value = headers_lower.get("access-control-allow-origin")
    result.cors_header_present = cors_value is not None
    if cors_value:
        if cors_value.strip() == "*":
            result.cors_allows_any_origin = True
            credentials_value = headers_lower.get("access-control-allow-credentials", "").lower()
            severity = "high" if credentials_value == "true" else "medium"
            detail = " combined with Access-Control-Allow-Credentials: true (browsers should reject this, but the configuration itself indicates a misconfigured policy)" if credentials_value == "true" else ""
            result.findings.append(CorsCspFinding(
                finding=f"CORS policy allows any origin (Access-Control-Allow-Origin: *){detail}",
                severity=severity,
            ))

    return result

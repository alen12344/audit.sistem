from __future__ import annotations

OWASP_TOP10_2021 = {
    "A01:2021-Broken Access Control": ["CWE-22", "CWE-284", "CWE-285", "CWE-639"],
    "A02:2021-Cryptographic Failures": ["CWE-311", "CWE-319", "CWE-326", "CWE-327"],
    "A03:2021-Injection": ["CWE-79", "CWE-89", "CWE-90", "CWE-564", "CWE-943"],
    "A04:2021-Insecure Design": ["CWE-256", "CWE-522", "CWE-656"],
    "A05:2021-Security Misconfiguration": ["CWE-16", "CWE-209", "CWE-611", "CWE-614"],
    "A06:2021-Vulnerable and Outdated Components": ["CWE-1104"],
    "A07:2021-Identification and Authentication Failures": ["CWE-287", "CWE-306", "CWE-307", "CWE-308", "CWE-798"],
    "A08:2021-Software and Data Integrity Failures": ["CWE-345", "CWE-353", "CWE-494", "CWE-829"],
    "A09:2021-Security Logging and Monitoring Failures": ["CWE-778", "CWE-223"],
    "A10:2021-Server-Side Request Forgery (SSRF)": ["CWE-918"],
}

CWE_TO_OWASP: dict[str, set[str]] = {}
for k, cwes in OWASP_TOP10_2021.items():
    for cwe in cwes:
        CWE_TO_OWASP.setdefault(cwe, set()).add(k)

def owasp_for_cwe(cwe: str | None) -> list[str]:
    if not cwe:
        return []
    return sorted(CWE_TO_OWASP.get(cwe.strip().upper(), set()))

def normalize_severity(s: str | None) -> str:
    s = (s or "").strip().lower()
    if s in {"critical", "crit"}: return "critical"
    if s in {"high", "h"}: return "high"
    if s in {"medium", "med", "m"}: return "medium"
    if s in {"low", "l"}: return "low"
    return "info"

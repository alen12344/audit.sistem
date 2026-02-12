from __future__ import annotations

ISO27001_LITE = [
  ("A.5", "Kebijakan keamanan informasi"),
  ("A.6", "Organisasi keamanan informasi"),
  ("A.8", "Manajemen aset"),
  ("A.9", "Kontrol akses"),
  ("A.10", "Kriptografi"),
  ("A.12", "Keamanan operasi"),
  ("A.13", "Keamanan komunikasi"),
  ("A.14", "Akuisisi/pengembangan/pemeliharaan SI"),
  ("A.16", "Manajemen insiden"),
  ("A.18", "Kepatuhan"),
]

ASVS_LITE = [
  ("V1", "Architecture, Design and Threat Modeling"),
  ("V2", "Authentication"),
  ("V3", "Session Management"),
  ("V4", "Access Control"),
  ("V5", "Validation, Sanitization and Encoding"),
  ("V6", "Stored Cryptography"),
  ("V7", "Error Handling and Logging"),
  ("V8", "Data Protection"),
  ("V9", "Communication"),
  ("V10", "Malicious Code"),
  ("V11", "Business Logic"),
  ("V12", "Files and Resources"),
  ("V13", "API and Web Service"),
  ("V14", "Configuration"),
]

OWASP_TO_COMPLIANCE = {
  "A01:2021-Broken Access Control": (["A.9"], ["V4"]),
  "A02:2021-Cryptographic Failures": (["A.10", "A.18"], ["V6", "V8", "V9"]),
  "A03:2021-Injection": (["A.14"], ["V5", "V13"]),
  "A04:2021-Insecure Design": (["A.5", "A.6", "A.14"], ["V1"]),
  "A05:2021-Security Misconfiguration": (["A.12", "A.14"], ["V14", "V7"]),
  "A06:2021-Vulnerable and Outdated Components": (["A.12", "A.18"], ["V14"]),
  "A07:2021-Identification and Authentication Failures": (["A.9"], ["V2", "V3"]),
  "A08:2021-Software and Data Integrity Failures": (["A.12", "A.14"], ["V10", "V14"]),
  "A09:2021-Security Logging and Monitoring Failures": (["A.16"], ["V7"]),
  "A10:2021-Server-Side Request Forgery (SSRF)": (["A.13", "A.14"], ["V13"]),
}

SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def heat_score(total_weight: int) -> str:
    if total_weight >= 12: return "very-high"
    if total_weight >= 8: return "high"
    if total_weight >= 4: return "medium"
    if total_weight >= 1: return "low"
    return "none"

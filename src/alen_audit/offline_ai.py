from __future__ import annotations
import re
from typing import Any

# Offline classifier (rule-based) untuk memberi label jenis kerentanan
# Ini bukan eksploit; hanya klasifikasi teks dari evidence/title/log.

PATTERNS = [
    ("sql_injection", re.compile(r"sql\s*injection|sqli|CWE-89|syntax\s+error|mysql|postgres|ORA-\d+", re.I)),
    ("xss", re.compile(r"\bxss\b|CWE-79|script\s*>|onerror\s*=|<svg|alert\(", re.I)),
    ("ssrf", re.compile(r"\bssrf\b|CWE-918|169\.254\.169\.254|metadata\s+service", re.I)),
    ("misconfiguration", re.compile(r"stacktrace|debug\s*=\s*true|directory\s+listing|server\s+banner", re.I)),
    ("auth", re.compile(r"broken\s+auth|weak\s+password|missing\s+mfa|CWE-287|CWE-798", re.I)),
    ("access_control", re.compile(r"broken\s+access|idor|CWE-284|CWE-639|forbidden\s+bypass", re.I)),
    ("crypto", re.compile(r"weak\s+tls|CWE-327|md5|sha1|insecure\s+crypto", re.I)),
]

LABEL_TO_CWE = {
    "sql_injection": "CWE-89",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "misconfiguration": "CWE-16",
    "auth": "CWE-287",
    "access_control": "CWE-284",
    "crypto": "CWE-327",
}

def classify_text(title: str = "", evidence: str = "", tags: list[str] | None = None) -> dict[str, Any]:
    text = " ".join([title or "", evidence or "", " ".join(tags or [])])
    hits = []
    for label, rx in PATTERNS:
        if rx.search(text):
            hits.append(label)
    primary = hits[0] if hits else "generic"
    return {
        "labels": hits,
        "primary": primary,
        "suggested_cwe": LABEL_TO_CWE.get(primary),
    }

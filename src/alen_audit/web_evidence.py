from __future__ import annotations
from typing import Any
import json
import re

SEC_HEADERS = [
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "strict-transport-security",
]

def load_har(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def analyze_har(har: dict[str, Any]) -> dict[str, Any]:
    entries = (((har.get("log") or {}).get("entries")) or [])
    issues = []
    summary = {
        "total_entries": len(entries),
        "missing_security_headers": 0,
        "possible_reflection_markers": 0,
    }

    for e in entries:
        req = e.get("request") or {}
        res = e.get("response") or {}
        url = req.get("url","")
        method = req.get("method","")
        headers = { (h.get("name","").lower()): (h.get("value","")) for h in (res.get("headers") or []) if isinstance(h, dict) }

        missing = [h for h in SEC_HEADERS if h not in headers]
        if missing:
            summary["missing_security_headers"] += 1
            issues.append({
                "type": "missing_security_headers",
                "url": url,
                "method": method,
                "missing": missing,
                "note": "Periksa apakah header wajib sesuai kebijakan org (CSP/HSTS dsb)."
            })

        # Passive reflection check: look for common markers in response body if present
        content = (res.get("content") or {})
        text = content.get("text") or ""
        if isinstance(text, str) and re.search(r"__XSS_TEST__|<script|onerror\s*=|\bUNION\b\s+\bSELECT\b", text, re.I):
            summary["possible_reflection_markers"] += 1
            issues.append({
                "type": "possible_reflection_marker",
                "url": url,
                "method": method,
                "note": "Marker ditemukan di response body. Validasi manual diperlukan untuk konfirmasi."
            })

    return {"summary": summary, "issues": issues}

def write_json(obj: dict[str, Any], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

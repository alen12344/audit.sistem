from __future__ import annotations
from typing import Any
import json

def load_openapi(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def summarize_openapi(spec: dict[str, Any]) -> dict[str, Any]:
    paths = spec.get("paths", {}) or {}
    security = spec.get("security", []) or []
    components = spec.get("components", {}) or {}
    sec_schemes = (components.get("securitySchemes", {}) or {})
    endpoints = []
    for p, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for m, meta in methods.items():
            if m.lower() not in {"get","post","put","patch","delete","options","head"}:
                continue
            meta = meta or {}
            endpoints.append({
                "path": p,
                "method": m.upper(),
                "operationId": meta.get("operationId"),
                "auth": bool(meta.get("security", security)),
                "summary": (meta.get("summary") or meta.get("description") or "")[:140],
            })
    return {
        "title": (spec.get("info", {}) or {}).get("title","OpenAPI"),
        "version": (spec.get("info", {}) or {}).get("version",""),
        "endpoint_count": len(endpoints),
        "endpoints": sorted(endpoints, key=lambda x: (x["path"], x["method"])),
        "security_schemes": list(sec_schemes.keys()),
    }

def to_markdown(summary: dict[str, Any]) -> str:
    lines = []
    lines.append(f"# API Surface — {summary.get('title','')}")
    if summary.get("version"):
        lines.append(f"- Version: `{summary['version']}`")
    lines.append(f"- Endpoints: **{summary['endpoint_count']}**")
    if summary.get("security_schemes"):
        lines.append(f"- Security schemes: {', '.join('`'+s+'`' for s in summary['security_schemes'])}")
    lines.append("")
    lines.append("## Endpoint List")
    lines.append("| Method | Path | Auth | OperationId | Summary |")
    lines.append("|---|---|---:|---|---|")
    for e in summary["endpoints"]:
        lines.append(f"| {e['method']} | `{e['path']}` | {'✅' if e['auth'] else '❌'} | `{e.get('operationId') or ''}` | {e.get('summary') or ''} |")
    lines.append("")
    lines.append("## Heuristic Checks (Defensive)")
    lines.append("- Endpoint tanpa auth (❌): cek apakah benar public atau missing authorization.")
    lines.append("- Endpoint write (POST/PUT/PATCH/DELETE): pastikan ACL, validasi input, logging.")
    return "\n".join(lines)

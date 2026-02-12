from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import json, datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import yaml

from .mapping import owasp_for_cwe, normalize_severity
from .compliance import ISO27001_LITE, ASVS_LITE, OWASP_TO_COMPLIANCE, SEVERITY_WEIGHT, heat_score
from .suppress import SuppressionRule, hash_evidence
from .offline_ai import classify_text

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    location: str
    evidence: str | None = None
    cwe: str | None = None
    tags: list[str] | None = None
    owasp: list[str] | None = None
    status: str = "open"
    suppressed_by: str | None = None
    ai_labels: list[str] | None = None

def load_findings(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_suppressions(path: str | None) -> list[SuppressionRule]:
    if not path:
        return []
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    rules: list[SuppressionRule] = []
    for r in (data.get("rules", []) or []):
        rules.append(SuppressionRule(
            id=str(r.get("id","")),
            reason=str(r.get("reason","")),
            title_regex=r.get("title_regex"),
            location_regex=r.get("location_regex"),
            cwe=r.get("cwe"),
            evidence_hash=r.get("evidence_hash"),
        ))
    return rules

def apply_mapping(f: Finding) -> Finding:
    f.severity = normalize_severity(f.severity)
    f.tags = f.tags or []

    # Offline AI classification -> suggested CWE if missing
    ai = classify_text(f.title, f.evidence or "", f.tags)
    f.ai_labels = ai.get("labels") or []
    if not f.cwe and ai.get("suggested_cwe"):
        f.cwe = ai["suggested_cwe"]

    f.owasp = owasp_for_cwe(f.cwe)
    return f

def suppress_findings(findings: list[Finding], rules: list[SuppressionRule]) -> list[Finding]:
    for f in findings:
        for rule in rules:
            if rule.matches(f.__dict__):
                f.status = "suppressed"
                f.suppressed_by = f"{rule.id}: {rule.reason}"
                break
    return findings

def kpi_by_severity(findings: list[Finding]) -> dict[str, int]:
    counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity,0)+1
    return counts

def owasp_counts(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        for o in (f.owasp or []):
            out[o] = out.get(o, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))

def chart_data(findings: list[Finding]) -> dict[str, Any]:
    sev = kpi_by_severity(findings)
    sev_labels = ["critical","high","medium","low","info"]
    sev_values = [sev.get(x,0) for x in sev_labels]
    cats = owasp_counts(findings)
    return {
        "severity": {"labels":[s.upper() for s in sev_labels], "values": sev_values},
        "category": {"labels": list(cats.keys()) or ["(none)"], "values": list(cats.values()) or [0]},
    }

def build_heatmap(findings: list[Finding]) -> tuple[list[str], list[dict[str, Any]]]:
    cols = ["ISO27001", "ASVS"]
    iso_w = {cid: 0 for cid,_ in ISO27001_LITE}
    asvs_w = {vid: 0 for vid,_ in ASVS_LITE}

    for f in findings:
        if f.status == "suppressed":
            continue
        weight = SEVERITY_WEIGHT.get(f.severity,0)
        for o in (f.owasp or []):
            iso_ids, asvs_ids = OWASP_TO_COMPLIANCE.get(o, ([],[]))
            for cid in iso_ids:
                if cid in iso_w:
                    iso_w[cid] += weight
            for vid in asvs_ids:
                if vid in asvs_w:
                    asvs_w[vid] += weight

    rows: list[dict[str, Any]] = []
    for cid, desc in ISO27001_LITE:
        wgt = iso_w.get(cid, 0)
        rows.append({
            "name": cid,
            "desc": desc,
            "cells": {
                "ISO27001": {"level": heat_score(wgt), "count": wgt, "label": "risk weight"},
                "ASVS": {"level": "none", "count": 0, "label": "-"},
            }
        })

    for vid, desc in ASVS_LITE:
        wgt = asvs_w.get(vid, 0)
        rows.append({
            "name": vid,
            "desc": desc,
            "cells": {
                "ISO27001": {"level": "none", "count": 0, "label": "-"},
                "ASVS": {"level": heat_score(wgt), "count": wgt, "label": "risk weight"},
            }
        })
    return cols, rows

def export_threat_model_md(project: str, target: str) -> str:
    today = datetime.date.today().isoformat()
    return f"""# Threat Model — {project}

## Scope
- Target: **{target}**
- Date: **{today}**

## Assets (contoh)
- Data user / PII
- Token/API keys
- Database

## Trust Boundaries
- Browser ↔ API Gateway
- API ↔ Database
- CI/CD ↔ Artifact registry

## STRIDE Checklist
| Area | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|---|---|---|---|---|---|---|
| Auth | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| API | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |
| Storage | ☐ | ☐ | ☐ | ☐ | ☐ | ☐ |

## Mitigations (ringkas)
- MFA untuk akses admin
- Input validation + output encoding
- Least privilege pada DB/service account
- Logging + alerting ke SOC
"""

def render_report(payload: dict[str, Any], outdir: str, project: str, owner: str, suppress_path: str | None = None) -> None:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)

    target = str(payload.get("target","(unknown)"))
    generated_at = payload.get("generated_at") or (datetime.datetime.utcnow().isoformat() + "Z")

    findings: list[Finding] = []
    for f in (payload.get("findings", []) or []):
        findings.append(apply_mapping(Finding(
            id=str(f.get("id","")),
            title=str(f.get("title","")),
            severity=str(f.get("severity","info")),
            location=str(f.get("location","")),
            evidence=f.get("evidence"),
            cwe=f.get("cwe"),
            tags=list(f.get("tags", []) or []),
        )))

    rules = load_suppressions(suppress_path)
    findings = suppress_findings(findings, rules)

    active = [x for x in findings if x.status != "suppressed"]
    sev = kpi_by_severity(active)

    heat_cols, heat_rows = build_heatmap(findings)

    summary = {
        "project": project,
        "owner": owner,
        "target": target,
        "generated_at": generated_at,
        "kpi_active": sev,
        "owasp_counts": owasp_counts(active),
        "findings": [f.__dict__ for f in findings],
        "notes": {
            "offline_ai": "rule-based classifier suggests CWE if missing (no internet)",
            "fp_engine": "suppressed findings include suppressed_by",
            "evidence_hash_hint": "use: alen-audit hash-evidence --text \"...\"",
        }
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "threat_model.md").write_text(export_threat_model_md(project, target), encoding="utf-8")

    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
        autoescape=select_autoescape(["html","xml"]),
    )
    tpl = env.get_template("report.html.j2")
    html = tpl.render(
        project=project,
        owner=owner,
        target=target,
        generated_at=generated_at,
        findings=findings,
        kpi={
            "total": len(findings),
            "active": len(active),
            "critical": sev.get("critical",0),
            "high": sev.get("high",0),
            "medium": sev.get("medium",0),
            "low": sev.get("low",0),
        },
        owasp_counts=owasp_counts(active),
        heat_cols=heat_cols,
        heat_rows=heat_rows,
        chart=chart_data(active),
    )
    (out / "report.html").write_text(html, encoding="utf-8")

def evidence_hash_cli(evidence: str) -> str:
    return hash_evidence(evidence)

from __future__ import annotations
import argparse, sys
from pathlib import Path
from rich.console import Console

from .banner import BANNER
from .reporting import load_findings, render_report, evidence_hash_cli
from .openapi_analyzer import load_openapi, summarize_openapi, to_markdown
from .web_evidence import load_har, analyze_har, write_json

console = Console()

def cmd_report(args: argparse.Namespace) -> int:
    payload = load_findings(args.input)
    render_report(payload, args.outdir, args.project, args.owner, args.suppress)
    console.print(f"[green]OK[/green] Report dibuat di: [bold]{Path(args.outdir).resolve()}[/bold]")
    console.print(f"- HTML: {Path(args.outdir,'report.html')}")
    console.print(f"- Summary: {Path(args.outdir,'summary.json')}")
    console.print(f"- Threat model: {Path(args.outdir,'threat_model.md')}")
    return 0

def cmd_api_surface(args: argparse.Namespace) -> int:
    spec = load_openapi(args.openapi)
    summ = summarize_openapi(spec)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(to_markdown(summ), encoding="utf-8")
    console.print(f"[green]OK[/green] API surface ditulis: [bold]{Path(args.out).resolve()}[/bold]")
    return 0

def cmd_hash_evidence(args: argparse.Namespace) -> int:
    console.print(evidence_hash_cli(args.text))
    return 0

def cmd_web_evidence(args: argparse.Namespace) -> int:
    har = load_har(args.har)
    result = analyze_har(har)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    write_json(result, args.out)
    console.print(f"[green]OK[/green] Web evidence ditulis: [bold]{Path(args.out).resolve()}[/bold]")
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="alen-audit", description="Alen Audit Sistem Informasi (defensive)")
    p.add_argument("--no-banner", action="store_true", help="disable banner")
    sub = p.add_subparsers(dest="cmd", required=True)

    rp = sub.add_parser("report", help="Generate HTML report + heatmap dari findings JSON (defensive)")
    rp.add_argument("--input", required=True, help="path findings json")
    rp.add_argument("--outdir", default="out", help="folder output")
    rp.add_argument("--project", default="Audit SI", help="nama project")
    rp.add_argument("--owner", default="Alen", help="owner")
    rp.add_argument("--suppress", default=None, help="path suppressions.yml (opsional)")
    rp.set_defaults(func=cmd_report)

    ap = sub.add_parser("api-surface", help="Analyze OpenAPI spec (tanpa scanning)")
    ap.add_argument("--openapi", required=True, help="path openapi json")
    ap.add_argument("--out", default="out/api_surface.md", help="output markdown")
    ap.set_defaults(func=cmd_api_surface)

    we = sub.add_parser("web-evidence", help="Passive analysis dari HAR/response dump (tanpa request)")
    we.add_argument("--har", required=True, help="path HAR json")
    we.add_argument("--out", default="out/web_evidence.json", help="output json")
    we.set_defaults(func=cmd_web_evidence)

    he = sub.add_parser("hash-evidence", help="Buat evidence_hash untuk suppression rules")
    he.add_argument("--text", required=True, help="evidence text")
    he.set_defaults(func=cmd_hash_evidence)

    return p

def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.no_banner:
        console.print(BANNER)
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())

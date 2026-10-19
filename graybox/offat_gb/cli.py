"""Gray-box pipeline orchestrator and CLI.

Gray-box = white-box source analysis fused with a black-box endpoint surface,
analyzed by AI. No live traffic is sent. Stages:

    recon -> map endpoints (graft) -> hunt (SAST) -> reachability -> analyze (AI) -> report

It reuses the white-box recon and hunters and the shared triager's AI backends,
adds graft-based endpoint mapping and reachability, and spends AI tokens only on
findings reachable from a mapped endpoint (batched + cached + tiered).
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

from offat_triage import enrich_threats
from offat_wb import hunt, recon
from offat_wb.tools import ToolStatus, have

from . import analyze, graph_map, reachability, report


def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for f in findings:
        key = (f.get("vector_id"), f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def run_pipeline(target: str, classes: Optional[List[str]], *, use_ai: bool, use_semgrep: bool,
                 use_graft: bool, use_cache: bool, out_dir: str,
                 provider: Optional[str] = None) -> Dict[str, Any]:
    status = ToolStatus()

    print(f"[recon] scanning {target} ...")
    recon_info = recon.recon(target, status)
    print(f"[recon] languages: {recon_info['languages']}  manifests: {len(recon_info['manifests'])}")

    print("[map] mapping endpoint attack surface ...")
    endpoints = graph_map.map_endpoints(target, status, use_graft=use_graft)
    print(f"[map] {len(endpoints)} endpoint(s) discovered "
          f"({'graft' if status.available.get('graft_graph') else 'native'})")

    print("[hunt] built-in pattern hunter ...")
    findings = hunt.builtin_hunt(target, classes)
    if use_semgrep and have("semgrep"):
        status.available["semgrep"] = True
        print("[hunt] semgrep ...")
        findings += hunt.semgrep_hunt(target)
    else:
        status.available["semgrep"] = have("semgrep")
        if not have("semgrep"):
            status.skip("semgrep", "not installed")
    findings += recon_info.pop("dependency_findings", [])
    findings = _dedupe(findings)
    print(f"[hunt] {len(findings)} candidate findings")

    # Threat mapping: OWASP API Top 10 (2023) + OWASP Top 10 (2021) + CWE.
    enrich_threats(findings)

    print("[reach] linking findings to endpoints ...")
    findings = reachability.link(target, findings, endpoints, status)
    reachable = sum(1 for f in findings if f.get("reachable"))
    print(f"[reach] {reachable}/{len(findings)} findings reachable from a mapped endpoint")

    print("[analyze] AI triage (reachable-only, batched, cached) ...")
    source = analyze.analyze(findings, out_dir, provider=provider, use_ai=use_ai,
                             cache_enabled=use_cache)
    print(f"[analyze] triage source: {source}")

    rep = report.build_report(target, findings, endpoints, recon_info, source, status)
    report.write_all(out_dir, rep)
    print(f"[report] written to {out_dir}/ "
          f"(report.json, findings.jsonl, endpoints.json, results.sarif, report.md, report.html, report.junit.xml)")
    _print_summary(rep)
    return rep


def _print_summary(rep: Dict[str, Any]) -> None:
    s = rep["summary"]
    print("\n=== Gray-box summary ===")
    print(f"  endpoints mapped : {s['endpoints']}")
    print(f"  reachable        : {s['reachable_findings']}/{s['total']}")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if s["by_severity"].get(sev):
            print(f"  {sev:9} {s['by_severity'][sev]}")
    for v in ["confirmed", "likely", "inconclusive", "false_positive"]:
        if s["by_verdict"].get(v):
            print(f"    {v:15} {s['by_verdict'][v]}")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="offat-graybox",
        description="OFFAT-AI gray-box pipeline: map endpoints with graft, fuse with SAST, "
                    "and AI-analyze reachable findings (no live traffic).",
    )
    ap.add_argument("target", nargs="?", default=".", help="path to the codebase (default: .)")
    ap.add_argument("--classes", default="", help="comma-separated classes to hunt (default: all)")
    ap.add_argument("-o", "--out", default="offat-report/graybox", help="output directory")
    ap.add_argument("--no-ai", action="store_true", help="use heuristic triage only (no tokens)")
    ap.add_argument("--provider", default=None,
                    help="AI backend: auto (default), anthropic, claude-code, codex, heuristic")
    ap.add_argument("--no-semgrep", action="store_true", help="skip semgrep even if installed")
    ap.add_argument("--no-graft", action="store_true", help="skip graft; map endpoints natively")
    ap.add_argument("--no-cache", action="store_true", help="do not read/write the AI-verdict cache")
    ap.add_argument("--fail-on", default="",
                    help="exit non-zero if an actionable finding is at/above this severity "
                         "(critical|high|medium|low|info)")
    args = ap.parse_args(argv)

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    classes = [c.strip() for c in args.classes.split(",") if c.strip()] or None

    rep = run_pipeline(
        target, classes, use_ai=not args.no_ai, use_semgrep=not args.no_semgrep,
        use_graft=not args.no_graft, use_cache=not args.no_cache, out_dir=args.out,
        provider=args.provider,
    )

    if args.fail_on:
        n = report.count_at_or_above(rep, args.fail_on)
        if n > 0:
            print(f"\nfail-on: {n} finding(s) at or above severity {args.fail_on!r} - exiting non-zero",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

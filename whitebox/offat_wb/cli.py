"""White-box pipeline orchestrator and CLI.

Stages: recon -> hunt (builtin + semgrep) -> chain -> verify (triage) -> report.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List

from . import hunt, recon, report, trace
from .tools import ToolStatus, have

# Import the shared triager, falling back to the sibling repo package when the
# distribution is not installed.
try:  # pragma: no cover
    from offat_triage import tiered_triage, enrich_threats
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "triager")))
    from offat_triage import tiered_triage, enrich_threats


def _dedupe(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for f in findings:
        key = (f.get("vector_id"), f.get("file"), f.get("line"))
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _chain(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Stage 3 — light attack-path composition.

    Annotates findings that are co-located (same file) with a higher-severity
    partner, e.g. a hardcoded secret next to an outbound request, or a source
    and a dangerous sink in the same module.
    """
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_file.setdefault(f.get("file", ""), []).append(f)
    for group in by_file.values():
        classes = {f.get("class") for f in group}
        if len(classes) > 1 and len(group) > 1:
            partners = ", ".join(sorted(classes))
            for f in group:
                f.setdefault("evidence", {})["chain"] = f"co-located with: {partners}"
    return findings


def run_pipeline(target: str, classes: List[str] | None, use_ai: bool,
                 use_semgrep: bool, out_dir: str, provider: str | None = None,
                 use_graft: bool = True, use_cache: bool = True) -> Dict[str, Any]:
    status = ToolStatus()
    print(f"[recon] scanning {target} ...")
    recon_info = recon.recon(target, status)
    print(f"[recon] languages: {recon_info['languages']}  manifests: {len(recon_info['manifests'])}  "
          f"sbom: {recon_info['sbom_components']}  dep-cves: {len(recon_info['dependency_findings'])}")

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

    if use_graft:
        print("[trace] source-to-sink tracing (graft) ...")
        findings = trace.trace(target, findings, status)
        traced = sum(1 for f in findings if f.get("traced"))
        if status.available.get("graft_graph"):
            print(f"[trace] {traced}/{len(findings)} findings reachable from an entry point")

    print("[chain] composing attack paths ...")
    findings = _chain(findings)

    print("[verify] triaging (cached, batched, tiered) ...")
    source = tiered_triage(findings, out_dir, provider=provider, use_ai=use_ai,
                           cache_enabled=use_cache)
    print(f"[verify] triage source: {source}")

    rep = report.build_report(target, findings, recon_info, source, status)
    report.write_all(out_dir, rep)
    print(f"[report] written to {out_dir}/ "
          f"(report.json, findings.jsonl, results.sarif, report.md, report.html, report.junit.xml)")
    _print_summary(rep)
    return rep


def _print_summary(rep: Dict[str, Any]) -> None:
    s = rep["summary"]
    print("\n=== Summary ===")
    for sev in ["critical", "high", "medium", "low", "info"]:
        if s["by_severity"].get(sev):
            print(f"  {sev:9} {s['by_severity'][sev]}")
    for v in ["confirmed", "likely", "inconclusive", "false_positive"]:
        if s["by_verdict"].get(v):
            print(f"    {v:15} {s['by_verdict'][v]}")


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="offat-whitebox",
        description="OFFAT-AI white-box (SAST) pipeline: recon -> hunt -> chain -> verify -> report",
    )
    ap.add_argument("target", nargs="?", default=".", help="path to the codebase (default: .)")
    ap.add_argument("--classes", default="", help="comma-separated classes to hunt (default: all)")
    ap.add_argument("-o", "--out", default="offat-report/whitebox", help="output directory")
    ap.add_argument("--no-ai", action="store_true", help="use heuristic triage only")
    ap.add_argument("--provider", default=None,
                    help="AI backend: auto (default), anthropic, claude-code, codex, heuristic")
    ap.add_argument("--no-semgrep", action="store_true", help="skip semgrep even if installed")
    ap.add_argument("--no-graft", action="store_true", help="skip graft source-to-sink tracing")
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
    rep = run_pipeline(target, classes, use_ai=not args.no_ai,
                       use_semgrep=not args.no_semgrep, out_dir=args.out,
                       provider=args.provider, use_graft=not args.no_graft,
                       use_cache=not args.no_cache)

    if args.fail_on:
        n = report.count_at_or_above(rep, args.fail_on)
        if n > 0:
            print(f"\nfail-on: {n} finding(s) at or above severity {args.fail_on!r} - exiting non-zero",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

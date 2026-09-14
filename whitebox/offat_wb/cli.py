"""White-box pipeline orchestrator and CLI.

Stages: recon -> hunt (builtin + semgrep) -> chain -> verify (triage) -> report.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List

from . import hunt, recon, report
from .tools import ToolStatus, have

# Import the shared triager, falling back to the sibling repo package when the
# distribution is not installed.
try:  # pragma: no cover
    from offat_triage import triage_findings
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "triager")))
    from offat_triage import triage_findings


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
                 use_semgrep: bool, out_dir: str) -> Dict[str, Any]:
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

    print("[chain] composing attack paths ...")
    findings = _chain(findings)

    print("[verify] triaging ...")
    source = triage_findings(findings, use_ai=use_ai)
    print(f"[verify] triage source: {source}")

    rep = report.build_report(target, findings, recon_info, source, status)
    report.write_all(out_dir, rep)
    print(f"[report] written to {out_dir}/ (report.json, findings.jsonl, results.sarif, report.md, report.html)")
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
    ap.add_argument("--no-semgrep", action="store_true", help="skip semgrep even if installed")
    args = ap.parse_args(argv)

    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    classes = [c.strip() for c in args.classes.split(",") if c.strip()] or None
    run_pipeline(target, classes, use_ai=not args.no_ai,
                 use_semgrep=not args.no_semgrep, out_dir=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

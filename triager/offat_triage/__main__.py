"""CLI: re-triage a findings file (JSON report or JSONL) with the shared triager.

    python -m offat_triage findings.jsonl --no-ai -o triaged.json
    offat-triage offat-report/report.json           # if installed

Accepts either a DAST report (``{"findings": [...]}``) or a JSONL/JSON array of
findings, and prints a short summary.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from typing import Any, Dict, List

from .triager import triage_findings


def _load(path: str) -> (List[Dict[str, Any]], Dict[str, Any]):
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read().strip()
    if not text:
        return [], {}
    # Try full JSON first (report object or array).
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and "findings" in obj:
            return obj["findings"], obj
        if isinstance(obj, list):
            return obj, {}
        if isinstance(obj, dict):
            return [obj], {}
    except json.JSONDecodeError:
        pass
    # Fall back to JSONL.
    findings = [json.loads(line) for line in text.splitlines() if line.strip()]
    return findings, {}


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="offat-triage", description="Re-triage OFFAT-AI findings")
    ap.add_argument("input", help="findings file (JSON report, JSON array, or JSONL)")
    ap.add_argument("-o", "--out", help="write triaged findings to this file (JSON)")
    ap.add_argument("--no-ai", action="store_true", help="use the heuristic triager only")
    ap.add_argument("--concurrency", type=int, default=4)
    args = ap.parse_args(argv)

    findings, wrapper = _load(args.input)
    if not findings:
        print("no findings to triage", file=sys.stderr)
        return 0

    source = triage_findings(findings, use_ai=not args.no_ai, concurrency=args.concurrency)
    print(f"triaged {len(findings)} findings via {source}")

    verdicts = Counter((f.get("triage") or {}).get("verdict", "?") for f in findings)
    for verdict, count in verdicts.most_common():
        print(f"  {verdict:15} {count}")

    if args.out:
        out: Any = wrapper if wrapper else findings
        if wrapper:
            wrapper["findings"] = findings
            wrapper["triage_source"] = source
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2)
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

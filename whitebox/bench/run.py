"""Benchmark the code-graph taint engine against a labeled answer key.

Runs ``offat_wb.cpg.analyze`` on each target in ``answer_key.json`` and scores
the proven flows against the ground truth:

* **true positive**  - an expected (file, class) flow the engine proved.
* **false negative**  - an expected flow it missed (hurts recall / true-positive rate).
* **false positive**  - a flow on a route labeled *silent* (a safe twin), or an
  unexpected (file, class) flow not in the answer key (hurts precision).

It reports precision, recall and F1 overall and per class, and can gate CI with
``--fail-under-recall`` / ``--fail-under-precision``. A target whose ``path`` is
missing, or that needs tree-sitter when it is not installed, is skipped (CI runs
the pure-Python targets hermetically; richer targets run locally).

    python whitebox/bench/run.py
    python whitebox/bench/run.py --fail-under-recall 1.0 --fail-under-precision 1.0
    python whitebox/bench/run.py --json out.json --markdown out.md
    python whitebox/bench/run.py --key custom.json --target ./myapp
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
WB = os.path.abspath(os.path.join(HERE, ".."))
if WB not in sys.path:
    sys.path.insert(0, WB)
TRIAGER = os.path.abspath(os.path.join(WB, "..", "triager"))
if os.path.isdir(TRIAGER) and TRIAGER not in sys.path:
    sys.path.insert(0, TRIAGER)

from offat_wb import cpg  # noqa: E402

try:
    import tree_sitter_language_pack  # noqa: F401
    HAVE_TS = True
except ImportError:
    HAVE_TS = False


def _routes(finding: Dict[str, Any]) -> List[str]:
    return finding.get("reachable_from") or []


def score_target(root: str, target: Dict[str, Any]) -> Dict[str, Any]:
    """Score one target. Returns per-class counts and the concrete mismatches."""
    path = os.path.join(root, target["path"]) if not os.path.isabs(target["path"]) else target["path"]
    result = cpg.analyze(path)

    # Expected flows (skip tree-sitter-only expectations when it is unavailable).
    expected: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for e in target.get("expect", []):
        if e.get("needs_tree_sitter") and not HAVE_TS:
            continue
        expected[(e["file"], e["class"])] = e
    silent = set(target.get("silent", []))

    got: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in result.findings:
        got.setdefault((f["file"], f["class"]), f)

    tp: Dict[str, int] = defaultdict(int)
    fn: Dict[str, int] = defaultdict(int)
    fp: Dict[str, int] = defaultdict(int)
    misses: List[str] = []
    spurious: List[str] = []

    for key, e in expected.items():
        if key in got:
            tp[e["class"]] += 1
        else:
            fn[e["class"]] += 1
            misses.append(f"MISS  {e['class']:16} {e['file']}  (route {e.get('route', '?')})")

    for key, f in got.items():
        file, cls = key
        on_silent = any(r in silent for r in _routes(f))
        if key not in expected or on_silent:
            fp[cls] += 1
            why = "safe-twin route" if on_silent else "not in answer key"
            spurious.append(f"FP    {cls:16} {file}:{f.get('line')}  ({why}; "
                            f"routes {', '.join(_routes(f)) or 'none'})")

    classes = sorted(set(tp) | set(fn) | set(fp))
    per_class = {c: {"tp": tp[c], "fn": fn[c], "fp": fp[c]} for c in classes}
    return {
        "name": target["name"], "path": target["path"],
        "tp": sum(tp.values()), "fn": sum(fn.values()), "fp": sum(fp.values()),
        "per_class": per_class, "misses": misses, "spurious": spurious,
        "flows": len(result.findings), "functions": result.stats.get("nodes.function", 0),
    }


def _prf(tp: int, fn: int, fp: int) -> Tuple[float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def run(key_path: str, root: str, only_target: Optional[str] = None) -> Dict[str, Any]:
    with open(key_path, encoding="utf-8") as fh:
        key = json.load(fh)
    results, skipped = [], []
    for target in key["targets"]:
        if only_target and target["name"] != only_target:
            continue
        path = os.path.join(root, target["path"]) if not os.path.isabs(target["path"]) else target["path"]
        if not os.path.isdir(path):
            skipped.append(f"{target['name']} (path not found: {target['path']})")
            continue
        if target.get("needs_tree_sitter") and not HAVE_TS:
            skipped.append(f"{target['name']} (needs tree-sitter; not installed)")
            continue
        results.append(score_target(root, target))
    tp = sum(r["tp"] for r in results)
    fn = sum(r["fn"] for r in results)
    fp = sum(r["fp"] for r in results)
    precision, recall, f1 = _prf(tp, fn, fp)
    agg: Dict[str, Dict[str, int]] = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})
    for r in results:
        for c, v in r["per_class"].items():
            for k in ("tp", "fn", "fp"):
                agg[c][k] += v[k]
    return {
        "targets": results, "skipped": skipped,
        "tp": tp, "fn": fn, "fp": fp,
        "precision": precision, "recall": recall, "f1": f1,
        "per_class": {c: dict(v, **dict(zip(("precision", "recall", "f1"),
                                            _prf(v["tp"], v["fn"], v["fp"])))) for c, v in sorted(agg.items())},
    }


def to_markdown(report: Dict[str, Any]) -> str:
    L = ["# OFFAT code-graph benchmark", "",
         f"**Recall (true-positive rate):** {report['recall']:.1%}  ·  "
         f"**Precision:** {report['precision']:.1%}  ·  **F1:** {report['f1']:.3f}",
         f"TP {report['tp']} · FN {report['fn']} · FP {report['fp']}", "",
         "| Class | TP | FN | FP | Recall | Precision |", "|---|--:|--:|--:|--:|--:|"]
    for c, v in report["per_class"].items():
        L.append(f"| {c} | {v['tp']} | {v['fn']} | {v['fp']} | {v['recall']:.0%} | {v['precision']:.0%} |")
    L += ["", "| Target | Functions | Flows | TP | FN | FP |", "|---|--:|--:|--:|--:|--:|"]
    for r in report["targets"]:
        L.append(f"| {r['name']} | {r['functions']} | {r['flows']} | {r['tp']} | {r['fn']} | {r['fp']} |")
    if report["skipped"]:
        L += ["", "_Skipped:_ " + "; ".join(report["skipped"])]
    return "\n".join(L) + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Benchmark the code-graph taint engine.")
    ap.add_argument("--key", default=os.path.join(HERE, "answer_key.json"))
    ap.add_argument("--root", default=WB, help="root the target paths are relative to")
    ap.add_argument("--target", default=None, help="score only this named target")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--markdown", dest="md_out", default=None)
    ap.add_argument("--fail-under-recall", type=float, default=0.0)
    ap.add_argument("--fail-under-precision", type=float, default=0.0)
    args = ap.parse_args(argv)

    report = run(args.key, args.root, args.target)
    print(to_markdown(report))
    for r in report["targets"]:
        for line in r["misses"] + r["spurious"]:
            print(f"  [{r['name']}] {line}")
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as fh:
            fh.write(to_markdown(report))

    rc = 0
    if report["recall"] < args.fail_under_recall:
        print(f"::error::recall {report['recall']:.3f} < required {args.fail_under_recall}", file=sys.stderr)
        rc = 1
    if report["precision"] < args.fail_under_precision:
        print(f"::error::precision {report['precision']:.3f} < required {args.fail_under_precision}", file=sys.stderr)
        rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

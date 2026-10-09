"""offat-platform - orchestrate the OFFAT-AI platform stages over a Bundle.

Phase 1 implements the `map` subcommand (attack surface + inventory + parameter
relation graph) and `validate` (check a Bundle against the schema). Later phases
add `threat-model`, `test-gen`, `execute`, `triage`, `report`.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

import offat_bundle as ob

import os.path as _osp

from . import consolidate, mapping, prg, testgen, threat_model


def _cmd_map(args) -> int:
    target = os.path.abspath(args.target)
    if not os.path.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    classes = [c.strip() for c in (args.classes or "").split(",") if c.strip()] or None

    bundle = ob.new_bundle(target={"source_path": target})
    print(f"[map] scanning {target} ...")
    mapping.map_target(bundle, target, use_graft=not args.no_graft, classes=classes)
    eps = (bundle.get("asm") or {}).get("endpoints", [])
    sinks = (bundle.get("inventory") or {}).get("sinks", [])
    srcs = (bundle.get("inventory") or {}).get("sources", [])
    print(f"[map] endpoints: {len(eps)}  sinks: {len(sinks)}  sources: {len(srcs)}")

    print("[prg] building parameter relation graph ...")
    stats = prg.build(bundle)
    print(f"[prg] producers: {stats['producers']}  consumers: {stats['consumers']}  edges: {stats['edges']}")

    if args.threat_model:
        print("[threat] modeling ...")
        ts = threat_model.build(bundle)
        print(f"[threat] assets: {ts['assets']}  threats: {ts['threats']}  dataflows: {ts['dataflows']}")

    problems = ob.validate_bundle(bundle)
    if problems:
        print("[warn] bundle validation issues:", file=sys.stderr)
        for p in problems[:10]:
            print("  -", p, file=sys.stderr)

    out = args.out
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    ob.save(bundle, out)
    print(f"[bundle] written to {out}")
    return 0


def _cmd_threat_model(args) -> int:
    bundle = ob.load(args.bundle)
    print("[threat] modeling ...")
    ts = threat_model.build(bundle)
    print(f"[threat] assets: {ts['assets']}  threats: {ts['threats']}  dataflows: {ts['dataflows']}")
    out = args.out or args.bundle
    ob.save(bundle, out)
    print(f"[bundle] written to {out}")
    return 0


def _cmd_test_gen(args) -> int:
    bundle = ob.load(args.bundle)
    print("[test-gen] generating test cases ...")
    stats = testgen.build(bundle, use_ai=args.ai, provider=args.provider)
    print(f"[test-gen] rule: {stats['rule']}  ai: {stats['ai']}  total: {stats['total']}")
    out = args.out or args.bundle
    ob.save(bundle, out)
    print(f"[bundle] written to {out}")
    return 0


def _cmd_triage(args) -> int:
    bundle = ob.load(args.bundle)
    out = args.out or args.bundle
    out_dir = _osp.dirname(_osp.abspath(out)) or "."
    print("[triage] consolidating + triaging findings ...")
    summary = consolidate.build(bundle, out_dir, use_ai=not args.no_ai,
                                provider=args.provider, cache_enabled=not args.no_cache)
    print(f"[triage] findings: {summary['findings']}  source: {summary['triage_source']}")
    print(f"[triage] by severity: {summary['by_severity']}")
    ob.save(bundle, out)
    print(f"[bundle] written to {out}")
    if args.fail_on:
        from offat_bundle import validate  # noqa: F401
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        thr = rank.get(args.fail_on.lower())
        if thr is not None:
            n = sum(1 for f in bundle.get("findings", [])
                    if rank.get(f.get("severity", ""), 9) <= thr
                    and (f.get("triage") or {}).get("verdict") != "false_positive")
            if n > 0:
                print(f"\nfail-on: {n} finding(s) at or above {args.fail_on!r}", file=sys.stderr)
                return 1
    return 0


def _cmd_validate(args) -> int:
    bundle = ob.load(args.bundle)
    problems = ob.validate_bundle(bundle) + ob.cross_refs(bundle)
    if problems:
        for p in problems:
            print("-", p)
        print(f"\n{len(problems)} problem(s)")
        return 1
    print("bundle is valid")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="offat-platform",
        description="OFFAT-AI platform orchestrator (Bundle-based pipeline)",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("map", help="map attack surface + inventory + PRG into a Bundle")
    m.add_argument("target", help="path to the codebase")
    m.add_argument("-o", "--out", default="offat-report/bundle.offat.json", help="output Bundle path")
    m.add_argument("--classes", default="", help="comma-separated vuln classes for the hunter")
    m.add_argument("--no-graft", action="store_true", help="map endpoints natively (skip graft)")
    m.add_argument("--threat-model", action="store_true", help="also build the threat model")
    m.set_defaults(func=_cmd_map)

    tmp = sub.add_parser("threat-model", help="add a threat model to an existing Bundle")
    tmp.add_argument("bundle", help="path to a .offat.json Bundle")
    tmp.add_argument("-o", "--out", default="", help="output path (default: in place)")
    tmp.set_defaults(func=_cmd_threat_model)

    tg = sub.add_parser("test-gen", help="generate a test plan into an existing Bundle")
    tg.add_argument("bundle", help="path to a .offat.json Bundle")
    tg.add_argument("-o", "--out", default="", help="output path (default: in place)")
    tg.add_argument("--ai", action="store_true", help="augment with AI-generated payloads")
    tg.add_argument("--provider", default=None, help="AI backend (auto|anthropic|...)")
    tg.set_defaults(func=_cmd_test_gen)

    tr = sub.add_parser("triage", help="consolidate + triage findings into a Bundle")
    tr.add_argument("bundle", help="path to a .offat.json Bundle")
    tr.add_argument("-o", "--out", default="", help="output path (default: in place)")
    tr.add_argument("--no-ai", action="store_true", help="heuristic triage only")
    tr.add_argument("--no-cache", action="store_true", help="do not read/write the verdict cache")
    tr.add_argument("--provider", default=None, help="AI backend (auto|anthropic|...)")
    tr.add_argument("--fail-on", default="", help="exit non-zero if an actionable finding is at/above this severity")
    tr.set_defaults(func=_cmd_triage)

    v = sub.add_parser("validate", help="validate a Bundle against the schema")
    v.add_argument("bundle", help="path to a .offat.json Bundle")
    v.set_defaults(func=_cmd_validate)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

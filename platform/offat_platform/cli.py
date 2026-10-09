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

from . import mapping, prg


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
    m.set_defaults(func=_cmd_map)

    v = sub.add_parser("validate", help="validate a Bundle against the schema")
    v.add_argument("bundle", help="path to a .offat.json Bundle")
    v.set_defaults(func=_cmd_validate)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

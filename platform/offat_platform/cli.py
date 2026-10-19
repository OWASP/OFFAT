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

from . import consolidate, identities as idmod, mapping, prg, testgen, threat_model


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
    ids = idmod.load(args.identities) if getattr(args, "identities", "") else []
    if ids:
        bundle.setdefault("meta", {})["identities"] = idmod.redacted(idmod.with_anon(ids))
        print(f"[test-gen] {len(ids)} identities loaded (access-control/auth tests enabled)")
    print("[test-gen] generating test cases ...")
    stats = testgen.build(bundle, use_ai=args.ai, provider=args.provider, identities=ids)
    print(f"[test-gen] rule: {stats['rule']} (authz: {stats.get('authz',0)}, "
          f"business: {stats.get('business',0)}, ws: {stats.get('websocket',0)}, "
          f"grpc: {stats.get('grpc',0)})  ai: {stats['ai']}  total: {stats['total']}")
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


def _find_engine() -> Optional[str]:
    """Locate the offat-engine binary: $OFFAT_ENGINE, then PATH, then the
    repo-local build (release preferred, then debug)."""
    import shutil

    env = os.environ.get("OFFAT_ENGINE")
    if env and _osp.isfile(env):
        return env
    on_path = shutil.which("offat-engine")
    if on_path:
        return on_path
    repo = _osp.abspath(_osp.join(_osp.dirname(__file__), "..", ".."))
    exe = "offat-engine.exe" if os.name == "nt" else "offat-engine"
    for profile in ("release", "debug"):
        cand = _osp.join(repo, "engine-rs", "target", profile, exe)
        if _osp.isfile(cand):
            return cand
    return None


def _run_engine(engine: str, bundle_path: str, args) -> int:
    """Invoke the Rust engine to execute the test plan against the target."""
    import subprocess

    cmd = [engine, "--bundle", bundle_path, "--url", args.url,
           "--concurrency", str(args.concurrency), "--rate", str(args.rate),
           "--timeout", str(args.timeout)]
    if args.identities:
        cmd += ["--identities", args.identities]
    for h in (args.header or []):
        cmd += ["-H", h]
    if args.insecure:
        cmd.append("--insecure")
    cmd.append("--yes")  # authorization already gated in _cmd_run
    print(f"[execute] {engine} --url {args.url} ...")
    try:
        return subprocess.call(cmd)
    except OSError as e:
        print(f"error: could not run the engine: {e}", file=sys.stderr)
        return 1


def _run_report(bundle_path: str, out_dir: str, formats: str) -> int:
    """Render reports, in-process when the reporter is importable, else via CLI."""
    argv = [bundle_path, "-o", out_dir, "--formats", formats]
    try:
        from offat_report.cli import main as report_main
        return report_main(argv)
    except Exception:
        import shutil
        import subprocess
        exe = shutil.which("offat-report")
        if exe:
            return subprocess.call([exe] + argv)
        return subprocess.call([sys.executable, "-m", "offat_report"] + argv)


def _cmd_run(args) -> int:
    """Run the complete pipeline in one go: map -> prg -> threat-model ->
    test-gen -> execute (engine) -> triage -> report."""
    target = _osp.abspath(args.target)
    if not _osp.isdir(target):
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2

    # Authorization gate: executing against a live URL sends real traffic.
    if args.url and not args.yes:
        print("WARNING: --url sends active attack traffic to " + args.url, file=sys.stderr)
        print("Only scan systems you own or are authorized to test. Re-run with --yes.",
              file=sys.stderr)
        return 3

    out = args.out
    os.makedirs(_osp.dirname(_osp.abspath(out)) or ".", exist_ok=True)
    reports_dir = args.report_dir or _osp.join(_osp.dirname(_osp.abspath(out)) or ".", "reports")

    classes = [c.strip() for c in (args.classes or "").split(",") if c.strip()] or None

    # 1) map + prg + threat model
    bundle = ob.new_bundle(target={"source_path": target, "base_url": args.url or ""})
    print(f"[map] scanning {target} ...")
    mapping.map_target(bundle, target, use_graft=not args.no_graft, classes=classes)
    eps = (bundle.get("asm") or {}).get("endpoints", [])
    print(f"[map] endpoints: {len(eps)}")
    prg.build(bundle)
    if not args.no_threat_model:
        threat_model.build(bundle)

    # 2) test-gen
    ids = idmod.load(args.identities) if args.identities else []
    if ids:
        bundle.setdefault("meta", {})["identities"] = idmod.redacted(idmod.with_anon(ids))
        print(f"[test-gen] {len(ids)} identities loaded")
    stats = testgen.build(bundle, use_ai=args.ai, provider=args.provider, identities=ids)
    print(f"[test-gen] {stats['total']} cases "
          f"(ws: {stats.get('websocket', 0)}, grpc: {stats.get('grpc', 0)})")
    ob.save(bundle, out)
    print(f"[bundle] written to {out}")

    # 3) execute (only against an authorized live URL)
    if args.url:
        engine = _find_engine()
        if not engine:
            print("error: offat-engine not found. Build it (`make engine`) or set "
                  "$OFFAT_ENGINE, or omit --url for a source-only run.", file=sys.stderr)
            return 1
        rc = _run_engine(engine, out, args)
        if rc != 0:
            print(f"[execute] engine exited {rc}; continuing to triage with whatever "
                  "results were captured.", file=sys.stderr)
        bundle = ob.load(out)  # engine wrote results back
    else:
        print("[execute] no --url given; source-only run (SAST findings only).")

    # 4) triage
    out_dir = _osp.dirname(_osp.abspath(out)) or "."
    summary = consolidate.build(bundle, out_dir, use_ai=not args.no_ai,
                                provider=args.provider, cache_enabled=not args.no_cache)
    ob.save(bundle, out)
    print(f"[triage] findings: {summary['findings']}  by severity: {summary['by_severity']}")

    # 5) report
    if not args.no_report:
        _run_report(out, reports_dir, args.formats)
        print(f"[report] written to {reports_dir}")

    # fail-on gate
    if args.fail_on:
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
    tg.add_argument("--identities", default="", help="JSON file of identities for BOLA/BFLA/RBAC/auth tests")
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

    r = sub.add_parser("run", help="run the whole pipeline in one go: map -> prg -> "
                                   "threat-model -> test-gen -> execute -> triage -> report")
    r.add_argument("target", help="path to the codebase")
    r.add_argument("--url", default="", help="base URL of an authorized live target "
                                             "(omit for a source-only run)")
    r.add_argument("-o", "--out", default="offat-report/bundle.offat.json", help="output Bundle path")
    r.add_argument("--report-dir", default="", help="reports directory (default: <bundle dir>/reports)")
    r.add_argument("--formats", default="all", help="report formats (sarif,md,html,compliance,pdf or 'all')")
    r.add_argument("--identities", default="", help="JSON file of identities for BOLA/BFLA/RBAC/auth tests")
    r.add_argument("--classes", default="", help="comma-separated vuln classes for the hunter")
    r.add_argument("--no-graft", action="store_true", help="map endpoints natively (skip graft)")
    r.add_argument("--no-threat-model", action="store_true", help="skip threat modeling")
    r.add_argument("--ai", action="store_true", help="augment test-gen with AI payloads")
    r.add_argument("--no-ai", action="store_true", help="heuristic triage only (no AI)")
    r.add_argument("--no-cache", action="store_true", help="do not read/write the verdict cache")
    r.add_argument("--no-report", action="store_true", help="skip rendering reports")
    r.add_argument("--provider", default=None, help="AI backend (auto|anthropic|claude-code|codex|heuristic)")
    r.add_argument("--concurrency", type=int, default=10, help="engine concurrent requests")
    r.add_argument("--rate", type=float, default=25.0, help="engine max requests/sec (0 = unlimited)")
    r.add_argument("--timeout", type=int, default=15, help="engine per-request timeout (s)")
    r.add_argument("--insecure", action="store_true", help="engine: skip TLS verification")
    r.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: Value' (repeatable)")
    r.add_argument("--fail-on", default="", help="exit non-zero if an actionable finding is at/above this severity")
    r.add_argument("--yes", action="store_true", help="confirm authorization to send live traffic to --url")
    r.set_defaults(func=_cmd_run)

    v = sub.add_parser("validate", help="validate a Bundle against the schema")
    v.add_argument("bundle", help="path to a .offat.json Bundle")
    v.set_defaults(func=_cmd_validate)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

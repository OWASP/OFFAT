"""White-box pipeline orchestrator and CLI.

Stages: recon -> graph (code-graph taint) + hunt (patterns) -> chain -> verify (triage,
optional graph-tool agent) -> report. semgrep is opt-in (``--semgrep``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

from . import cpg, hunt, recon, report, trace
from .tools import ToolStatus, have

# Import the shared triager, falling back to the sibling repo package when the
# distribution is not installed.
try:  # pragma: no cover
    from offat_triage import tiered_triage, reachable_triage, enrich_threats
except ImportError:  # pragma: no cover
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "triager")))
    from offat_triage import tiered_triage, reachable_triage, enrich_threats


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
                 use_graft: bool = True, use_cache: bool = True, use_graph: bool = True,
                 spec_file: str | None = None, local_sources: bool = False,
                 graph_out: bool = False, agent: int = 0, infer_specs: bool = False,
                 reachable_only: bool = False) -> Dict[str, Any]:
    status = ToolStatus()
    print(f"[recon] scanning {target} ...")
    recon_info = recon.recon(target, status)
    print(f"[recon] languages: {recon_info['languages']}  manifests: {len(recon_info['manifests'])}  "
          f"sbom: {recon_info['sbom_components']}  dep-cves: {len(recon_info['dependency_findings'])}")

    os.makedirs(out_dir, exist_ok=True)
    graph = None
    graph_findings: List[Dict[str, Any]] = []
    status.available["code_graph"] = use_graph and cpg.AVAILABLE
    if use_graph and cpg.AVAILABLE:
        print("[graph] building code graph + source-to-sink taint search ...")
        res = cpg.analyze(target, classes=classes, local_sources=local_sources, spec_file=spec_file)
        if infer_specs:
            from .cpg import infer
            items = infer.frontier(res.graph)
            with open(os.path.join(out_dir, "taint-frontier.json"), "w", encoding="utf-8") as fh:
                json.dump(items, fh, indent=2)
            labels = infer.classify(items, provider=provider) if use_ai else []
            if labels:
                spec_file = os.path.join(out_dir, "inferred-specs.json")
                spec = infer.to_spec_file(labels, spec_file)
                print(f"[graph] AI-inferred {len(spec['sinks'])} sink(s) / {len(spec['sanitizers'])} "
                      f"sanitizer(s) from {len(items)} frontier callee(s); re-running")
                res = cpg.analyze(target, classes=classes, local_sources=local_sources, spec_file=spec_file)
            else:
                print(f"[graph] taint frontier: {len(items)} unknown callee(s) receive attacker data "
                      "(taint-frontier.json)")
        graph, graph_findings = res.graph, res.findings
        for note in res.notes:
            status.notes.append(f"graph: {note}")
        print(f"[graph] {res.stats.get('nodes.function', 0)} functions, {res.stats.get('entrypoints', 0)} "
              f"entry points, {len(graph_findings)} proven source-to-sink flow(s)")
        if graph_out:
            graph.to_json(os.path.join(out_dir, "cpg.json"))
            graph.to_graphml(os.path.join(out_dir, "cpg.graphml"))
            print(f"[graph] exported {out_dir}/cpg.json and cpg.graphml")
    elif use_graph:
        status.skip("code_graph", "networkx not installed (pip install 'offat-whitebox[graph]')")

    print("[hunt] built-in pattern hunter ...")
    findings = hunt.builtin_hunt(target, classes)
    if use_semgrep and have("semgrep"):
        status.available["semgrep"] = True
        print("[hunt] semgrep (opt-in) ...")
        findings += hunt.semgrep_hunt(target)
    else:
        status.available["semgrep"] = False

    findings += recon_info.pop("dependency_findings", [])
    findings = _dedupe(findings)
    if graph is not None:
        findings = cpg.merge_with_patterns(graph, graph_findings, findings)
    print(f"[hunt] {len(findings)} candidate findings")

    # Threat mapping: OWASP API Top 10 (2023) + OWASP Top 10 (2021) + CWE.
    enrich_threats(findings)

    if use_graft and graph is None:
        print("[trace] source-to-sink tracing (graft) ...")
        findings = trace.trace(target, findings, status)
        traced = sum(1 for f in findings if f.get("traced"))
        if status.available.get("graft_graph"):
            print(f"[trace] {traced}/{len(findings)} findings reachable from an entry point")

    print("[chain] composing attack paths ...")
    findings = _chain(findings)

    tkw = {"system": cpg.GRAPH_SYSTEM, "block_fn": cpg.triage_block} if graph is not None else {}
    if reachable_only and graph is not None:
        print("[verify] triaging reachable-only (cached, batched, tiered) ...")
        source = reachable_triage(findings, out_dir, provider=provider, use_ai=use_ai,
                                  cache_enabled=use_cache, **tkw)
    else:
        print("[verify] triaging (cached, batched, tiered) ...")
        source = tiered_triage(findings, out_dir, provider=provider, use_ai=use_ai,
                               cache_enabled=use_cache, **tkw)
    print(f"[verify] triage source: {source}")
    if agent and use_ai and graph is not None:
        from .cpg.agent import make_agent_verifier, agent_verify
        verifier = make_agent_verifier(graph, target, provider)
        if verifier is None:
            status.skip("agent", "no API key and no claude-code/codex CLI available")
        else:
            n = agent_verify(findings, verifier, limit=agent)
            source += f" + agent:{verifier.model}({n})"
            print(f"[verify] graph-tool agent re-verified {n} finding(s)")

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
    ap.add_argument("--semgrep", action="store_true",
                    help="also run semgrep --config auto (opt-in; the code graph is the default engine)")
    ap.add_argument("--no-semgrep", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--no-graph", action="store_true", help="skip the code-graph taint engine")
    ap.add_argument("--specs", default=None, help="extra source/sink/sanitizer specs (JSON)")
    ap.add_argument("--local-sources", action="store_true",
                    help="also treat argv/env/stdin as sources (CLI tools, scripts)")
    ap.add_argument("--graph-out", action="store_true", help="export the code graph (JSON + GraphML)")
    ap.add_argument("--agent", type=int, default=0, metavar="N",
                    help="re-verify the top N graph findings with an AI agent (Anthropic API key, or the "
                         "claude-code / codex CLI via --provider / OFFAT_AI_PROVIDER)")
    ap.add_argument("--infer-specs", action="store_true",
                    help="list the taint frontier and (with an API key) let AI infer missing sinks/sanitizers")
    ap.add_argument("--no-graft", action="store_true", help="skip graft tracing (used only with --no-graph)")
    ap.add_argument("--baseline", default="", metavar="FILE",
                    help="JSON baseline of accepted finding fingerprints; matching findings are "
                         "suppressed from the --fail-on gate (adopt the scanner without drowning in "
                         "pre-existing findings)")
    ap.add_argument("--write-baseline", default="", metavar="FILE",
                    help="write the current findings' fingerprints to FILE (then review/commit it)")
    ap.add_argument("--reachable-only", action="store_true",
                    help="spend AI tokens only on findings reachable from an endpoint; triage the rest "
                         "offline and cap them at inconclusive (the gray-box token-discipline policy)")
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
                       use_semgrep=args.semgrep and not args.no_semgrep, out_dir=args.out,
                       provider=args.provider, use_graft=not args.no_graft,
                       use_cache=not args.no_cache, use_graph=not args.no_graph,
                       spec_file=args.specs, local_sources=args.local_sources,
                       graph_out=args.graph_out, agent=args.agent, infer_specs=args.infer_specs,
                       reachable_only=args.reachable_only)

    # Stamp stable fingerprints, then apply the baseline (suppress known findings).
    from offat_triage import finding_fingerprint
    for f in rep.get("findings", []):
        f.setdefault("fingerprint", finding_fingerprint(f))
    if args.write_baseline:
        fps = sorted({f["fingerprint"] for f in rep.get("findings", [])})
        with open(args.write_baseline, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "fingerprints": fps}, fh, indent=2)
        print(f"[baseline] wrote {len(fps)} fingerprint(s) to {args.write_baseline}")
    if args.baseline:
        try:
            with open(args.baseline, encoding="utf-8") as fh:
                known = set(json.load(fh).get("fingerprints", []))
        except (OSError, ValueError) as e:
            print(f"error: could not read baseline {args.baseline!r}: {e}", file=sys.stderr)
            return 2
        suppressed = 0
        for f in rep.get("findings", []):
            if f["fingerprint"] in known:
                f["baselined"] = True
                suppressed += 1
        print(f"[baseline] suppressed {suppressed}/{len(rep.get('findings', []))} finding(s) "
              f"present in {args.baseline}")

    if args.fail_on:
        n = report.count_at_or_above(rep, args.fail_on)
        if n > 0:
            print(f"\nfail-on: {n} finding(s) at or above severity {args.fail_on!r} - exiting non-zero",
                  file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

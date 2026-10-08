"""Stage 4 - Report. Endpoint-centric unified gray-box output.

Reuses the white-box report writers for JSON/JSONL/SARIF/Markdown/HTML so the
gray-box deliverable matches the other modes, and adds an endpoint attack-surface
section plus reachability annotations. Also writes report.junit.xml for CI.
"""

from __future__ import annotations

import datetime
import json
import os
from collections import Counter
from typing import Any, Dict, List

from offat_triage import api_summary
from offat_wb import report as wb_report

_SEVS = ["critical", "high", "medium", "low", "info"]
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
_VERDICT_ORDER = {"confirmed": 0, "likely": 1, "inconclusive": 2, "false_positive": 3, "": 4}


def build_report(target: str, findings: List[Dict[str, Any]], endpoints: List[Dict[str, Any]],
                 recon: Dict[str, Any], triage_source: str, tool_status) -> Dict[str, Any]:
    for f in findings:
        f.setdefault("source_mode", "graybox")
    findings.sort(key=lambda f: (
        _VERDICT_ORDER.get((f.get("triage") or {}).get("verdict", ""), 4),
        _SEV_ORDER.get(f.get("severity", ""), 5),
        -float(f.get("confidence", 0)),
    ))
    by_sev = Counter(f.get("severity", "") for f in findings)
    by_verdict = Counter((f.get("triage") or {}).get("verdict", "") for f in findings)
    by_class = Counter(f.get("class", "") for f in findings)
    reachable = sum(1 for f in findings if f.get("reachable"))
    return {
        "tool": "offat-ai-graybox",
        "version": "1.0.0",
        "mode": "graybox",
        "target": target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "triage_source": triage_source,
        "recon": recon,
        "endpoints": endpoints,
        "tools": {"available": tool_status.available, "notes": tool_status.notes},
        "threat_mapping": api_summary(findings),
        "summary": {
            "total": len(findings),
            "endpoints": len(endpoints),
            "reachable_findings": reachable,
            "by_severity": dict(by_sev),
            "by_verdict": dict(by_verdict),
            "by_class": dict(by_class),
        },
        "findings": findings,
    }


def write_all(out_dir: str, report: Dict[str, Any]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(os.path.join(out_dir, "findings.jsonl"), "w", encoding="utf-8") as fh:
        for f in report["findings"]:
            fh.write(json.dumps(f) + "\n")
    with open(os.path.join(out_dir, "endpoints.json"), "w", encoding="utf-8") as fh:
        json.dump(report["endpoints"], fh, indent=2)
    with open(os.path.join(out_dir, "results.sarif"), "w", encoding="utf-8") as fh:
        json.dump(wb_report._sarif(report), fh, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(_markdown(report))
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(wb_report._html(report))
    with open(os.path.join(out_dir, "report.junit.xml"), "w", encoding="utf-8") as fh:
        fh.write(_junit(report))


def count_at_or_above(report: Dict[str, Any], sev: str) -> int:
    """Actionable findings (not false-positive) at or above severity sev."""
    threshold = _SEV_ORDER.get((sev or "").strip().lower())
    if threshold is None or not sev:
        return 0
    n = 0
    for f in report["findings"]:
        rank = _SEV_ORDER.get(f.get("severity", ""))
        if rank is None or rank == 5:
            continue
        verdict = (f.get("triage") or {}).get("verdict", "")
        if rank <= threshold and verdict != "false_positive":
            n += 1
    return n


def _markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = ["# OFFAT-AI Gray-box Report", "",
             f"- **Target:** `{report['target']}`",
             f"- **Generated:** {report['generated_at']}",
             f"- **Triage:** {report['triage_source']}",
             f"- **Endpoints mapped:** {s['endpoints']}",
             f"- **Reachable findings:** {s['reachable_findings']} / {s['total']}",
             f"- **Languages:** {', '.join(report['recon'].get('languages', {}).keys()) or 'n/a'}", ""]
    notes = report["tools"].get("notes", [])
    if notes:
        lines += ["> Tool status: " + "; ".join(notes), ""]

    lines += ["## Endpoint attack surface", ""]
    if report["endpoints"]:
        lines += ["| Method | Path | Handler | Location |", "|---|---|---|---|"]
        for ep in report["endpoints"]:
            loc = f"{ep.get('file','')}:{ep.get('line','')}"
            lines.append(f"| {ep.get('method','')} | `{ep.get('path','')}` | "
                         f"{ep.get('handler','') or '-'} | `{loc}` |")
    else:
        lines.append("_No HTTP endpoints discovered in source._")
    lines += [""]

    lines += ["## Summary", "", "| Severity | Count |", "|---|---|"]
    for sev in _SEVS:
        if s["by_severity"].get(sev):
            lines.append(f"| {sev.title()} | {s['by_severity'][sev]} |")
    lines += ["", f"**Total findings:** {s['total']}", ""]

    tm = report.get("threat_mapping") or []
    if tm:
        lines += ["## Threat mapping (OWASP API Top 10 - 2023)", "",
                  "| Category | Name | Findings |", "|---|---|---|"]
        for row in tm:
            lines.append(f"| {row['id']} | {row['name']} | {row['count']} |")
        lines += [""]

    lines += ["## Findings", ""]
    if not report["findings"]:
        lines.append("_No findings._")
    for i, f in enumerate(report["findings"], 1):
        t = f.get("triage") or {}
        th = f.get("threat") or {}
        lines.append(f"### {i}. {f.get('title', '')}")
        head = f"- **Severity:** {f.get('severity', '').title()}"
        if t:
            head += f"  |  **Verdict:** {t.get('verdict')}  |  **CVSS:** {t.get('cvss')}  |  **Source:** {t.get('source')}"
        lines.append(head)
        loc = f.get("file", "")
        if f.get("line"):
            loc += f":{f['line']}"
        lines.append(f"- **Location:** `{loc}`")
        rf = f.get("reachable_from") or []
        lines.append(f"- **Reachable from:** {', '.join(f'`{r}`' for r in rf) if rf else '_not reachable from a mapped endpoint_'}")
        lines.append(f"- **Class:** {f.get('class')}")
        lines.append(
            f"- **Threat:** {th.get('owasp_api','')} {th.get('owasp_api_name','')}  |  "
            f"OWASP Web {th.get('owasp_web','')} {th.get('owasp_web_name','')}  |  "
            f"{th.get('cwe','')} {th.get('cwe_name','')}")
        if f.get("code"):
            lines += ["", "```", f["code"][:800], "```"]
        if t.get("rationale"):
            lines += ["", f"**Triage:** {t['rationale']}"]
        if t.get("remediation"):
            lines += ["", f"**Remediation:** {t['remediation']}"]
        lines += ["", "---", ""]
    return "\n".join(lines) + "\n"


def _junit(report: Dict[str, Any]) -> str:
    import xml.sax.saxutils as sx

    cases = []
    failures = 0
    for f in report["findings"]:
        t = f.get("triage") or {}
        name = f.get("title", "")
        loc = f.get("file", "")
        if f.get("line"):
            loc += f":{f['line']}"
        if loc:
            name += f" [{loc}]"
        classname = f.get("class", "")
        verdict = t.get("verdict", "")
        if verdict != "false_positive":
            failures += 1
            rf = ", ".join(f.get("reachable_from") or []) or "none"
            body = (f"{f.get('severity','')} {classname} - verdict {verdict}\n"
                    f"reachable_from: {rf}\n{t.get('remediation','')}")
            case = (f'  <testcase name={sx.quoteattr(name)} classname={sx.quoteattr(classname)} time="0">\n'
                    f'    <failure type={sx.quoteattr(f.get("severity",""))} '
                    f'message={sx.quoteattr(f"{classname} {verdict}")}>'
                    f'{sx.escape(body)}</failure>\n  </testcase>')
        else:
            case = (f'  <testcase name={sx.quoteattr(name)} classname={sx.quoteattr(classname)} time="0"/>')
        cases.append(case)
    total = len(report["findings"])
    head = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuites tests="{total}" failures="{failures}">\n'
            f'  <testsuite name="offat-ai-graybox" tests="{total}" failures="{failures}" time="0">\n')
    return head + "\n".join(cases) + "\n  </testsuite>\n</testsuites>\n"

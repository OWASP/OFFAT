"""Stage 5 — Report. Writes JSON, JSONL, SARIF 2.1.0, Markdown and HTML,
matching the DAST engine's output formats and the security-harness deliverable.
"""

from __future__ import annotations

import datetime
import html
import json
import os
from collections import Counter
from typing import Any, Dict, List

try:  # pragma: no cover
    from offat_triage import api_summary
except ImportError:  # pragma: no cover
    def api_summary(findings):
        return []

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}
_VERDICT_ORDER = {"confirmed": 0, "likely": 1, "inconclusive": 2, "false_positive": 3, "": 4}
_SEVS = ["critical", "high", "medium", "low", "info"]


def build_report(target: str, findings: List[Dict[str, Any]], recon: Dict[str, Any],
                 triage_source: str, tool_status) -> Dict[str, Any]:
    findings.sort(key=lambda f: (
        _VERDICT_ORDER.get((f.get("triage") or {}).get("verdict", ""), 4),
        _SEV_ORDER.get(f.get("severity", ""), 5),
        -float(f.get("confidence", 0)),
    ))
    return {
        "tool": "offat-ai-whitebox",
        "version": "1.0.0",
        "target": target,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "triage_source": triage_source,
        "recon": recon,
        "tools": {"available": tool_status.available, "notes": tool_status.notes},
        "summary": _summary(findings),
        "threat_mapping": api_summary(findings),
        "findings": findings,
    }


def _summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_sev = Counter(f.get("severity", "") for f in findings)
    by_verdict = Counter((f.get("triage") or {}).get("verdict", "") for f in findings)
    by_class = Counter(f.get("class", "") for f in findings)
    return {
        "total": len(findings),
        "by_severity": dict(by_sev),
        "by_verdict": dict(by_verdict),
        "by_class": dict(by_class),
    }


def write_all(out_dir: str, report: Dict[str, Any]) -> None:
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    with open(os.path.join(out_dir, "findings.jsonl"), "w", encoding="utf-8") as fh:
        for f in report["findings"]:
            fh.write(json.dumps(f) + "\n")
    with open(os.path.join(out_dir, "results.sarif"), "w", encoding="utf-8") as fh:
        json.dump(_sarif(report), fh, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(_markdown(report))
    with open(os.path.join(out_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(_html(report))
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


def _junit(report: Dict[str, Any]) -> str:
    import xml.sax.saxutils as sx

    cases, failures = [], 0
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
            body = (f"{f.get('severity','')} {classname} - verdict {verdict}\n"
                    f"{t.get('remediation','')}")
            cases.append(
                f'  <testcase name={sx.quoteattr(name)} classname={sx.quoteattr(classname)} time="0">\n'
                f'    <failure type={sx.quoteattr(f.get("severity",""))} '
                f'message={sx.quoteattr(f"{classname} {verdict}")}>'
                f'{sx.escape(body)}</failure>\n  </testcase>'
            )
        else:
            cases.append(
                f'  <testcase name={sx.quoteattr(name)} classname={sx.quoteattr(classname)} time="0"/>'
            )
    total = len(report["findings"])
    head = ('<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuites tests="{total}" failures="{failures}">\n'
            f'  <testsuite name="offat-ai-whitebox" tests="{total}" failures="{failures}" time="0">\n')
    return head + "\n".join(cases) + "\n  </testsuite>\n</testsuites>\n"


def _sarif(report: Dict[str, Any]) -> Dict[str, Any]:
    rules, results = {}, []
    for f in report["findings"]:
        rid = f.get("vector_id", "rule")
        rules.setdefault(rid, {
            "id": rid, "name": f.get("class", ""),
            "shortDescription": {"text": f.get("title", "")},
            "fullDescription": {"text": f.get("title", "")},
            "properties": {"cwe": f.get("cwe", ""), "owasp": f.get("owasp", "")},
        })
        level = "error" if f.get("severity") in ("critical", "high") else \
                "warning" if f.get("severity") == "medium" else "note"
        results.append({
            "ruleId": rid, "level": level,
            "message": {"text": f.get("title", "")},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("file", "")},
                "region": {"startLine": max(1, int(f.get("line", 1) or 1))},
            }}],
            "properties": {"verdict": (f.get("triage") or {}).get("verdict", ""),
                           "confidence": f.get("confidence", 0)},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "offat-ai-whitebox", "version": "1.0.0",
            "informationUri": "https://github.com/dmdhrumilmistry/offat-ai",
            "rules": list(rules.values()),
        }}, "results": results}],
    }


def _markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    lines = ["# OFFAT-AI White-box Report", "",
             f"- **Target:** `{report['target']}`",
             f"- **Generated:** {report['generated_at']}",
             f"- **Triage:** {report['triage_source']}",
             f"- **Languages:** {', '.join(report['recon'].get('languages', {}).keys()) or 'n/a'}",
             f"- **Dependency components:** {report['recon'].get('sbom_components', 0)}", ""]
    notes = report["tools"].get("notes", [])
    if notes:
        lines += ["> Tool status: " + "; ".join(notes), ""]
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
            head += f"  |  **Verdict:** {t.get('verdict')}  |  **CVSS:** {t.get('cvss')}"
        lines.append(head)
        loc = f.get("file", "")
        if f.get("line"):
            loc += f":{f['line']}"
        lines.append(f"- **Location:** `{loc}`")
        lines.append(f"- **Class:** {f.get('class')}  |  **Tool:** {f.get('source_tool')}")
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


def _html(report: Dict[str, Any]) -> str:
    s = report["summary"]
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             "<title>OFFAT-AI White-box Report</title><style>", _CSS,
             "</style></head><body><div class='wrap'>",
             "<h1>OFFAT-AI White-box Report</h1>",
             f"<div class='meta'><div><b>Target</b><span>{html.escape(report['target'])}</span></div>",
             f"<div><b>Generated</b><span>{report['generated_at'][:19]}</span></div>",
             f"<div><b>Triage</b><span>{html.escape(report['triage_source'])}</span></div>",
             f"<div><b>Findings</b><span>{s['total']}</span></div></div>"]
    parts.append("<div class='cards'>")
    for sev in _SEVS:
        if s["by_severity"].get(sev):
            parts.append(f"<div class='card sev-{sev}'><span class='n'>{s['by_severity'][sev]}</span><span class='l'>{sev.title()}</span></div>")
    parts.append("</div>")

    tm = report.get("threat_mapping") or []
    if tm:
        parts.append("<h2 style='font-size:17px'>Threat mapping - OWASP API Top 10 (2023)</h2><div class='tags'>")
        for row in tm:
            parts.append(f"<span class='tag'>{html.escape(row['id'])} {html.escape(row['name'])}: {row['count']}</span>")
        parts.append("</div>")

    for i, f in enumerate(report["findings"], 1):
        t = f.get("triage") or {}
        th = f.get("threat") or {}
        sev = f.get("severity", "info")
        parts.append(f"<div class='finding b-{sev}'><h2><span class='pill sev-{sev}'>{sev.title()}</span> {i}. {html.escape(f.get('title',''))}</h2>")
        parts.append("<div class='tags'>")
        loc = f.get("file", "") + (f":{f['line']}" if f.get("line") else "")
        parts.append(f"<span class='tag'>{html.escape(loc)}</span>")
        parts.append(f"<span class='tag'>{html.escape(f.get('class',''))}</span>")
        if th:
            parts.append(f"<span class='tag'>{html.escape(th.get('owasp_api',''))}</span>")
            parts.append(f"<span class='tag'>OWASP Web {html.escape(th.get('owasp_web',''))}</span>")
            parts.append(f"<span class='tag'>{html.escape(th.get('cwe',''))}</span>")
        if t:
            parts.append(f"<span class='tag v-{t.get('verdict','')}'>{t.get('verdict','')} · CVSS {t.get('cvss','')}</span>")
        parts.append("</div>")
        if f.get("code"):
            parts.append(f"<pre>{html.escape(f['code'][:800])}</pre>")
        if t.get("rationale"):
            parts.append(f"<p><b>Triage:</b> {html.escape(t['rationale'])}</p>")
        if t.get("remediation"):
            parts.append(f"<p class='rem'><b>Remediation:</b> {html.escape(t['remediation'])}</p>")
        parts.append("</div>")
    parts.append("</div></body></html>")
    return "".join(parts)


_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0e1116;color:#e6e6e6;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:960px;margin:0 auto;padding:32px 20px}h1{font-size:24px}
.meta{display:flex;flex-wrap:wrap;gap:16px;background:#171b22;border:1px solid #2a3038;border-radius:10px;padding:14px 18px;margin-bottom:18px}
.meta div{display:flex;flex-direction:column}.meta b{color:#9aa4b2;font-size:11px;text-transform:uppercase}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}
.card{flex:1;min-width:110px;background:#171b22;border:1px solid #2a3038;border-radius:10px;padding:14px;text-align:center}
.card .n{display:block;font-size:26px;font-weight:700}.card .l{color:#9aa4b2;font-size:12px;text-transform:uppercase}
.finding{background:#171b22;border:1px solid #2a3038;border-left-width:4px;border-radius:10px;padding:16px 18px;margin-bottom:16px}
.finding h2{font-size:17px;margin:0 0 10px}.tags{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.tag{background:#20262f;border:1px solid #2a3038;border-radius:20px;padding:2px 10px;font-size:12px;color:#9aa4b2}
.pill{border-radius:6px;padding:2px 8px;font-size:12px;color:#fff;margin-right:6px}
pre{background:#0b0e13;border:1px solid #2a3038;border-radius:6px;padding:12px;overflow:auto;font-size:12px;white-space:pre-wrap}
.rem{color:#8fd19e}
.sev-critical{background:#7b1e1e}.sev-high{background:#a3421c}.sev-medium{background:#8a6d1a}.sev-low{background:#3b5566}.sev-info{background:#3a3f47}
.b-critical{border-left-color:#e5484d}.b-high{border-left-color:#f0883e}.b-medium{border-left-color:#e3b341}.b-low{border-left-color:#539bf5}.b-info{border-left-color:#6a737d}
.v-confirmed{color:#e5484d}.v-likely{color:#f0883e}.v-inconclusive{color:#9aa4b2}.v-false_positive{color:#6a737d}
"""

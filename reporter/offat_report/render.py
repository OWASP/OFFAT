"""Render an OFFAT Bundle into deliverables: SARIF, Markdown, HTML, a compliance
report (OWASP API Top 10 + ASVS), and (best-effort) PDF.

Pure standard library. PDF uses an external engine (wkhtmltopdf, or headless
Chrome/Chromium) when present; otherwise it is skipped with a note.
"""

from __future__ import annotations

import html
import json
import os
import shutil
import subprocess
from typing import Any, Dict, List

try:  # optional, for OWASP API Top 10 names
    from offat_triage.taxonomy import OWASP_API_2023
except Exception:  # pragma: no cover
    OWASP_API_2023 = {}

_SEVS = ["critical", "high", "medium", "low", "info"]


def _findings(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    return bundle.get("findings", []) or []


def _loc(f: Dict[str, Any]) -> str:
    if f.get("endpoint") and not f.get("file"):
        return f.get("endpoint", "")
    loc = f.get("file", "")
    if f.get("line"):
        loc += f":{f['line']}"
    return loc or f.get("endpoint", "")


# ---- SARIF ----------------------------------------------------------------

def sarif(bundle: Dict[str, Any]) -> Dict[str, Any]:
    rules, results = {}, []
    for f in _findings(bundle):
        rid = f.get("vector_id") or f.get("class") or "finding"
        th = f.get("threat") or {}
        rules.setdefault(rid, {
            "id": rid, "name": f.get("class", ""),
            "shortDescription": {"text": f.get("title", rid)},
            "properties": {"cwe": th.get("cwe", f.get("cwe", "")),
                           "owasp-api": th.get("owasp_api", ""),
                           "security-severity": _sec_sev(f)},
        })
        sev = f.get("severity", "")
        level = "error" if sev in ("critical", "high") else "warning" if sev == "medium" else "note"
        uri = f.get("file") or ((f.get("request") or {}).get("url")) or f.get("endpoint", "")
        results.append({
            "ruleId": rid, "level": level,
            "message": {"text": f.get("title", "") + _verdict_suffix(f)},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri or "n/a"},
                "region": {"startLine": max(1, int(f.get("line", 1) or 1))}}}],
            "properties": {"verdict": (f.get("triage") or {}).get("verdict", ""),
                           "confidence": f.get("confidence", 0),
                           "source_mode": f.get("source_mode", "")},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {
            "name": "offat-ai", "version": bundle.get("meta", {}).get("version", "2.0.0"),
            "informationUri": "https://github.com/dmdhrumilmistry/offat-ai",
            "rules": list(rules.values())}}, "results": results}],
    }


def _sec_sev(f: Dict[str, Any]) -> str:
    cvss = (f.get("triage") or {}).get("cvss")
    return str(cvss) if cvss else ""


def _verdict_suffix(f: Dict[str, Any]) -> str:
    v = (f.get("triage") or {}).get("verdict", "")
    return f" (verdict: {v})" if v else ""


# ---- Markdown -------------------------------------------------------------

def markdown(bundle: Dict[str, Any]) -> str:
    s = bundle.get("summary", {})
    meta = bundle.get("meta", {})
    L = ["# OFFAT-AI Report", "",
         f"- **Target:** `{meta.get('target', {}).get('source_path') or meta.get('target', {}).get('base_url', 'n/a')}`",
         f"- **Generated:** {meta.get('generated_at', '')}",
         f"- **Stages:** {', '.join(x.get('name', '') for x in meta.get('stages', []))}",
         f"- **Endpoints:** {s.get('endpoints', 0)}  |  **Test cases:** {s.get('test_cases', 0)}  "
         f"|  **Executions:** {s.get('executions', 0)}  |  **Threats:** {s.get('threats', 0)}",
         ""]
    L += ["## Findings by severity", "", "| Severity | Count |", "|---|---|"]
    for sev in _SEVS:
        if s.get("by_severity", {}).get(sev):
            L.append(f"| {sev.title()} | {s['by_severity'][sev]} |")
    api = s.get("by_owasp_api", {})
    if api:
        L += ["", "## OWASP API Top 10 (2023) coverage", "", "| Category | Name | Findings |", "|---|---|---|"]
        for k in sorted(api):
            if api[k]:
                L.append(f"| {k} | {OWASP_API_2023.get(k, '')} | {api[k]} |")
    L += ["", "## Findings", ""]
    if not _findings(bundle):
        L.append("_No findings._")
    for i, f in enumerate(_findings(bundle), 1):
        t = f.get("triage") or {}
        th = f.get("threat") or {}
        L.append(f"### {i}. {f.get('title', '')}")
        L.append(f"- **Severity:** {f.get('severity', '').title()}  |  **Verdict:** {t.get('verdict', 'n/a')}  "
                 f"|  **CVSS:** {t.get('cvss', 'n/a')}  |  **Source:** {f.get('source_mode', '')}")
        L.append(f"- **Location:** `{_loc(f)}`")
        L.append(f"- **Threat:** {th.get('owasp_api', '')} {th.get('owasp_api_name', '')}  |  "
                 f"{th.get('cwe', '')} {th.get('cwe_name', '')}")
        if f.get("payload"):
            L.append(f"- **Payload:** `{f['payload']}`")
        ev = f.get("evidence", {})
        if ev.get("matched_signature"):
            L.append(f"- **Signal:** {ev['matched_signature']}")
        if t.get("remediation"):
            L += ["", f"**Remediation:** {t['remediation']}"]
        L += ["", "---", ""]
    return "\n".join(L) + "\n"


# ---- HTML -----------------------------------------------------------------

def html_report(bundle: Dict[str, Any]) -> str:
    s = bundle.get("summary", {})
    meta = bundle.get("meta", {})
    dfd = (bundle.get("threat_model") or {}).get("dfd_mermaid", "")
    p = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
         '<meta name="viewport" content="width=device-width,initial-scale=1">',
         "<title>OFFAT-AI Report</title><style>", _CSS, "</style></head><body><div class='wrap'>",
         "<h1>OFFAT-AI Report</h1>",
         f"<div class='meta'><div><b>Target</b><span>{html.escape(str(meta.get('target', {}).get('source_path') or meta.get('target', {}).get('base_url', 'n/a')))}</span></div>",
         f"<div><b>Generated</b><span>{html.escape(meta.get('generated_at', '')[:19])}</span></div>",
         f"<div><b>Endpoints</b><span>{s.get('endpoints', 0)}</span></div>",
         f"<div><b>Findings</b><span>{s.get('findings', 0)}</span></div></div>"]
    p.append("<div class='cards'>")
    for sev in _SEVS:
        if s.get("by_severity", {}).get(sev):
            p.append(f"<div class='card sev-{sev}'><span class='n'>{s['by_severity'][sev]}</span><span class='l'>{sev.title()}</span></div>")
    p.append("</div>")

    api = s.get("by_owasp_api", {})
    if api:
        p.append("<h2>OWASP API Top 10 (2023)</h2><div class='tags'>")
        for k in sorted(api):
            if api[k]:
                p.append(f"<span class='tag'>{html.escape(k)} {html.escape(OWASP_API_2023.get(k, ''))}: {api[k]}</span>")
        p.append("</div>")

    if dfd:
        p.append("<h2>Threat model (data-flow diagram)</h2>")
        p.append(f"<pre class='mermaid'>{html.escape(dfd)}</pre>")

    for i, f in enumerate(_findings(bundle), 1):
        t = f.get("triage") or {}
        th = f.get("threat") or {}
        sev = f.get("severity", "info")
        p.append(f"<div class='finding b-{sev}'><h2><span class='pill sev-{sev}'>{sev.title()}</span> {i}. {html.escape(f.get('title', ''))}</h2>")
        p.append("<div class='tags'>")
        p.append(f"<span class='tag'>{html.escape(_loc(f))}</span>")
        p.append(f"<span class='tag'>{html.escape(th.get('owasp_api', ''))}</span>")
        p.append(f"<span class='tag'>{html.escape(th.get('cwe', ''))}</span>")
        p.append(f"<span class='tag'>{html.escape(f.get('source_mode', ''))}</span>")
        if t.get("verdict"):
            p.append(f"<span class='tag'>{html.escape(t['verdict'])} · CVSS {t.get('cvss', '')}</span>")
        p.append("</div>")
        if f.get("payload"):
            p.append(f"<p><b>Payload:</b> <code>{html.escape(str(f['payload']))}</code></p>")
        if (f.get('evidence') or {}).get('matched_signature'):
            p.append(f"<p><b>Signal:</b> {html.escape(f['evidence']['matched_signature'])}</p>")
        if t.get("remediation"):
            p.append(f"<p class='rem'><b>Remediation:</b> {html.escape(t['remediation'])}</p>")
        p.append("</div>")
    p.append('<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>')
    p.append('<script>try{mermaid.initialize({startOnLoad:true,theme:"dark"})}catch(e){}</script>')
    p.append("</div></body></html>")
    return "".join(p)


# ---- Compliance -----------------------------------------------------------

def compliance(bundle: Dict[str, Any]) -> str:
    api = (bundle.get("summary", {}) or {}).get("by_owasp_api", {})
    L = ["# OFFAT-AI Compliance Report", "",
         "Maps findings to the OWASP API Security Top 10 (2023). A category with one",
         "or more actionable findings is marked **FAIL**; otherwise **PASS** (not",
         "assessed categories are noted).", "",
         "| Category | Name | Findings | Status |", "|---|---|---|---|"]
    for k, name in OWASP_API_2023.items():
        n = api.get(k, 0)
        status = "FAIL" if n else "PASS"
        L.append(f"| {k} | {name} | {n} | {status} |")
    fails = sum(1 for k in OWASP_API_2023 if api.get(k))
    L += ["", f"**Categories with findings:** {fails} / {len(OWASP_API_2023)}", "",
          "> ASVS note: injection findings map to ASVS V5 (Validation, Sanitization,",
          "> Encoding); access-control to V4; authentication to V2; crypto to V6.", ""]
    return "\n".join(L) + "\n"


# ---- PDF (best effort) ----------------------------------------------------

def pdf_from_html(html_path: str, pdf_path: str) -> str:
    """Render HTML to PDF with an available engine. Returns the engine used or ''."""
    if shutil.which("wkhtmltopdf"):
        try:
            subprocess.run(["wkhtmltopdf", "-q", html_path, pdf_path], check=True, timeout=120)
            return "wkhtmltopdf"
        except Exception:
            pass
    for chrome in ("chromium", "chromium-browser", "google-chrome", "chrome"):
        if shutil.which(chrome):
            try:
                subprocess.run([chrome, "--headless", "--no-sandbox", "--disable-gpu",
                                f"--print-to-pdf={pdf_path}", html_path], check=True, timeout=120)
                if os.path.exists(pdf_path):
                    return chrome
            except Exception:
                pass
    return ""


_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0e1116;color:#e6e6e6;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:32px 20px}h1{font-size:24px}h2{font-size:18px;margin-top:28px}
.meta{display:flex;flex-wrap:wrap;gap:16px;background:#171b22;border:1px solid #2a3038;border-radius:10px;padding:14px 18px;margin-bottom:18px}
.meta div{display:flex;flex-direction:column}.meta b{color:#9aa4b2;font-size:11px;text-transform:uppercase}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.card{flex:1;min-width:110px;background:#171b22;border:1px solid #2a3038;border-radius:10px;padding:14px;text-align:center}
.card .n{display:block;font-size:26px;font-weight:700}.card .l{color:#9aa4b2;font-size:12px;text-transform:uppercase}
.finding{background:#171b22;border:1px solid #2a3038;border-left-width:4px;border-radius:10px;padding:16px 18px;margin-bottom:16px}
.finding h2{font-size:16px;margin:0 0 10px}.tags{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
.tag{background:#20262f;border:1px solid #2a3038;border-radius:20px;padding:2px 10px;font-size:12px;color:#9aa4b2}
.pill{border-radius:6px;padding:2px 8px;font-size:12px;color:#fff;margin-right:6px}
code{background:#0b0e13;border:1px solid #2a3038;border-radius:6px;padding:1px 6px}
pre{background:#0b0e13;border:1px solid #2a3038;border-radius:6px;padding:12px;overflow:auto;font-size:12px}
.rem{color:#8fd19e}
.sev-critical{background:#7b1e1e}.sev-high{background:#a3421c}.sev-medium{background:#8a6d1a}.sev-low{background:#3b5566}.sev-info{background:#3a3f47}
.b-critical{border-left-color:#e5484d}.b-high{border-left-color:#f0883e}.b-medium{border-left-color:#e3b341}.b-low{border-left-color:#539bf5}.b-info{border-left-color:#6a737d}
"""

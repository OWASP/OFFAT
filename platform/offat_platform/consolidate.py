"""Phase 5 - Consolidation + triage.

Turns the engine's execution captures into DAST candidate findings (signature /
reflection / status heuristics), folds in the SAST sinks from the inventory,
attaches the OWASP/CWE threat mapping, triages everything with the shared
token-disciplined triager, and writes `findings` + `summary` into the Bundle.
"""

from __future__ import annotations

import collections
from typing import Any, Dict, List, Optional

import offat_bundle as ob
from offat_triage import enrich_threats, tiered_triage

_SQL_ERRORS = [
    "sql syntax", "sqlite3", "psycopg2", "ora-", "you have an error in your sql",
    "unclosed quotation mark", "pg::syntaxerror", "mysql_fetch", "sqlstate",
]
_TRAVERSAL_MARKERS = ["root:x:0:0", "[extensions]", "; for 16-bit app support"]

_SEVERITY = {
    "sqli": "high", "command_injection": "high", "ssti": "high", "deserialization": "high",
    "bola": "high", "bfla": "high", "access_control": "high", "broken_auth": "high",
    "secrets": "high", "nosqli": "high", "xxe": "high", "path_traversal": "high",
    "vulnerable_dependency": "high",
    "xss": "medium", "ssrf": "medium", "open_redirect": "medium", "mass_assignment": "medium",
    "data_exposure": "medium", "ldap_injection": "medium", "crypto": "medium", "csrf": "medium",
    "security_misconfig": "low",
}


def _sev(cls: str) -> str:
    return _SEVERITY.get(cls, "medium")


def _detect(case: Dict[str, Any], ex: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    resp = ex.get("response") or {}
    status = int(resp.get("status", 0) or 0)
    body = (resp.get("body_snippet") or "").lower()
    cls = case.get("class", "")
    payload = str(case.get("payload", ""))
    technique = case.get("technique", "")
    signal = ""
    conf = 0.0

    if cls in ("sqli", "nosqli"):
        if any(s in body for s in _SQL_ERRORS):
            signal, conf = "sql error signature", 0.85
        elif status >= 500:
            signal, conf = "server error on injection", 0.5
    elif cls in ("xss", "ssti"):
        if cls == "ssti" and "49" in body and "7*7" in payload:
            signal, conf = "template arithmetic evaluated (49)", 0.85
        elif payload and payload.lower() in body:
            signal, conf = "payload reflected in response", 0.6
    elif cls == "path_traversal":
        if any(m.lower() in body for m in _TRAVERSAL_MARKERS):
            signal, conf = "file content disclosed", 0.85
    elif cls == "open_redirect":
        loc = (resp.get("location") or "").lower()
        if status in (301, 302, 303, 307, 308) and payload and payload.lower().strip("/") in loc:
            signal, conf = "redirect to attacker-controlled location", 0.8
    elif cls == "command_injection":
        if "uid=" in body or "gid=" in body:
            signal, conf = "command output in response", 0.85
        elif status >= 500:
            signal, conf = "server error on command injection", 0.45
    else:
        if status >= 500:
            signal, conf = "server error", 0.4

    if not signal:
        return None
    req = ex.get("request") or {}
    return {
        "id": ob.make_id("f", case.get("id", ""), ex.get("id", "")),
        "vector_id": f"{cls}-{technique}" if technique else cls,
        "class": cls, "title": f"{cls} on {req.get('method','')} {req.get('url','')}",
        "severity": _sev(cls), "endpoint": case.get("endpoint", ""),
        "test_case": case.get("id", ""), "param": case.get("param", ""),
        "location": case.get("location", ""), "technique": technique, "payload": payload,
        "confidence": conf, "source_mode": "dast",
        "evidence": {"status_code": status, "matched_signature": signal,
                     "snippet": (resp.get("body_snippet") or "")[:400],
                     "request_url": req.get("url", "")},
    }


def _sinks_to_findings(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for s in (bundle.get("inventory") or {}).get("sinks", []):
        cls = s.get("class", "")
        out.append({
            "id": ob.make_id("f", "sast", s.get("id", "")),
            "vector_id": f"sast-{cls}", "class": cls,
            "title": f"{cls} sink at {s.get('file','')}:{s.get('line','')}",
            "severity": _sev(cls), "cwe": s.get("cwe", ""),
            "file": s.get("file", ""), "line": s.get("line", 0),
            "confidence": 0.55, "source_mode": "sast",
            "evidence": {"notes": f"static sink in {s.get('symbol','') or 'source'}"},
        })
    return out


def build(bundle: Dict[str, Any], out_dir: str = ".", *, use_ai: bool = True,
          provider: Optional[str] = None, cache_enabled: bool = True) -> Dict[str, Any]:
    cases = {c["id"]: c for c in (bundle.get("test_plan") or {}).get("cases", [])}
    findings: List[Dict[str, Any]] = []

    for ex in (bundle.get("results") or {}).get("executions", []):
        case = cases.get(ex.get("case_id", ""))
        if not case:
            continue
        f = _detect(case, ex)
        if f:
            findings.append(f)

    findings.extend(_sinks_to_findings(bundle))

    # Dedupe by id (same sink/exec detected twice).
    seen, deduped = set(), []
    for f in findings:
        if f["id"] in seen:
            continue
        seen.add(f["id"])
        deduped.append(f)
    findings = deduped

    enrich_threats(findings)
    source = tiered_triage(findings, out_dir, provider=provider, use_ai=use_ai,
                           cache_enabled=cache_enabled)

    bundle["findings"] = findings
    bundle["summary"] = _summary(bundle, findings, source)
    ob.record_stage(bundle, "triage", tool="offat-platform", version="1.0.0")
    return bundle["summary"]


def _summary(bundle: Dict[str, Any], findings: List[Dict[str, Any]], source: str) -> Dict[str, Any]:
    by_sev = collections.Counter(f.get("severity", "") for f in findings)
    by_verdict = collections.Counter((f.get("triage") or {}).get("verdict", "") for f in findings)
    by_api = collections.Counter((f.get("threat") or {}).get("owasp_api", "") for f in findings)
    return {
        "findings": len(findings),
        "endpoints": len((bundle.get("asm") or {}).get("endpoints", [])),
        "threats": len((bundle.get("threat_model") or {}).get("threats", [])),
        "test_cases": len((bundle.get("test_plan") or {}).get("cases", [])),
        "executions": len((bundle.get("results") or {}).get("executions", [])),
        "triage_source": source,
        "by_severity": dict(by_sev),
        "by_verdict": dict(by_verdict),
        "by_owasp_api": dict(by_api),
    }

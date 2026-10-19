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
    "rbac": "high", "business_logic": "medium",
    "security_misconfig": "low",
}


def _sev(cls: str) -> str:
    return _SEVERITY.get(cls, "medium")


# gRPC status codes that mean the call was rejected for authentication /
# authorization (a healthy outcome for an unauthenticated / unprivileged probe).
_GRPC_DENIED = {7, 16}  # PERMISSION_DENIED, UNAUTHENTICATED
# Codes that mean the method does not exist or the server was unreachable, so the
# probe is inconclusive rather than a finding.
_GRPC_INCONCLUSIVE = {4, 5, 12, 14}  # DEADLINE, NOT_FOUND, UNIMPLEMENTED, UNAVAILABLE


def _mk_finding(case: Dict[str, Any], ex: Dict[str, Any], cls: str, technique: str,
                signal: str, conf: float, sev_override: Optional[str],
                payload: str, proto: str) -> Dict[str, Any]:
    resp = ex.get("response") or {}
    status = int(resp.get("status", 0) or 0)
    req = ex.get("request") or {}
    snippet = resp.get("body_snippet") or resp.get("first_text") or ""
    if not snippet and resp.get("frames"):
        snippet = " ".join(str(f) for f in resp.get("frames", []))
    return {
        "id": ob.make_id("f", case.get("id", ""), ex.get("id", "")),
        "vector_id": f"{cls}-{technique}" if technique else cls,
        "class": cls, "title": f"{cls} on {req.get('method', proto.upper())} "
                                f"{req.get('url', '') or req.get('method', '')}".strip(),
        "severity": sev_override or _sev(cls), "endpoint": case.get("endpoint", ""),
        "test_case": case.get("id", ""), "param": case.get("param", ""),
        "location": case.get("location", ""), "technique": technique, "payload": payload,
        "protocol": proto, "confidence": conf, "source_mode": "dast",
        "evidence": {"status_code": status, "matched_signature": signal,
                     "protocol": proto,
                     "grpc_status": resp.get("grpc_status"),
                     "ws_connected": resp.get("connected"),
                     "identity": req.get("identity", ""), "baseline_identity": req.get("baseline_identity", ""),
                     "baseline_status": (ex.get("baseline") or {}).get("status"),
                     "snippet": str(snippet)[:400],
                     "request_url": req.get("url", "")},
    }


def _detect_ws(case: Dict[str, Any], ex: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    resp = ex.get("response") or {}
    cls = case.get("class", "")
    technique = case.get("technique", "")
    payload = str(case.get("payload", ""))
    connected = bool(resp.get("connected"))
    frames = resp.get("frames") or []
    body = (str(resp.get("first_text") or "") + " " + " ".join(str(f) for f in frames)).lower()
    signal, conf = "", 0.0

    if cls == "broken_auth" and technique == "no-auth":
        if connected:
            signal, conf = "WebSocket handshake accepted with no credentials", 0.6
    elif not connected:
        return None  # no injection signal without an open socket
    elif cls in ("sqli", "nosqli"):
        if any(s in body for s in _SQL_ERRORS):
            signal, conf = "sql error signature in WebSocket frame", 0.8
    elif cls == "ssti":
        if "49" in body and "7*7" in payload:
            signal, conf = "template arithmetic evaluated (49) in WebSocket frame", 0.8
    elif cls == "xss":
        if payload and payload.lower() in body:
            signal, conf = "payload reflected in WebSocket frame", 0.55
    elif cls == "command_injection":
        if "uid=" in body or "gid=" in body:
            signal, conf = "command output in WebSocket frame", 0.8

    if not signal:
        return None
    return _mk_finding(case, ex, cls, technique, signal, conf, None, payload, "ws")


def _detect_grpc(case: Dict[str, Any], ex: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    resp = ex.get("response") or {}
    if not resp.get("connected"):
        return None
    cls = case.get("class", "")
    technique = case.get("technique", "")
    code = resp.get("grpc_code")
    if code is None or int(code) in _GRPC_DENIED or int(code) in _GRPC_INCONCLUSIVE:
        return None  # denied (healthy) or inconclusive
    code = int(code)
    reached = "OK" if code == 0 else f"grpc-status {resp.get('grpc_status', code)}"

    if cls == "broken_auth" and technique == "no-auth":
        conf = 0.7 if code == 0 else 0.55
        signal = f"gRPC method processed with no metadata credentials ({reached})"
        return _mk_finding(case, ex, cls, technique, signal, conf, None, "", "grpc")
    if cls in ("bfla", "rbac"):
        conf = 0.7 if code == 0 else 0.55
        signal = f"privileged gRPC method processed as a non-privileged identity ({reached})"
        return _mk_finding(case, ex, cls, technique, signal, conf, None, "", "grpc")
    return None


def _detect(case: Dict[str, Any], ex: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    proto = (case.get("protocol") or ex.get("protocol") or "http").lower()
    if proto in ("ws", "wss", "websocket"):
        return _detect_ws(case, ex)
    if proto == "grpc":
        return _detect_grpc(case, ex)

    resp = ex.get("response") or {}
    status = int(resp.get("status", 0) or 0)
    body = (resp.get("body_snippet") or "").lower()
    cls = case.get("class", "")
    payload = str(case.get("payload", ""))
    technique = case.get("technique", "")
    signal = ""
    conf = 0.0
    sev_override = None

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
    elif cls == "broken_auth" and technique == "no-auth":
        if 200 <= status < 300:
            signal, conf = "endpoint returned 2xx with no credentials", 0.65
    elif cls in ("bola", "bfla", "rbac"):
        base = ex.get("baseline") or {}
        bstatus = int(base.get("status", 0) or 0)
        bbody = base.get("body_snippet") or ""
        pbody = resp.get("body_snippet") or ""
        if 200 <= status < 300:
            if 200 <= bstatus < 300 and pbody and pbody == bbody:
                signal, conf = "unauthorized identity got the SAME 2xx response as the authorized baseline", 0.85
            elif 200 <= bstatus < 300:
                signal, conf = "unauthorized identity received 2xx (authorized baseline also 2xx)", 0.8
            else:
                signal, conf = "unauthorized identity received 2xx where access should be denied", 0.7
    elif cls == "business_logic":
        if 200 <= status < 300:
            if technique == "priv-field":
                signal, conf, sev_override = "privilege field accepted (possible escalation)", 0.6, "high"
            else:
                signal, conf = "invalid business value accepted (%s)" % payload, 0.55
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
        "severity": sev_override or _sev(cls), "endpoint": case.get("endpoint", ""),
        "test_case": case.get("id", ""), "param": case.get("param", ""),
        "location": case.get("location", ""), "technique": technique, "payload": payload,
        "confidence": conf, "source_mode": "dast",
        "evidence": {"status_code": status, "matched_signature": signal,
                     "identity": req.get("identity", ""), "baseline_identity": req.get("baseline_identity", ""),
                     "baseline_status": (ex.get("baseline") or {}).get("status"),
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

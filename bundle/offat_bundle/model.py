"""Builders and id helpers for the OFFAT Bundle (schema v1).

A Bundle is a plain dict. ``schema_version`` and ``meta`` are required; every
other section is optional and added as a stage produces it. Ids are stable and
content-derived so cross-references survive merges and re-runs.
"""

from __future__ import annotations

import datetime
import hashlib
from typing import Any, Dict, List, Optional

SCHEMA_VERSION = "1.0"


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def new_run_id() -> str:
    return "run-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")


def make_id(prefix: str, *parts: Any) -> str:
    """Stable content-derived id: ``<prefix>-<12 hex>``."""
    blob = "|".join(str(p) for p in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(blob).hexdigest()[:12]}"


def new_bundle(*, target: Optional[Dict[str, Any]] = None, tool: str = "offat-ai",
               version: str = "2.0.0", run_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "meta": {
            "tool": tool,
            "version": version,
            "run_id": run_id or new_run_id(),
            "generated_at": _now(),
            "target": target or {},
            "stages": [],
        },
    }


def record_stage(bundle: Dict[str, Any], name: str, tool: str = "", version: str = "") -> None:
    bundle.setdefault("meta", {}).setdefault("stages", []).append(
        {"name": name, "tool": tool, "version": version, "at": _now()}
    )
    bundle["meta"]["generated_at"] = _now()


def _section(bundle: Dict[str, Any], key: str, listkey: str) -> List[Dict[str, Any]]:
    sec = bundle.setdefault(key, {})
    return sec.setdefault(listkey, [])


# ---- builders (return dicts; callers add them via the add_* helpers) --------

def endpoint(method: str, path: str, *, protocol: str = "http",
             operation_id: str = "", handler: str = "",
             params: Optional[List[Dict[str, Any]]] = None,
             auth: Optional[Dict[str, Any]] = None,
             source: Optional[Dict[str, Any]] = None,
             responses: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    return {
        "id": make_id("ep", method.upper(), path, protocol),
        "method": method.upper(), "path": path, "protocol": protocol,
        "operation_id": operation_id, "handler": handler,
        "params": params or [], "auth": auth or {},
        "source": source or {}, "responses": responses or [],
    }


def param(name: str, location: str, *, type: str = "string",
          required: bool = False, example: Any = None) -> Dict[str, Any]:
    p = {"name": name, "location": location, "type": type, "required": required}
    if example is not None:
        p["example"] = example
    return p


def sink(vclass: str, *, symbol: str = "", file: str = "", line: int = 0,
         cwe: str = "") -> Dict[str, Any]:
    return {"id": make_id("sink", vclass, file, line), "class": vclass,
            "symbol": symbol, "file": file, "line": line, "cwe": cwe}


def source(kind: str, *, symbol: str = "", file: str = "", line: int = 0) -> Dict[str, Any]:
    return {"id": make_id("src", kind, file, line), "kind": kind,
            "symbol": symbol, "file": file, "line": line}


def prg_node(kind: str, endpoint_id: str, name: str, location: str,
             type: str = "string") -> Dict[str, Any]:
    return {"id": make_id("prg", kind, endpoint_id, name, location),
            "kind": kind, "endpoint": endpoint_id, "name": name,
            "location": location, "type": type}


def prg_edge(from_id: str, to_id: str, *, confidence: float = 0.5,
             basis: str = "", resource: str = "") -> Dict[str, Any]:
    return {"from": from_id, "to": to_id, "confidence": confidence,
            "basis": basis, "resource": resource}


def threat(title: str, *, stride: str = "", endpoint_id: str = "",
           owasp_api: str = "", cwe: str = "", likelihood: str = "",
           impact: str = "", risk: str = "", mitigation: str = "") -> Dict[str, Any]:
    return {"id": make_id("th", title, endpoint_id, stride), "title": title,
            "stride": stride, "endpoint": endpoint_id, "owasp_api": owasp_api,
            "cwe": cwe, "likelihood": likelihood, "impact": impact,
            "risk": risk, "mitigation": mitigation}


def test_case(endpoint_id: str, *, param: str = "", location: str = "",
              vclass: str = "", technique: str = "", protocol: str = "http",
              payload: str = "", origin: str = "rule", rationale: str = "",
              chain: Optional[List[str]] = None, expected_signal: str = "") -> Dict[str, Any]:
    return {"id": make_id("tc", endpoint_id, param, vclass, technique, payload),
            "endpoint": endpoint_id, "param": param, "location": location,
            "class": vclass, "technique": technique, "protocol": protocol,
            "payload": payload, "origin": origin, "rationale": rationale,
            "chain": chain or [], "expected_signal": expected_signal}


def execution(case_id: str, *, protocol: str = "http",
              request: Optional[Dict[str, Any]] = None,
              response: Optional[Dict[str, Any]] = None,
              baseline: Optional[Dict[str, Any]] = None,
              latency_ms: float = 0.0) -> Dict[str, Any]:
    return {"id": make_id("ex", case_id, protocol), "case_id": case_id,
            "protocol": protocol, "request": request or {},
            "response": response or {}, "baseline": baseline or {},
            "latency_ms": latency_ms, "at": _now()}


# ---- add helpers (append to the right section) ------------------------------

def add_endpoint(bundle, ep): _section(bundle, "asm", "endpoints").append(ep); return ep["id"]
def add_sink(bundle, s): _section(bundle, "inventory", "sinks").append(s); return s["id"]
def add_source(bundle, s): _section(bundle, "inventory", "sources").append(s); return s["id"]
def add_prg_node(bundle, n): _section(bundle, "prg", "nodes").append(n); return n["id"]
def add_prg_edge(bundle, e): _section(bundle, "prg", "edges").append(e)
def add_threat(bundle, t): _section(bundle, "threat_model", "threats").append(t); return t["id"]
def add_test_case(bundle, c): _section(bundle, "test_plan", "cases").append(c); return c["id"]
def add_execution(bundle, x): _section(bundle, "results", "executions").append(x); return x["id"]


def add_finding(bundle: Dict[str, Any], finding: Dict[str, Any]) -> None:
    bundle.setdefault("findings", []).append(finding)

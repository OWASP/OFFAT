"""Bundle validation.

Uses ``jsonschema`` against the bundled JSON Schema when it is installed;
otherwise falls back to a dependency-free structural check of the required keys,
types and section shapes. Also offers an optional cross-reference check that every
id a section points at exists.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

_SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "schema", "offat-bundle-v1.schema.json")


def schema() -> Dict[str, Any]:
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def validate(bundle: Dict[str, Any]) -> List[str]:
    """Return a list of problems. Empty list means the bundle is valid."""
    try:
        import jsonschema  # optional
        errors = sorted(
            jsonschema.Draft202012Validator(schema()).iter_errors(bundle),
            key=lambda e: list(e.path),
        )
        return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}" for e in errors]
    except ImportError:
        return _structural(bundle)


def _structural(bundle: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    if not isinstance(bundle, dict):
        return ["<root>: bundle must be an object"]
    if not isinstance(bundle.get("schema_version"), str):
        problems.append("schema_version: required string")
    meta = bundle.get("meta")
    if not isinstance(meta, dict):
        problems.append("meta: required object")
    else:
        for k in ("run_id", "generated_at"):
            if not isinstance(meta.get(k), str):
                problems.append(f"meta.{k}: required string")

    def check_list(path: str, val: Any, required_keys: Tuple[str, ...]):
        if val is None:
            return
        if not isinstance(val, list):
            problems.append(f"{path}: must be an array")
            return
        for i, item in enumerate(val):
            if not isinstance(item, dict):
                problems.append(f"{path}[{i}]: must be an object")
                continue
            for rk in required_keys:
                if rk not in item:
                    problems.append(f"{path}[{i}]: missing '{rk}'")

    asm = bundle.get("asm") or {}
    check_list("asm.endpoints", asm.get("endpoints"), ("id", "method", "path"))
    inv = bundle.get("inventory") or {}
    check_list("inventory.sinks", inv.get("sinks"), ("id", "class"))
    check_list("inventory.sources", inv.get("sources"), ("id",))
    prg = bundle.get("prg") or {}
    check_list("prg.nodes", prg.get("nodes"), ("id", "kind"))
    check_list("prg.edges", prg.get("edges"), ("from", "to"))
    tm = bundle.get("threat_model") or {}
    check_list("threat_model.threats", tm.get("threats"), ("id", "title"))
    tp = bundle.get("test_plan") or {}
    check_list("test_plan.cases", tp.get("cases"), ("id",))
    res = bundle.get("results") or {}
    check_list("results.executions", res.get("executions"), ("id",))
    if "findings" in bundle and not isinstance(bundle["findings"], list):
        problems.append("findings: must be an array")
    return problems


def cross_refs(bundle: Dict[str, Any]) -> List[str]:
    """Report dangling references between sections (ids pointed at but absent)."""
    problems: List[str] = []
    ep_ids = {e.get("id") for e in (bundle.get("asm") or {}).get("endpoints", [])}
    prg_ids = {n.get("id") for n in (bundle.get("prg") or {}).get("nodes", [])}
    case_ids = {c.get("id") for c in (bundle.get("test_plan") or {}).get("cases", [])}

    for e in (bundle.get("prg") or {}).get("edges", []):
        for side in ("from", "to"):
            if e.get(side) and prg_ids and e[side] not in prg_ids:
                problems.append(f"prg.edge.{side} -> unknown node {e[side]}")
    for c in (bundle.get("test_plan") or {}).get("cases", []):
        if c.get("endpoint") and ep_ids and c["endpoint"] not in ep_ids:
            problems.append(f"test_plan case {c.get('id')} -> unknown endpoint {c['endpoint']}")
    for x in (bundle.get("results") or {}).get("executions", []):
        if x.get("case_id") and case_ids and x["case_id"] not in case_ids:
            problems.append(f"results execution {x.get('id')} -> unknown case {x['case_id']}")
    return problems


def is_valid(bundle: Dict[str, Any]) -> bool:
    return not validate(bundle)

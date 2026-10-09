"""Phase 1 - Parameter Relation Graph.

Builds the cross-endpoint dataflow graph from the attack surface: an endpoint's
response fields are *producers*, its request parameters are *consumers*, and an
edge links a producer to a consumer when they refer to the same value. This is
what lets a later stage seed endpoint Y's input from endpoint X's output (and
powers BOLA/IDOR by replaying a foreign identifier).

Matching bases, strongest first:
- ``exact-name``   - normalized names are equal (e.g. ``userId`` == ``user_id``).
- ``resource-id``  - an ``id`` field on resource R feeds a path param ``id`` or
  ``<R>_id`` on another endpoint.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

import offat_bundle as ob


def _norm(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def _resource(path: str) -> str:
    """Best-effort resource name from a path, e.g. /api/users/{id} -> user."""
    for seg in reversed([s for s in (path or "").split("/") if s and "{" not in s and "<" not in s and ":" not in s]):
        seg = _norm(seg)
        if seg:
            return seg[:-1] if seg.endswith("s") else seg
    return ""


def build(bundle: Dict[str, Any]) -> Dict[str, int]:
    endpoints = (bundle.get("asm") or {}).get("endpoints", [])

    producers: List[Dict[str, Any]] = []   # {node_id, name, norm, resource}
    consumers: List[Dict[str, Any]] = []   # {node_id, name, norm, location, resource}

    for ep in endpoints:
        res = _resource(ep.get("path", ""))
        for resp in ep.get("responses", []):
            for field in resp.get("fields", []):
                nid = ob.add_prg_node(bundle, ob.prg_node(
                    "producer", ep["id"], field["name"], "response", field.get("type", "string")))
                producers.append({"id": nid, "name": field["name"],
                                  "norm": _norm(field["name"]), "resource": res})
        for p in ep.get("params", []):
            nid = ob.add_prg_node(bundle, ob.prg_node(
                "consumer", ep["id"], p["name"], p.get("location", "query"),
                p.get("type", "string")))
            consumers.append({"id": nid, "name": p["name"], "norm": _norm(p["name"]),
                              "location": p.get("location", "query"), "resource": res})

    edges = 0
    for prod in producers:
        for cons in consumers:
            if prod["id"] == cons["id"]:
                continue
            basis, conf = _match(prod, cons)
            if basis:
                ob.add_prg_edge(bundle, ob.prg_edge(
                    prod["id"], cons["id"], confidence=conf, basis=basis,
                    resource=prod["resource"] or cons["resource"]))
                edges += 1

    ob.record_stage(bundle, "prg", tool="offat-platform", version="1.0.0")
    return {"producers": len(producers), "consumers": len(consumers), "edges": edges}


def _match(prod: Dict[str, Any], cons: Dict[str, Any]):
    if prod["norm"] and prod["norm"] == cons["norm"]:
        return "exact-name", 0.9
    # resource-id: producer "id" on resource R feeds a path "id" / "<R>_id".
    if prod["norm"] == "id" and cons["location"] == "path":
        if cons["norm"] in ("id",) or (prod["resource"] and cons["norm"] == f"{prod['resource']}id"):
            return "resource-id", 0.7
    return "", 0.0

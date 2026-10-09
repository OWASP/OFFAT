"""Phase 2 - Threat modeling.

Turns the attack surface (asm), the sink/source inventory and the parameter
relation graph (prg) into a threat model: assets, trust boundaries, data flows,
STRIDE threats mapped to the OWASP API Top 10 + CWE with a likelihood x impact
risk, and a Mermaid data-flow diagram. Deterministic and offline; AI enrichment
can be layered on later.
"""

from __future__ import annotations

from typing import Any, Dict, List

import offat_bundle as ob
from offat_triage.taxonomy import threat_for

# vulnerability class -> STRIDE category
_STRIDE = {
    "sqli": "Tampering", "nosqli": "Tampering", "ldap_injection": "Tampering",
    "injection": "Tampering", "xss": "Tampering", "mass_assignment": "Tampering",
    "security_misconfig": "Tampering", "csrf": "Tampering",
    "command_injection": "Elevation of Privilege", "ssti": "Elevation of Privilege",
    "deserialization": "Elevation of Privilege", "access_control": "Elevation of Privilege",
    "bola": "Elevation of Privilege", "bfla": "Elevation of Privilege",
    "vulnerable_dependency": "Elevation of Privilege",
    "path_traversal": "Information Disclosure", "ssrf": "Information Disclosure",
    "xxe": "Information Disclosure", "data_exposure": "Information Disclosure",
    "secrets": "Information Disclosure", "crypto": "Information Disclosure",
    "broken_auth": "Spoofing", "open_redirect": "Spoofing",
}

_IMPACT = {
    "sqli": "high", "command_injection": "high", "ssti": "high", "deserialization": "high",
    "bola": "high", "bfla": "high", "access_control": "high", "broken_auth": "high",
    "secrets": "high", "vulnerable_dependency": "high", "nosqli": "high", "xxe": "high",
    "path_traversal": "high",
    "xss": "medium", "ssrf": "medium", "mass_assignment": "medium", "data_exposure": "medium",
    "open_redirect": "medium", "ldap_injection": "medium", "crypto": "medium",
    "injection": "medium", "csrf": "medium",
    "security_misconfig": "low",
}

_DATASTORE = {
    "sqli": "Database", "nosqli": "Database", "ssrf": "External service",
    "path_traversal": "Filesystem", "file_upload": "Filesystem",
    "deserialization": "Application runtime", "command_injection": "Operating system",
    "secrets": "Secret store", "xxe": "Filesystem",
}

_RISK = {
    ("high", "high"): "critical", ("high", "medium"): "high", ("high", "low"): "medium",
    ("medium", "high"): "high", ("medium", "medium"): "medium", ("medium", "low"): "low",
    ("low", "high"): "medium", ("low", "medium"): "low", ("low", "low"): "low",
}


def _endpoint_for_sink(sink: Dict[str, Any], endpoints: List[Dict[str, Any]]) -> str:
    sym = (sink.get("symbol") or "").lower()
    sfile = sink.get("file") or ""
    for ep in endpoints:
        if sym and ep.get("handler", "").lower() == sym:
            return ep["id"]
    for ep in endpoints:
        if sfile and (ep.get("source") or {}).get("file") == sfile:
            return ep["id"]
    return ""


def build(bundle: Dict[str, Any]) -> Dict[str, int]:
    endpoints = (bundle.get("asm") or {}).get("endpoints", [])
    sinks = (bundle.get("inventory") or {}).get("sinks", [])
    tm = bundle.setdefault("threat_model", {})
    assets: List[Dict[str, Any]] = []
    boundaries: Dict[str, Dict[str, Any]] = {}
    dataflows: List[Dict[str, Any]] = []
    threats: List[Dict[str, Any]] = []
    datastores: Dict[str, Dict[str, Any]] = {}

    # Endpoints are assets; client->endpoint is a data flow across the internet
    # trust boundary.
    inet = boundaries.setdefault("tb-internet", {"id": "tb-internet",
                                                 "name": "Internet (untrusted clients)",
                                                 "members": []})
    for ep in endpoints:
        assets.append({"id": ep["id"], "name": f"{ep['method']} {ep['path']}",
                       "kind": "endpoint"})
        inet["members"].append(ep["id"])
        dataflows.append({"id": ob.make_id("df", "client", ep["id"]),
                          "from": "client", "to": ep["id"], "data": "request",
                          "crosses": "tb-internet"})

    # Sinks -> threats, with the data store they reach as an asset + data flow.
    for s in sinks:
        cls = s.get("class", "")
        ep_id = _endpoint_for_sink(s, endpoints)
        t = threat_for({"class": cls, "cwe": s.get("cwe", "")})
        impact = _IMPACT.get(cls, "medium")
        likelihood = "medium"
        risk = _RISK.get((likelihood, impact), "medium")
        stride = _STRIDE.get(cls, "Tampering")
        title = f"{stride}: {cls} at {s.get('file','')}:{s.get('line','')}"
        threats.append(ob.threat(
            title, stride=stride, endpoint_id=ep_id,
            owasp_api=t["owasp_api"], cwe=t["cwe"],
            likelihood=likelihood, impact=impact, risk=risk,
            mitigation=f"Remediate the {cls} sink; validate/parameterize untrusted input.",
        ))
        store = _DATASTORE.get(cls)
        if store:
            aid = "asset-" + store.lower().replace(" ", "-")
            datastores.setdefault(aid, {"id": aid, "name": store, "kind": "datastore"})
            if ep_id:
                dataflows.append({"id": ob.make_id("df", ep_id, aid),
                                  "from": ep_id, "to": aid, "data": cls,
                                  "crosses": ""})

    # PRG id/resource edges indicate object references flowing between endpoints:
    # candidate IDOR/BOLA (API1).
    prg_edges = (bundle.get("prg") or {}).get("edges", [])
    prg_nodes = {n["id"]: n for n in (bundle.get("prg") or {}).get("nodes", [])}
    idor_eps = set()
    for e in prg_edges:
        if e.get("basis") == "resource-id":
            cons = prg_nodes.get(e.get("to"), {})
            ep_id = cons.get("endpoint", "")
            if ep_id and ep_id not in idor_eps:
                idor_eps.add(ep_id)
                t = threat_for({"class": "bola"})
                threats.append(ob.threat(
                    f"Elevation of Privilege: object reference consumed by endpoint {ep_id}",
                    stride="Elevation of Privilege", endpoint_id=ep_id,
                    owasp_api=t["owasp_api"], cwe=t["cwe"],
                    likelihood="medium", impact="high", risk="high",
                    mitigation="Enforce object-level authorization on every request (BOLA/IDOR).",
                ))

    assets.extend(datastores.values())
    tm["assets"] = assets
    tm["trust_boundaries"] = list(boundaries.values())
    tm["dataflows"] = dataflows
    tm["threats"] = threats
    tm["dfd_mermaid"] = _mermaid(endpoints, datastores.values(), dataflows)

    ob.record_stage(bundle, "threat-model", tool="offat-platform", version="1.0.0")
    return {"assets": len(assets), "threats": len(threats), "dataflows": len(dataflows)}


def _mermaid(endpoints, datastores, dataflows) -> str:
    lines = ["graph LR", "  client([Client])"]
    label = {}
    for ep in endpoints:
        nid = ep["id"].replace("-", "_")
        label[ep["id"]] = nid
        lines.append(f'  {nid}["{ep["method"]} {ep["path"]}"]')
    for ds in datastores:
        nid = ds["id"].replace("-", "_")
        label[ds["id"]] = nid
        lines.append(f'  {nid}[({ds["name"]})]')
    seen = set()
    for df in dataflows:
        a = "client" if df["from"] == "client" else label.get(df["from"])
        b = label.get(df["to"])
        if not a or not b:
            continue
        key = (a, b)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"  {a} --> {b}")
    return "\n".join(lines)

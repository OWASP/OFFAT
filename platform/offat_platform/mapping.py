"""Phase 1 - Mapping: write the attack surface and sink/source inventory.

Reuses the gray-box endpoint mapper (decorator routes + OpenAPI/Swagger specs,
now carrying params and response fields) and the white-box hunter (sinks), and
records them as Bundle `asm` and `inventory` sections. Request parameters are
recorded as sources (where untrusted input enters).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import offat_bundle as ob
from offat_gb import graph_map
from offat_gb.reachability import _enclosing_symbol
from offat_wb import hunt
from offat_wb.tools import ToolStatus


def map_target(bundle: Dict[str, Any], target: str, *, use_graft: bool = False,
               classes: Optional[List[str]] = None, status: Optional[ToolStatus] = None
               ) -> ToolStatus:
    status = status or ToolStatus()

    endpoints = graph_map.map_endpoints(target, status, use_graft=use_graft)
    for e in endpoints:
        params = [ob.param(p["name"], p.get("location", "query"),
                           type=p.get("type", "string"), required=p.get("required", False))
                  for p in e.get("params", [])]
        ep = ob.endpoint(
            e["method"], e["path"], protocol="http",
            operation_id=e.get("handler", "") if e.get("framework") == "openapi" else "",
            handler=e.get("handler", ""), params=params,
            source={"file": e.get("file", ""), "line": e.get("line", 0),
                    "framework": e.get("framework", "")},
            responses=e.get("responses", []),
        )
        ep_id = ob.add_endpoint(bundle, ep)
        # Each request parameter is a source of untrusted input.
        for p in e.get("params", []):
            ob.add_source(bundle, {
                "id": ob.make_id("src", "param", ep_id, p["name"], p.get("location", "")),
                "kind": "request_param", "name": p["name"],
                "location": p.get("location", ""), "endpoint": ep_id,
                "symbol": e.get("handler", ""), "file": e.get("file", ""),
                "line": e.get("line", 0),
            })

    for f in hunt.builtin_hunt(target, classes):
        ob.add_sink(bundle, ob.sink(
            f.get("class", ""), symbol=_enclosing_symbol(target, f),
            file=f.get("file", ""), line=int(f.get("line", 0) or 0),
            cwe=f.get("cwe", ""),
        ))

    ob.record_stage(bundle, "map", tool="offat-platform", version="1.0.0")
    return status

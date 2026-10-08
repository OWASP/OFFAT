"""Stage 2 - Reachability: link endpoints to vulnerable sinks.

This is the gray-box join. A SAST finding on its own says "there is a dangerous
sink at file:line". The endpoint map says "these HTTP routes are exposed". The
reachability stage connects the two: for each finding, which exposed endpoints
can actually reach the sink through the call graph?

With graft present we walk callers of the finding's enclosing symbol up toward
handler symbols. Without graft we use a cheap, conservative heuristic: a finding
is considered reachable from endpoints declared in the same source file (the
common case for handler-local sinks), which keeps the pipeline useful offline.

Each finding gains:
    reachable_from: [ "METHOD /path", ... ]   # endpoints that reach the sink
    reachable:      bool                        # any endpoint reaches it
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

from offat_wb import tools


def _ep_label(ep: Dict[str, Any]) -> str:
    return f"{ep.get('method', 'ANY')} {ep.get('path', '')}".strip()


def _enclosing_symbol(root: str, finding: Dict[str, Any]) -> str:
    """Best-effort: the function name enclosing the finding's line."""
    rel = finding.get("file", "")
    line = int(finding.get("line", 0) or 0)
    if not rel or line <= 0:
        return ""
    import os

    path = os.path.join(root, rel)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = re.search(r"\b(?:async\s+)?def\s+(\w+)", lines[i])
        if m:
            return m.group(1)
        m = re.search(r"\bfunc(?:tion)?\s+(\w+)", lines[i])
        if m:
            return m.group(1)
    return ""


def _graft_callers(symbol: str, root: str) -> List[str]:
    """Transitive caller symbol names via graft (empty on any failure)."""
    if not symbol or not tools.have("graft"):
        return []
    data = tools.run_json(
        ["graft", "callers", symbol, root, "-d", "all", "--json"], timeout=300
    )
    names: List[str] = []
    _collect_symbol_names(data, names)
    return names


def _collect_symbol_names(data: Any, out: List[str]) -> None:
    """Walk graft JSON tolerantly, collecting any symbol/name-like strings."""
    if isinstance(data, dict):
        for key in ("name", "symbol", "id", "caller"):
            v = data.get(key)
            if isinstance(v, str):
                out.append(v.split(".")[-1].split(":")[-1])
        for v in data.values():
            _collect_symbol_names(v, out)
    elif isinstance(data, list):
        for item in data:
            _collect_symbol_names(item, out)


def link(root: str, findings: List[Dict[str, Any]],
         endpoints: List[Dict[str, Any]], status) -> List[Dict[str, Any]]:
    have_graft = tools.have("graft") and status.available.get("graft_graph")
    handlers_by_name: Dict[str, List[Dict[str, Any]]] = {}
    eps_by_file: Dict[str, List[Dict[str, Any]]] = {}
    for ep in endpoints:
        if ep.get("handler"):
            handlers_by_name.setdefault(ep["handler"], []).append(ep)
        eps_by_file.setdefault(ep.get("file", ""), []).append(ep)

    for f in findings:
        reached: Dict[str, Dict[str, Any]] = {}
        how = ""

        # 1. Handler-name match: the finding's enclosing function is an endpoint
        #    handler (decorator target or OpenAPI operationId). Works offline and
        #    links spec-driven routes to their code.
        symbol = _enclosing_symbol(root, f)
        if symbol:
            for ep in handlers_by_name.get(symbol, []):
                reached[_ep_label(ep)] = ep
            if reached:
                how = "handler match"

        # 2. graft call graph: walk callers up to a handler symbol.
        if have_graft and not reached:
            callers = set(_graft_callers(symbol, root))
            for name in callers:
                for ep in handlers_by_name.get(name, []):
                    reached[_ep_label(ep)] = ep
            if reached:
                how = "graft call graph"

        # 3. Same-file heuristic: a sink in a file that declares routes.
        if not reached:
            for ep in eps_by_file.get(f.get("file", ""), []):
                reached[_ep_label(ep)] = ep
            if reached:
                how = "same-file heuristic"

        f["reachable_from"] = sorted(reached.keys())
        f["reachable"] = bool(reached)
        if reached:
            f.setdefault("evidence", {})["reachability"] = (
                "reachable from " + ", ".join(sorted(reached.keys())) + f" ({how})"
            )
    return findings

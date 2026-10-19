"""The code graph: a networkx MultiDiGraph shared by every language frontend.

Node kinds
    function  a function/method (attrs: name, qualname, file, line, params, entry, route)
    param     a formal parameter of a function
    var       one *version* of a local variable (a new node per assignment, so
              ``x = int(x)`` really does cut the flow)
    global    a module-level name (flow-insensitive)
    field     an attribute on ``self`` keyed by class (``User.email``)
    call      a call site; the node is the call's *result value*
    arg       one argument at a call site (sinks are annotated here)
    return    a function's return value
    source    attacker-controlled input (request field, handler param, ...)

Edge kinds
    flow      data moves from u to v (optionally ``sanitizes={classes}``)
    call      arg -> param at call site ``site`` (interprocedural entry)
    ret       return -> call at call site ``site`` (interprocedural exit)
    calls     function -> function (call graph; data-free)
    contains  function -> call (structure)

Every node carries ``file``, ``line`` and ``code`` so a path can be rendered
as source lines for a human or an LLM.
"""

from __future__ import annotations

import json
from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Set

import networkx as nx


class CodeGraph:
    def __init__(self) -> None:
        self.g = nx.MultiDiGraph()
        self.lines: Dict[str, List[str]] = {}   # rel file -> source lines

    # --- construction ------------------------------------------------------
    def node(self, nid: str, kind: str, **attrs: Any) -> str:
        if nid in self.g:
            self.g.nodes[nid].update({k: v for k, v in attrs.items() if v is not None})
        else:
            self.g.add_node(nid, kind=kind, **attrs)
        return nid

    def flow(self, u: str, v: str, kind: str = "flow", **attrs: Any) -> None:
        if u == v or u not in self.g or v not in self.g:
            return
        # Avoid parallel duplicates of the same edge kind/site.
        for _, data in (self.g.get_edge_data(u, v) or {}).items():
            if data.get("kind") == kind and data.get("site") == attrs.get("site") \
                    and data.get("sanitizes") == attrs.get("sanitizes"):
                return
        self.g.add_edge(u, v, kind=kind, **attrs)

    def code_at(self, file: str, line: int) -> str:
        src = self.lines.get(file) or []
        if 1 <= line <= len(src):
            return src[line - 1].strip()[:240]
        return ""

    # --- queries (used by the taint engine, graybox and the AI tools) --------
    def functions(self) -> Iterable[str]:
        return (n for n, d in self.g.nodes(data=True) if d.get("kind") == "function")

    def entry_functions(self) -> List[str]:
        return [n for n in self.functions() if self.g.nodes[n].get("entry")]

    def callers(self, fn: str, depth: int = 50) -> Set[str]:
        """Transitive callers of a function over the ``calls`` edges."""
        seen: Set[str] = set()
        q = deque([(fn, 0)])
        while q:
            cur, d = q.popleft()
            if d >= depth:
                continue
            for u, _, data in self.g.in_edges(cur, data=True):
                if data.get("kind") == "calls" and u not in seen:
                    seen.add(u)
                    q.append((u, d + 1))
        return seen

    def callees(self, fn: str) -> Set[str]:
        return {v for _, v, d in self.g.out_edges(fn, data=True) if d.get("kind") == "calls"}

    def function_of(self, nid: str) -> Optional[str]:
        return self.g.nodes[nid].get("fn") if nid in self.g else None

    def entries_reaching(self, fn: str) -> List[str]:
        """Entry-point functions (route handlers etc.) from which ``fn`` is reachable."""
        out = [fn] if self.g.nodes.get(fn, {}).get("entry") else []
        out += [c for c in self.callers(fn) if self.g.nodes[c].get("entry")]
        return sorted(set(out))

    def function_source(self, fn: str, max_lines: int = 80) -> str:
        d = self.g.nodes.get(fn) or {}
        src = self.lines.get(d.get("file", "")) or []
        start = int(d.get("line", 0) or 0)
        end = int(d.get("end_line", start) or start)
        if not start:
            return ""
        end = min(end, start + max_lines - 1, len(src))
        return "".join(f"{i:>5}  {src[i - 1]}" for i in range(start, end + 1)).rstrip()

    def find_function(self, name: str) -> List[str]:
        """Resolve a bare or dotted name to function node ids (for AI tools)."""
        out = []
        for n in self.functions():
            d = self.g.nodes[n]
            if name in (d.get("name"), d.get("qualname"), n) or n.endswith(":" + name):
                out.append(n)
        return out

    def stats(self) -> Dict[str, int]:
        kinds: Dict[str, int] = {}
        for _, d in self.g.nodes(data=True):
            kinds[d.get("kind", "?")] = kinds.get(d.get("kind", "?"), 0) + 1
        ekinds: Dict[str, int] = {}
        for _, _, d in self.g.edges(data=True):
            ekinds[d.get("kind", "?")] = ekinds.get(d.get("kind", "?"), 0) + 1
        return {**{f"nodes.{k}": v for k, v in sorted(kinds.items())},
                **{f"edges.{k}": v for k, v in sorted(ekinds.items())}}

    # --- export ------------------------------------------------------------
    def to_json(self, path: str) -> None:
        def clean(d: Dict[str, Any]) -> Dict[str, Any]:
            out = {}
            for k, v in d.items():
                if isinstance(v, (set, frozenset)):
                    v = sorted(v)
                out[k] = v
            return out
        data = {
            "nodes": [{"id": n, **clean(d)} for n, d in self.g.nodes(data=True)],
            "edges": [{"source": u, "target": v, **clean(d)} for u, v, d in self.g.edges(data=True)],
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=1, default=str)

    def to_graphml(self, path: str) -> None:
        """GraphML for Gephi / yEd / Neo4j import (non-scalar attrs stringified)."""
        h = nx.MultiDiGraph()
        for n, d in self.g.nodes(data=True):
            h.add_node(n, **{k: (v if isinstance(v, (str, int, float, bool)) else json.dumps(v, default=str))
                             for k, v in d.items() if v is not None})
        for u, v, d in self.g.edges(data=True):
            h.add_edge(u, v, **{k: (x if isinstance(x, (str, int, float, bool)) else json.dumps(x, default=str))
                                for k, x in d.items() if x is not None})
        nx.write_graphml(h, path)

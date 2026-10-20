"""Interprocedural taint search over the CodeGraph.

A breadth-first search from every ``source`` node along ``flow``/``call``/``ret``
edges. The search state is ``(node, call stack, sanitized classes)``:

* ``call`` edges push their call site, ``ret`` edges only pop a matching site
  (CFL-style matched calls/returns; with an empty stack a return may go to any
  caller, which is how taint escapes a handler-local helper). The stack is
  bounded (``k``) so recursion terminates.
* an edge with ``sanitizes={...}`` adds those classes to the state, so
  ``shlex.quote`` stops command injection but not SQL injection.

Reaching an ``arg`` node annotated with a sink whose class is not sanitized
yields a flow. The shortest path per (sink, class) is kept and rendered as
``file:line  code`` hops - the evidence a human (or the AI triager) needs.
"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from . import specs
from .graph import CodeGraph

State = Tuple[str, Tuple[str, ...], FrozenSet[str]]

_SKIP_EDGES = {"calls", "contains"}
_WHOLE_OBJECT = re.compile(r"(\.body|\.json|get_json\(\)|get_data\(\)|\.form|\.POST|\.data|"
                           r"query_params|handler param)$|handler param `\w+`: [A-Z]")
_STRING_ONLY = re.compile(r"(^|\.)(params|path_params|view_args|match_info|headers|cookies|COOKIES|META)"
                          r"(\??\.|\[|$)|handler param `\w+`: "
                          r"(int|str|float|bool|UUID)")
_COMMENT = re.compile(r"(?m)\s(#|//).*$")


def search(cg: CodeGraph, k: int = 5, max_states: int = 60_000,
           include_local: bool = False) -> List[Dict[str, Any]]:
    g = cg.g
    best: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for src, sd in g.nodes(data=True):
        if sd.get("kind") != "source":
            continue
        if sd.get("trust") == "local" and not include_local:
            continue
        start: State = (src, (), frozenset())
        parent: Dict[State, Optional[Tuple[State, Dict[str, Any]]]] = {start: None}
        q = deque([start])
        while q and len(parent) < max_states:
            state = q.popleft()
            node, stack, san = state
            nd = g.nodes[node]
            if nd.get("kind") == "arg" and nd.get("sinks"):
                for sink in nd["sinks"]:
                    cls = sink["class"]
                    if specs.ALL in san or cls in san:
                        continue
                    if cls == "bola" and not _bola_source(sd):
                        continue
                    if sink.get("whole_object") and not _WHOLE_OBJECT.search(sd.get("label", "")):
                        continue
                    if cls == "nosqli" and _STRING_ONLY.search(sd.get("label", "")) \
                            and "$where" not in nd.get("code", ""):
                        continue   # path params are strings: no operator smuggling (but $where is JS eval)
                    path, weak = _path(parent, state)
                    key = (node, cls)
                    cur = best.get(key)
                    if cur is None or len(path) < len(cur["path"]):
                        best[key] = {"source": src, "sink_node": node, "sink": sink,
                                     "path": path, "weak": weak,
                                     "sources": {src} | (cur["sources"] if cur else set())}
                    else:
                        cur["sources"].add(src)
            for _, v, d in g.out_edges(node, data=True):
                kind = d.get("kind")
                if kind in _SKIP_EDGES:
                    continue
                nstack = stack
                if kind == "call":
                    nstack = (stack + (d.get("site", ""),))[-k:]
                elif kind == "ret":
                    if stack:
                        if stack[-1] != d.get("site"):
                            continue
                        nstack = stack[:-1]
                nsan = san | d["sanitizes"] if d.get("sanitizes") else san
                ns: State = (v, nstack, nsan)
                if ns in parent:
                    continue
                parent[ns] = (state, d)
                q.append(ns)
    return list(best.values())


def _bola_source(sd: Dict[str, Any]) -> bool:
    """BOLA only makes sense for an identifier the client picks."""
    label = (sd.get("param") or sd.get("label") or "").lower()
    return bool(re.search(r"(^|[^a-z])(id|pk|uuid|slug|key|number|no)\b|_id\b|id`|\bid\b", label)) \
        or "view_args" in label or "path_params" in label or "params" in label or "args" in label


def _path(parent, state) -> Tuple[List[str], bool]:
    nodes: List[str] = []
    weak = False
    cur = state
    while cur is not None:
        nodes.append(cur[0])
        link = parent.get(cur)
        if link is None:
            break
        prev, edge = link
        weak = weak or bool(edge.get("weak"))
        cur = prev
    return list(reversed(nodes)), weak


# --- findings -------------------------------------------------------------

def render_hops(cg: CodeGraph, path: List[str]) -> List[Dict[str, Any]]:
    hops: List[Dict[str, Any]] = []
    for nid in path:
        d = cg.g.nodes[nid]
        kind = d.get("kind")
        file, line = d.get("file", ""), int(d.get("line", 0) or 0)
        if kind in ("global",) and not line:
            label = d.get("code", nid)
        elif kind == "return":
            label = d.get("code", "")
        else:
            label = d.get("label") or d.get("name") or d.get("callee") or ""
        hop = {"kind": kind, "file": file, "line": line, "code": d.get("code", ""), "label": label}
        if hops and hops[-1]["file"] == file and hops[-1]["line"] == line and kind not in ("source",):
            if hops[-1]["kind"] != "source" and kind == "arg":
                hops[-1] = {**hops[-1], "kind": "arg"}
            continue
        hops.append(hop)
    return hops


def hops_text(hops: List[Dict[str, Any]]) -> str:
    return "\n".join(f"  {i + 1:>2}. {h['file']}:{h['line']}  [{h['kind']}] {h['code']}"
                     for i, h in enumerate(hops))


def _snippet(cg: CodeGraph, file: str, line: int) -> str:
    src = cg.lines.get(file) or []
    start, end = max(0, line - 3), min(len(src), line + 2)
    return "".join(src[start:end]).rstrip()


def to_findings(cg: CodeGraph, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, int, str], Dict[str, Any]] = {}
    for fl in sorted(flows, key=lambda x: len(x["path"])):
        sink = fl["sink"]
        snode = cg.g.nodes[fl["sink_node"]]
        src = cg.g.nodes[fl["source"]]
        file, line = snode.get("file", ""), int(snode.get("line", 0) or 0)
        hops = render_hops(cg, fl["path"])
        # Entry points that taint this flow's source(s)...
        src_entries = {e for s in fl["sources"] for e in cg.entries_reaching(cg.g.nodes[s].get("fn", ""))}
        # ...intersected with the entry points whose call graph actually reaches the
        # sink's function. A shared field (or other merged node) can carry taint from a
        # route that never calls the sink's function (e.g. a "safe" sibling method); such
        # a route cannot trigger the sink, so it must not be attributed to the flow.
        sink_entries = set(cg.entries_reaching(snode.get("fn", "")))
        entry_fns = sorted(src_entries & sink_entries) or sorted(src_entries)
        routes = []
        for fn in entry_fns:
            r = cg.g.nodes[fn].get("route") or {}
            if r:
                routes.append(f"{r.get('method', 'ANY')} {r.get('path', '')}".strip())
        conf = 0.85
        if fl["weak"]:
            conf -= 0.15
        if len(hops) > 12:
            conf -= 0.1
        if not entry_fns and src.get("trust") != "local":
            conf -= 0.1
        cls = sink["class"]
        extra: Dict[str, Any] = {}
        if cls == "bola":
            authz = _authz_context(cg, fl, entry_fns)
            if authz["scoped"]:
                continue
            conf = 0.55 if authz["auth"] else 0.45
            extra["authz"] = authz
        uid = hashlib.sha1(f"cpg:{cls}:{file}:{line}:{src.get('file')}:{src.get('line')}".encode()).hexdigest()[:12]
        f = {
            "id": uid,
            "vector_id": f"taint-{cls}",
            "class": cls,
            "title": sink["title"],
            "severity": sink["severity"],
            "cwe": sink["cwe"],
            "owasp": sink["owasp"],
            "file": file,
            "line": line,
            "technique": "taint-graph",
            "confidence": round(max(0.2, min(conf, 0.95)), 2),
            "code": _snippet(cg, file, line),
            "traced": True,
            "evidence": {
                "source": f"{src.get('label')} @ {src.get('file')}:{src.get('line')}",
                "sink": f"{sink.get('sink')} @ {file}:{line}",
                "data_flow": " -> ".join(f"{h['file']}:{h['line']}" for h in hops),
                "path": hops,
                "sources": sorted(f"{cg.g.nodes[s].get('label')} @ {cg.g.nodes[s].get('file')}:"
                                  f"{cg.g.nodes[s].get('line')}" for s in fl["sources"]),
                "entrypoints": [cg.g.nodes[e].get("qualname") for e in entry_fns],
                "notes": "source-to-sink path proven on the code graph"
                         + (" (uses a name-resolved call edge)" if fl["weak"] else ""),
                **extra,
            },
            "reachable_from": routes,
            "reachable": bool(routes) or bool(entry_fns),
            "references": [f"https://cwe.mitre.org/data/definitions/{sink['cwe'].split('-')[1]}.html"],
            "source_tool": "offat-cpg",
        }
        key = (file, line, cls)
        if key in seen:   # same sink line reached via a sibling arg (text() inside execute())
            seen[key]["evidence"]["sources"] = sorted(set(seen[key]["evidence"]["sources"])
                                                      | set(f["evidence"]["sources"]))
            continue
        seen[key] = f
        if src.get("param"):
            f["param"] = src["param"]
        if routes:
            f["endpoint"] = routes[0]
        out.append(f)
    out.sort(key=lambda x: (x["file"], x["line"], x["class"]))
    return out


def _authz_context(cg: CodeGraph, fl: Dict[str, Any], entry_fns: List[str]) -> Dict[str, Any]:
    """Is the object lookup scoped to the caller, or guarded by an ownership check?"""
    snode = cg.g.nodes[fl["sink_node"]]
    file, line = snode.get("file", ""), int(snode.get("line", 0) or 0)
    tokens = specs.AUTH_IDENTITY_TOKENS + specs.JS_AUTH_TOKENS
    src_lines = [_COMMENT.sub("", ln) for ln in (cg.lines.get(file) or [])]
    call_text = "".join(src_lines[max(0, line - 1): line + 1])
    fn = snode.get("fn", "")
    fd = cg.g.nodes.get(fn, {})
    after = "".join(src_lines[line: int(fd.get("end_line", line) or line)])
    scoped = any(t in call_text for t in tokens)
    owner_check = bool(re.search(r"(owner|user_?id|current_user|request\.user|req\.user)[^\n]*(!=|==|!==|===)"
                                 r"|(!=|==|!==|===)[^\n]*(owner|user_?id|current_user|request\.user|req\.user)",
                                 after))
    handler_text = "\n".join(_COMMENT.sub("", cg.function_source(e, 400)) for e in entry_fns) + "\n" + \
        "\n".join(str(cg.g.nodes[e].get("decorators", "")) for e in entry_fns)
    auth = any(t in handler_text for t in tokens) or bool(re.search(
        r"login_required|jwt_required|auth|permission|Depends\(\s*get_current|authenticate", handler_text))
    return {"scoped": scoped or owner_check, "auth": auth, "owner_check": owner_check}

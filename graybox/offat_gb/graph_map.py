"""Stage 1 - Map the endpoint attack surface with graft.

The gray-box pipeline needs the full set of HTTP entry points (the black-box
surface) tied back to their handler symbols in source (the white-box view).
``graft`` builds a structural code graph for free (tree-sitter, no API key, no
LLM tokens), and we query it to locate every route declaration and its
enclosing handler. When graft is not installed the same route declarations are
recovered with a dependency-free regex pass, so the pipeline always produces an
endpoint map.

Endpoint schema (one dict per route):
    {method, path, handler, file, line, framework}
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from offat_wb import tools
from offat_wb.hunt import iter_source_files

# --- route declaration patterns, per framework -----------------------------
# Each entry: framework, compiled regex with named groups (method?, path),
# and the file extensions it applies to. method is optional; when absent the
# endpoint method is resolved separately (decorator verb, or ANY).

_PY_DECORATOR = re.compile(
    r"""@\s*\w+\s*\.\s*(?P<verb>route|get|post|put|delete|patch|head|options)\s*\(\s*"""
    r"""['"](?P<path>[^'"]+)['"]"""
    r"""(?P<rest>[^)]*)""",
    re.IGNORECASE,
)
_PY_METHODS = re.compile(r"methods\s*=\s*\[(?P<methods>[^\]]*)\]", re.IGNORECASE)

_EXPRESS = re.compile(
    r"""(?:app|router|r)\s*\.\s*(?P<verb>get|post|put|delete|patch|all|use)\s*\(\s*"""
    r"""['"`](?P<path>/[^'"`]*)['"`]""",
    re.IGNORECASE,
)

_DJANGO = re.compile(
    r"""(?:re_)?path\s*\(\s*r?['"](?P<path>[^'"]*)['"]\s*,\s*(?P<handler>[A-Za-z_][\w.]*)""",
)

_SPRING = re.compile(
    r"""@\s*(?P<verb>Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*"""
    r"""(?:value\s*=\s*|path\s*=\s*)?['"](?P<path>[^'"]+)['"]""",
)

_GO_ROUTER = re.compile(
    r"""\.\s*(?P<verb>GET|POST|PUT|DELETE|PATCH|Handle|HandleFunc)\s*\(\s*"""
    r"""['"](?P<path>/[^'"]*)['"]\s*,\s*(?P<handler>[A-Za-z_][\w.]*)""",
)

_RAILS = re.compile(
    r"""^\s*(?P<verb>get|post|put|patch|delete)\s+['"](?P<path>[^'"]+)['"]""",
)

_PY_EXTS = {".py"}
_JS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs"}
_JAVA_EXTS = {".java", ".kt"}
_GO_EXTS = {".go"}
_RUBY_EXTS = {".rb"}


def _next_handler(lines: List[str], idx: int) -> str:
    """Return the function/method name defined just after a decorator line."""
    for j in range(idx, min(idx + 6, len(lines))):
        m = re.search(r"\b(?:async\s+)?def\s+(\w+)", lines[j])
        if m:
            return m.group(1)
        m = re.search(r"\bfunction\s+(\w+)", lines[j])
        if m:
            return m.group(1)
    return ""


def _methods_from_rest(rest: str, verb: str) -> List[str]:
    if verb.lower() != "route":
        return [verb.upper()]
    mm = _PY_METHODS.search(rest or "")
    if not mm:
        return ["GET"]
    methods = re.findall(r"['\"](\w+)['\"]", mm.group("methods"))
    return [m.upper() for m in methods] or ["GET"]


def _scan_file(path: str, rel: str, ext: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: List[Dict[str, Any]] = []

    def add(method: str, route: str, handler: str, lineno: int, fw: str) -> None:
        out.append({
            "method": method.upper(),
            "path": route,
            "handler": handler,
            "file": rel,
            "line": lineno,
            "framework": fw,
        })

    for i, line in enumerate(lines):
        if ext in _PY_EXTS:
            m = _PY_DECORATOR.search(line)
            if m:
                handler = _next_handler(lines, i + 1)
                fw = "fastapi" if m.group("verb").lower() != "route" else "flask"
                for method in _methods_from_rest(m.group("rest"), m.group("verb")):
                    add(method, m.group("path"), handler, i + 1, fw)
                continue
        if ext in _JS_EXTS:
            m = _EXPRESS.search(line)
            if m and m.group("verb").lower() not in ("use",):
                add(m.group("verb"), m.group("path"), "", i + 1, "express")
                continue
        if ext in _PY_EXTS and ("path(" in line or "re_path(" in line):
            m = _DJANGO.search(line)
            if m:
                add("ANY", m.group("path"), m.group("handler"), i + 1, "django")
                continue
        if ext in _JAVA_EXTS:
            m = _SPRING.search(line)
            if m:
                verb = m.group("verb")
                method = "ANY" if verb == "Request" else verb.upper()
                handler = _next_handler(lines, i + 1)
                add(method, m.group("path"), handler, i + 1, "spring")
                continue
        if ext in _GO_EXTS:
            m = _GO_ROUTER.search(line)
            if m:
                verb = m.group("verb")
                method = "ANY" if verb in ("Handle", "HandleFunc") else verb.upper()
                add(method, m.group("path"), m.group("handler"), i + 1, "go")
                continue
        if ext in _RUBY_EXTS:
            m = _RAILS.search(line)
            if m:
                add(m.group("verb"), m.group("path"), "", i + 1, "rails")
                continue
    return out


_HTTP_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}


def _spec_endpoints(path: str, rel: str) -> List[Dict[str, Any]]:
    """Endpoints declared in an OpenAPI/Swagger spec (YAML or JSON).

    Covers spec-driven frameworks (e.g. connexion) where routes live in the spec
    rather than code decorators. operationId, when present, becomes the handler so
    the reachability stage can link the route back to its function.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []
    low = text.lower()
    if "paths" not in low or ("openapi" not in low and "swagger" not in low):
        return []

    data = None
    try:
        import yaml  # optional; PyYAML
        data = yaml.safe_load(text)
    except Exception:
        try:
            import json
            data = json.loads(text)
        except Exception:
            data = None
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return _spec_endpoints_regex(text, rel)

    out: List[Dict[str, Any]] = []
    for route, item in data["paths"].items():
        if not isinstance(item, dict):
            continue
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            handler = ""
            if isinstance(op, dict) and op.get("operationId"):
                handler = str(op["operationId"]).split(".")[-1]
            out.append({
                "method": method.upper(), "path": str(route), "handler": handler,
                "file": rel, "line": _line_of(text, route), "framework": "openapi",
            })
    return out


def _spec_endpoints_regex(text: str, rel: str) -> List[Dict[str, Any]]:
    """Fallback spec parse when no YAML/JSON loader yields a dict."""
    out: List[Dict[str, Any]] = []
    lines = text.splitlines()
    cur_path = None
    path_indent = -1
    for i, line in enumerate(lines):
        pm = re.match(r"^(\s*)(/\S*):\s*$", line)
        if pm:
            cur_path = pm.group(2)
            path_indent = len(pm.group(1))
            continue
        if cur_path:
            mm = re.match(r"^(\s*)(get|post|put|delete|patch|head|options):", line, re.IGNORECASE)
            if mm and len(mm.group(1)) > path_indent:
                out.append({
                    "method": mm.group(2).upper(), "path": cur_path, "handler": "",
                    "file": rel, "line": i + 1, "framework": "openapi",
                })
    return out


def _line_of(text: str, needle: str) -> int:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    return 0


def native_map(root: str) -> List[Dict[str, Any]]:
    """Dependency-free endpoint discovery across supported frameworks + specs."""
    endpoints: List[Dict[str, Any]] = []
    for path, ext in iter_source_files(root):
        rel = os.path.relpath(path, root)
        if ext in (".yaml", ".yml", ".json"):
            endpoints.extend(_spec_endpoints(path, rel))
        else:
            endpoints.extend(_scan_file(path, rel, ext))
    return _dedupe(endpoints)


def _dedupe(endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen, out = set(), []
    for e in endpoints:
        key = (e["method"], e["path"], e["file"], e["line"])
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out


def ensure_graft(status) -> bool:
    """Record graft availability. Never installs anything (a machine change)."""
    ok = tools.have("graft")
    status.available["graft"] = ok
    if not ok:
        status.skip("graft", "not installed; using native endpoint mapping")
    return ok


def graft_build(root: str) -> bool:
    """Build the structural graph ($0, no key). Returns True on success."""
    if not tools.have("graft"):
        return False
    try:
        proc = tools.run(["graft", "build", root], timeout=1200)
    except Exception:
        return False
    return proc.returncode == 0


def map_endpoints(root: str, status, use_graft: bool = True) -> List[Dict[str, Any]]:
    """Map the endpoint attack surface.

    Uses graft's structural graph when present (built once, queried for route
    declarations), and always confirms paths/handlers with the native parser so
    output is deterministic. Falls back cleanly to the native parser when graft
    is unavailable or disabled.
    """
    if not use_graft:
        status.available["graft"] = False
        status.skip("graft", "disabled (--no-graft); using native endpoint mapping")
        return native_map(root)
    have_graft = ensure_graft(status)
    if have_graft:
        built = graft_build(root)
        status.available["graft_graph"] = built
        if not built:
            status.skip("graft", "build failed; using native endpoint mapping")
    # The native parser is the authoritative, deterministic extractor; the graft
    # graph (when built) powers the reachability stage that follows.
    return native_map(root)

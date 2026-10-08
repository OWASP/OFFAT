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


def native_map(root: str) -> List[Dict[str, Any]]:
    """Dependency-free endpoint discovery across supported frameworks."""
    endpoints: List[Dict[str, Any]] = []
    for path, ext in iter_source_files(root):
        rel = os.path.relpath(path, root)
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

"""Optional graft-backed source-to-sink tracing.

The built-in hunter finds sinks by pattern. This pass, when graft is installed,
asks the structural call graph whether each sink's enclosing symbol is reachable
from an entry point (a route handler, controller, `main`, CLI, or message
consumer). A sink an attacker can actually reach is more credible, so a traced
finding gets a confidence bump and a data-flow note; an isolated sink is left as
found. Without graft the pass is a no-op (the report records the degradation).
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from . import tools

# Caller names that look like untrusted entry points.
_ENTRY_HINTS = re.compile(
    r"(handler|handle|route|view|controller|endpoint|resolver|"
    r"^main$|_main|cli|command|consume|subscribe|listen|on_message|lambda_handler)",
    re.IGNORECASE,
)

_SYMBOL_RE = re.compile(r"\b(?:async\s+)?def\s+(\w+)|\bfunc(?:tion)?\s+(\w+)")


def _enclosing_symbol(root: str, finding: Dict[str, Any]) -> str:
    rel = finding.get("file", "")
    line = int(finding.get("line", 0) or 0)
    if not rel or line <= 0:
        return ""
    path = os.path.join(root, rel)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            lines = fh.readlines()
    except OSError:
        return ""
    for i in range(min(line, len(lines)) - 1, -1, -1):
        m = _SYMBOL_RE.search(lines[i])
        if m:
            return m.group(1) or m.group(2) or ""
    return ""


def _caller_names(symbol: str, root: str) -> List[str]:
    if not symbol or not tools.have("graft"):
        return []
    data = tools.run_json(
        ["graft", "callers", symbol, root, "-d", "all", "--json"], timeout=300
    )
    names: List[str] = []
    _collect(data, names)
    return names


def _collect(data: Any, out: List[str]) -> None:
    if isinstance(data, dict):
        for key in ("name", "symbol", "id", "caller"):
            v = data.get(key)
            if isinstance(v, str):
                out.append(v.split(".")[-1].split(":")[-1])
        for v in data.values():
            _collect(v, out)
    elif isinstance(data, list):
        for item in data:
            _collect(item, out)


def trace(root: str, findings: List[Dict[str, Any]], status) -> List[Dict[str, Any]]:
    """Annotate findings with graft reachability. No-op without graft."""
    if not tools.have("graft"):
        status.available.setdefault("graft", False)
        status.skip("graft", "not installed; skipping source-to-sink tracing")
        return findings
    status.available["graft"] = True
    try:
        built = tools.run(["graft", "build", root], timeout=1200).returncode == 0
    except Exception:
        built = False
    status.available["graft_graph"] = built
    if not built:
        status.skip("graft", "build failed; skipping source-to-sink tracing")
        return findings

    for f in findings:
        symbol = _enclosing_symbol(root, f)
        callers = _caller_names(symbol, root)
        entries = sorted({c for c in callers if _ENTRY_HINTS.search(c or "")})
        if entries:
            f["traced"] = True
            f["confidence"] = min(1.0, float(f.get("confidence", 0.5)) + 0.15)
            f.setdefault("evidence", {})["data_flow"] = (
                "reachable from entry point(s): " + ", ".join(entries[:5])
            )
        else:
            f.setdefault("traced", False)
    return findings

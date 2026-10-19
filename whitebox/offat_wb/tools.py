"""External tool discovery and subprocess helpers.

Every integration degrades gracefully: if a tool is not installed the wrapper
returns an empty result and records the tool as skipped, so the pipeline runs
end-to-end with whatever is available.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolStatus:
    available: Dict[str, bool] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def mark(self, name: str) -> bool:
        ok = shutil.which(name) is not None
        self.available[name] = ok
        return ok

    def skip(self, name: str, reason: str) -> None:
        self.notes.append(f"{name}: skipped ({reason})")


def have(name: str) -> bool:
    return shutil.which(name) is not None


def run(cmd: List[str], cwd: Optional[str] = None, timeout: int = 900) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False
    )


def run_json(cmd: List[str], cwd: Optional[str] = None, timeout: int = 900) -> Optional[Any]:
    """Run a command and parse stdout as JSON. Returns None on any failure."""
    try:
        proc = run(cmd, cwd=cwd, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # Some tools emit JSON on the last line or NDJSON.
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.startswith("{") or line.startswith("["):
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
    return None

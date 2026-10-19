"""Persistent AI-verdict cache, shared by the white-box and gray-box pipelines.

AI triage is the only token-spending stage, so each verdict is keyed on a hash of
the finding's stable content. A re-run reuses cached verdicts and pays tokens only
for findings that are new or have changed, which makes iterating cheap.

The cache is a plain JSON file inside the run's output directory.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Optional

DEFAULT_CACHE_NAME = ".offat-triage-cache.json"


def finding_key(finding: Dict[str, Any]) -> str:
    basis = {
        "class": finding.get("class", ""),
        "vector_id": finding.get("vector_id", ""),
        "file": finding.get("file", ""),
        "line": finding.get("line", 0),
        "endpoint": finding.get("endpoint", ""),
        "param": finding.get("param", ""),
        "payload": finding.get("payload", ""),
        "code": (finding.get("code", "") or "")[:500],
        "reachable_from": sorted(finding.get("reachable_from", []) or []),
    }
    blob = json.dumps(basis, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


class VerdictCache:
    def __init__(self, out_dir: str, enabled: bool = True,
                 name: str = DEFAULT_CACHE_NAME) -> None:
        self.path = os.path.join(out_dir, name)
        self.enabled = enabled
        self._data: Dict[str, Any] = {}
        self.hits = 0
        self.misses = 0
        if enabled:
            self._load()

    def _load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self._data = loaded.get("verdicts", {})
        except (OSError, json.JSONDecodeError):
            self._data = {}

    def get(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        v = self._data.get(finding_key(finding))
        if v is not None:
            self.hits += 1
        else:
            self.misses += 1
        return v

    def put(self, finding: Dict[str, Any], verdict: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        self._data[finding_key(finding)] = verdict

    def save(self) -> None:
        if not self.enabled:
            return
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump({"version": 1, "verdicts": self._data}, fh, indent=2)
        except OSError:
            pass

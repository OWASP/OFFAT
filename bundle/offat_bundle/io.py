"""Load, save and merge OFFAT Bundles."""

from __future__ import annotations

import json
from typing import Any, Dict, List

_LIST_SECTIONS = {
    "asm": ["endpoints"],
    "inventory": ["sinks", "sources"],
    "prg": ["nodes", "edges"],
    "threat_model": ["assets", "trust_boundaries", "dataflows", "threats"],
    "test_plan": ["cases"],
    "results": ["executions"],
}


def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def save(bundle: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)


def _merge_by_id(dst: List[Dict[str, Any]], src: List[Dict[str, Any]]) -> None:
    index = {item.get("id"): i for i, item in enumerate(dst) if "id" in item}
    for item in src:
        key = item.get("id")
        if key is not None and key in index:
            dst[index[key]] = item  # replace existing by id
        else:
            dst.append(item)


def merge(base: Dict[str, Any], other: Dict[str, Any]) -> Dict[str, Any]:
    """Merge ``other`` into ``base`` (in place) and return it.

    List sections union by id (later wins); `findings` unions by id when present
    else appends; `meta.stages` concatenate; scalars in `meta` and `summary` are
    overwritten by non-empty values from ``other``.
    """
    for section, lists in _LIST_SECTIONS.items():
        if section not in other:
            continue
        bsec = base.setdefault(section, {})
        for lk in lists:
            if lk in other[section]:
                _merge_by_id(bsec.setdefault(lk, []), other[section][lk])
        for k, v in other[section].items():
            if k not in lists:
                bsec[k] = v

    if "findings" in other:
        _merge_by_id(base.setdefault("findings", []), other["findings"])

    if "meta" in other:
        bmeta = base.setdefault("meta", {})
        for k, v in other["meta"].items():
            if k == "stages":
                bmeta.setdefault("stages", []).extend(v or [])
            elif v:
                bmeta[k] = v

    if "summary" in other:
        base.setdefault("summary", {}).update(other["summary"])

    base.setdefault("schema_version", other.get("schema_version", "1.0"))
    return base

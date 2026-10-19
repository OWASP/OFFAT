"""Identities for access-control / auth testing.

An identity is a principal the scanner can act as: a name, a role, request
`headers` (bearer token, cookie, etc.), and optionally `owns` - object ids that
belong to it (used to seed BOLA tests). Identities are loaded from a JSON file:

    [
      {"name": "admin", "role": "admin", "headers": {"Authorization": "Bearer A"}},
      {"name": "userA", "role": "user",  "headers": {"Authorization": "Bearer B"},
       "owns": {"id": "1"}},
      {"name": "userB", "role": "user",  "headers": {"Authorization": "Bearer C"},
       "owns": {"id": "2"}}
    ]

An implicit `anon` identity (no headers, role "anon") always exists for missing-auth
tests. Secrets (`headers`) never enter the Bundle - test cases reference an identity
by name and the engine resolves headers from the file at execution time.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

PRIVILEGED_ROLES = {"admin", "superadmin", "root", "manager"}


def load(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("identities file must be a JSON array")
    out = []
    for item in data:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        out.append({
            "name": str(item["name"]),
            "role": str(item.get("role", "user")).lower(),
            "headers": item.get("headers", {}) or {},
            "owns": item.get("owns", {}) or {},
        })
    return out


def with_anon(identities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if any(i["role"] == "anon" or i["name"] == "anon" for i in identities):
        return identities
    return identities + [{"name": "anon", "role": "anon", "headers": {}, "owns": {}}]


def is_privileged(identity: Dict[str, Any]) -> bool:
    return identity.get("role", "") in PRIVILEGED_ROLES


def privileged(identities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [i for i in identities if is_privileged(i)]


def unprivileged(identities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [i for i in identities if not is_privileged(i) and i.get("role") != "anon"]


def redacted(identities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identity summary safe to store in the Bundle (no headers/secrets)."""
    return [{"name": i["name"], "role": i["role"],
             "owns": list((i.get("owns") or {}).keys())} for i in identities]

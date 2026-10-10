"""Phase 3 - Test-case generation.

Generates a test plan from the attack surface, the parameter relation graph and a
compact built-in vector set. Cases are *meaningful*: vectors are matched to each
parameter by location and name hints (a `url`-like param gets SSRF/open-redirect,
an `id` gets SQLi/BOLA, a `file` gets path traversal), and multi-step cases are
seeded from the PRG so a consumer param can be driven by a producer endpoint.

Rule-based generation is deterministic and offline. With ``use_ai`` and a provider
available, the model proposes extra context-aware payloads per endpoint (batched,
best-effort, degrading to rules).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import offat_bundle as ob

# class -> (technique, cwe, payloads)
_VECTORS: Dict[str, Dict[str, Any]] = {
    "sqli": {"technique": "error", "cwe": "CWE-89",
             "payloads": ["'", "' OR '1'='1' -- "]},
    "xss": {"technique": "reflection", "cwe": "CWE-79",
            "payloads": ["<script>alert(1)</script>", "\"><svg onload=alert(1)>"]},
    "command_injection": {"technique": "time", "cwe": "CWE-78",
                          "payloads": ["; id", "| id"]},
    "ssti": {"technique": "reflection", "cwe": "CWE-1336", "payloads": ["{{7*7}}", "${7*7}"]},
    "path_traversal": {"technique": "error", "cwe": "CWE-22",
                       "payloads": ["../../../../etc/passwd", "..%2f..%2fetc%2fpasswd"]},
    "ssrf": {"technique": "reflection", "cwe": "CWE-918",
             "payloads": ["http://169.254.169.254/latest/meta-data/", "http://localhost:80/"]},
    "open_redirect": {"technique": "status", "cwe": "CWE-601",
                      "payloads": ["//evil.example", "https://evil.example/"]},
    "nosqli": {"technique": "boolean", "cwe": "CWE-943", "payloads": ["[$ne]", "' || '1'=='1"]},
    "xxe": {"technique": "error", "cwe": "CWE-611",
            "payloads": ["<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><x>&e;</x>"]},
    "ldap_injection": {"technique": "error", "cwe": "CWE-90", "payloads": ["*)(uid=*))(|(uid=*"]},
}


def _classes_for(name: str, location: str) -> List[str]:
    n = (name or "").lower()
    classes: List[str] = []
    if any(h in n for h in ("url", "uri", "link", "callback", "webhook", "redirect", "next", "return", "dest")):
        classes += ["ssrf", "open_redirect"]
    if any(h in n for h in ("file", "path", "dir", "folder", "template", "doc", "page")):
        classes += ["path_traversal"]
    if any(h in n for h in ("id", "user", "account", "order", "key", "uuid")):
        classes += ["sqli"]
    if any(h in n for h in ("q", "query", "search", "name", "title", "comment", "message", "text", "desc", "email")):
        classes += ["sqli", "xss"]
    if not classes:
        classes = ["sqli", "xss"]  # default for free-text-ish params
    # body objects can also carry nosqli; xml-ish bodies xxe
    if location == "body":
        classes.append("nosqli")
    # de-dup preserving order
    seen, out = set(), []
    for c in classes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _producer_chain(bundle: Dict[str, Any], consumer_ep: str, pname: str) -> List[str]:
    """Endpoints whose output can seed this consumer param, via the PRG."""
    prg = bundle.get("prg") or {}
    nodes = {n["id"]: n for n in prg.get("nodes", [])}
    chain = []
    for e in prg.get("edges", []):
        cons = nodes.get(e.get("to"), {})
        prod = nodes.get(e.get("from"), {})
        if cons.get("endpoint") == consumer_ep and cons.get("name", "").lower() == pname.lower():
            if prod.get("endpoint") and prod["endpoint"] != consumer_ep:
                chain.append(prod["endpoint"])
    return sorted(set(chain))


def build(bundle: Dict[str, Any], *, use_ai: bool = False,
          provider: Optional[str] = None, max_payloads: int = 2,
          identities: Optional[List[Dict[str, Any]]] = None) -> Dict[str, int]:
    endpoints = (bundle.get("asm") or {}).get("endpoints", [])
    rule_n = 0
    for ep in endpoints:
        for p in ep.get("params", []):
            chain = _producer_chain(bundle, ep["id"], p["name"])
            for cls in _classes_for(p["name"], p.get("location", "query")):
                vec = _VECTORS.get(cls)
                if not vec:
                    continue
                for payload in vec["payloads"][:max_payloads]:
                    ob.add_test_case(bundle, ob.test_case(
                        ep["id"], param=p["name"], location=p.get("location", "query"),
                        vclass=cls, technique=vec["technique"], payload=payload,
                        origin="rule", chain=chain,
                        rationale=f"{cls} probe on {p.get('location','')} param '{p['name']}'",
                        expected_signal=vec["technique"],
                    ))
                    rule_n += 1
            # BOLA/IDOR: a path id with a producer edge -> replay a foreign id.
            if p.get("location") == "path" and p["name"].lower().endswith("id") and chain:
                ob.add_test_case(bundle, ob.test_case(
                    ep["id"], param=p["name"], location="path", vclass="bola",
                    technique="diff", payload="<foreign-id>", origin="rule", chain=chain,
                    rationale="Replay a foreign object id to test object-level authorization",
                    expected_signal="unauthorized 2xx",
                ))
                rule_n += 1

    authz_n = _gen_access_control(bundle, endpoints, identities or [])
    biz_n = _gen_business_logic(bundle, endpoints)

    ai_n = 0
    if use_ai:
        ai_n = _augment_with_ai(bundle, endpoints, provider)

    ob.record_stage(bundle, "test-gen", tool="offat-platform", version="1.0.0")
    rule_total = rule_n + authz_n + biz_n
    return {"rule": rule_total, "authz": authz_n, "business": biz_n, "ai": ai_n,
            "total": rule_total + ai_n}


def _augment_with_ai(bundle, endpoints, provider) -> int:
    """Best-effort AI payloads per endpoint. No-op unless an API provider works."""
    try:
        from offat_triage.triager import AnthropicTriager
        import urllib.request
        from offat_triage.triager import ANTHROPIC_VERSION
    except Exception:
        return 0
    t = AnthropicTriager.from_env()
    if t is None:
        return 0
    added = 0
    for ep in endpoints:
        params = [p["name"] for p in ep.get("params", [])]
        if not params:
            continue
        prompt = (f"Endpoint {ep['method']} {ep['path']} with params {params}. "
                  "Propose up to 4 meaningful security test payloads. Respond ONLY as a JSON "
                  'array of {"param":"","class":"","technique":"","payload":"","rationale":""}.')
        payload = {"model": t.model, "max_tokens": 700,
                   "messages": [{"role": "user", "content": prompt}]}
        req = urllib.request.Request(
            t.base_url + "/v1/messages", data=json.dumps(payload).encode(),
            headers={"content-type": "application/json", "x-api-key": t.api_key or "",
                     "anthropic-version": ANTHROPIC_VERSION}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=t.timeout) as resp:
                data = json.loads(resp.read().decode())
            text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
            arr = json.loads(text[text.find("["):text.rfind("]") + 1])
        except Exception:
            continue
        for item in arr if isinstance(arr, list) else []:
            if not isinstance(item, dict) or not item.get("payload"):
                continue
            ob.add_test_case(bundle, ob.test_case(
                ep["id"], param=str(item.get("param", "")), vclass=str(item.get("class", "")),
                technique=str(item.get("technique", "")), payload=str(item["payload"]),
                origin="ai", rationale=str(item.get("rationale", ""))[:300]))
            added += 1
    return added


# --- access control (BOLA/BFLA/RBAC), auth, business logic ------------------

_PRIV_HINT = ("admin", "manage", "internal", "config", "approve", "promote",
              "grant", "role", "setting", "delete", "disable", "enable", "owner")
_WRITE = {"POST", "PUT", "PATCH", "DELETE"}
_MONEY = ("price", "amount", "qty", "quantity", "total", "balance", "discount",
          "cost", "credit", "points", "limit", "fee")
_PRIV_FIELDS = {"role": "admin", "is_admin": "true", "isadmin": "true",
                "admin": "true", "is_staff": "true", "verified": "true"}


def _is_priv_endpoint(ep: Dict[str, Any]) -> bool:
    text = (ep.get("path", "") + " " + ep.get("handler", "")).lower()
    if any(h in text for h in _PRIV_HINT):
        return True
    return ep.get("method", "GET").upper() == "DELETE"


def _id_path_params(ep: Dict[str, Any]):
    return [p for p in ep.get("params", [])
            if p.get("location") == "path" and
            (p["name"].lower() == "id" or p["name"].lower().endswith("id")
             or p["name"].lower().endswith("_id"))]


def _gen_access_control(bundle, endpoints, identities) -> int:
    from . import identities as idmod
    ids = idmod.with_anon(identities) if identities else [{"name": "anon", "role": "anon", "owns": {}}]
    privs = idmod.privileged(identities)
    unprivs = idmod.unprivileged(identities)
    owners = [i for i in identities if i.get("owns")]
    n = 0

    for ep in endpoints:
        # 1) Missing authentication: call with no credentials, expect a deny.
        n += _add(bundle, ep, vclass="broken_auth", technique="no-auth",
                  identity="anon", expected_status="401/403",
                  rationale="Call the endpoint with no credentials; a protected endpoint must deny.")

        # 2) BOLA: request another principal's object id.
        for idp in _id_path_params(ep):
            for owner in owners:
                oid = str(owner["owns"].get(idp["name"]) or owner["owns"].get("id") or "")
                if not oid:
                    continue
                for other in ids:
                    if other["name"] == owner["name"]:
                        continue
                    if idmod.is_privileged(other):
                        continue  # a privileged principal reading others' objects is expected
                    n += _add(bundle, ep, vclass="bola", technique="authz-diff",
                              param=idp["name"], location="path", payload=oid,
                              identity=other["name"], baseline_identity=owner["name"],
                              expected_status="403/404",
                              rationale=f"Access {owner['name']}'s object ({idp['name']}={oid}) as {other['name']}.")

        # 3) BFLA: privileged endpoint reached by a non-privileged identity.
        if _is_priv_endpoint(ep) and (unprivs or not identities):
            targets = unprivs or [{"name": "anon", "role": "anon"}]
            base = privs[0]["name"] if privs else ""
            for other in targets:
                n += _add(bundle, ep, vclass="bfla", technique="authz-diff",
                          identity=other["name"], baseline_identity=base,
                          expected_status="403",
                          rationale=f"Privileged function reached as non-privileged '{other['name']}'.")

        # 4) RBAC: state-changing endpoint invoked by each non-admin role.
        elif ep.get("method", "GET").upper() in _WRITE and unprivs:
            base = privs[0]["name"] if privs else ""
            for other in unprivs:
                n += _add(bundle, ep, vclass="rbac", technique="authz-diff",
                          identity=other["name"], baseline_identity=base,
                          expected_status="403",
                          rationale=f"State-changing {ep.get('method')} invoked by role '{other['role']}'.")
    return n


def _gen_business_logic(bundle, endpoints) -> int:
    n = 0
    tampers = ["-1", "0", "999999999", "-99999"]
    for ep in endpoints:
        for p in ep.get("params", []):
            name = p["name"].lower()
            if any(m in name for m in _MONEY):
                for val in tampers:
                    n += _add(bundle, ep, vclass="business_logic", technique="value-tamper",
                              param=p["name"], location=p.get("location", "query"), payload=val,
                              expected_status="4xx",
                              rationale=f"Tamper business value '{p['name']}'={val}; invalid values must be rejected.")
            if name in _PRIV_FIELDS:
                n += _add(bundle, ep, vclass="business_logic", technique="priv-field",
                          param=p["name"], location=p.get("location", "body"),
                          payload=_PRIV_FIELDS[name], expected_status="403/ignored",
                          rationale=f"Set privilege field '{p['name']}'={_PRIV_FIELDS[name]} (mass-assignment / escalation).")
    return n


def _add(bundle, ep, *, vclass, technique, param="", location="", payload="",
         identity="", baseline_identity="", expected_status="", rationale="") -> int:
    ob.add_test_case(bundle, ob.test_case(
        ep["id"], param=param, location=location, vclass=vclass, technique=technique,
        payload=payload, origin="rule", identity=identity,
        baseline_identity=baseline_identity, expected_status=expected_status,
        rationale=rationale, expected_signal=expected_status))
    return 1

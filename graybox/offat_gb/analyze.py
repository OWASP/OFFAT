"""Stage 3 - AI analysis (the only token-spending stage).

Token discipline, by construction:

1. **Reachable-only.** Findings that no mapped endpoint can reach are triaged by
   the offline heuristic and never sent to a model. The structural graft graph
   (free) does the filtering, so AI spend tracks the real attack surface.
2. **Cached.** Each verdict is keyed on a content hash; a re-run reuses cached
   verdicts and pays only for new or changed findings.
3. **Batched + tiered.** Uncached reachable findings are screened in batches by a
   cheap model; only the ones the screen rates confirmed/likely are re-checked
   per-finding by a strong model. Tokens concentrate on the few findings that
   matter.

All AI paths degrade to the deterministic heuristic, so a run never breaks and
never requires a key.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

from offat_triage import heuristic_triage, make_triager
from offat_triage.triager import (
    ANTHROPIC_VERSION,
    AnthropicTriager,
    cvss_for,
)

from .cache import VerdictCache

# Cheap screening model and strong verification model. Overridable by env so the
# tiering can be tuned or flattened without code changes.
SCREEN_MODEL = os.environ.get("OFFAT_GB_SCREEN_MODEL", "claude-haiku-5")
VERIFY_MODEL = os.environ.get("OFFAT_GB_VERIFY_MODEL", "claude-sonnet-5")
BATCH_SIZE = int(os.environ.get("OFFAT_GB_BATCH_SIZE", "8") or "8")

_GB_SYSTEM = (
    "You are an expert application-security triager reviewing candidate findings "
    "in GRAY-BOX mode: you have the source AND the exposed HTTP endpoints that can "
    "reach each sink. Assume the detector may be wrong; try to REFUTE first.\n"
    "Weigh reachability: a sink reachable from an unauthenticated endpoint is more "
    "serious; an unreachable or dead-code sink is less so.\n"
    "For a BATCH, respond with ONLY a JSON array; element i is the verdict for "
    "candidate [i], each of the form:\n"
    '{"verdict":"confirmed|likely|inconclusive|false_positive","confidence":0.0-1.0,'
    '"cvss":0.0-10.0,"severity":"critical|high|medium|low|info","rationale":"1-2 sentences",'
    '"remediation":"one sentence"}'
)


def _finding_block(idx: int, f: Dict[str, Any]) -> str:
    parts = [f"[{idx}]"]
    for k in ("class", "title", "cwe", "owasp", "severity"):
        if f.get(k):
            parts.append(f"{k}={f[k]}")
    if f.get("file"):
        parts.append(f"location={f['file']}:{f.get('line', '')}")
    rf = f.get("reachable_from") or []
    parts.append("reachable_from=" + (", ".join(rf) if rf else "none"))
    parts.append(f"detector_confidence={f.get('confidence', 0)}")
    head = " ".join(parts)
    code = str(f.get("code", "") or "")[:800]
    return head + (f"\ncode:\n{code}" if code else "")


def _apply(f: Dict[str, Any], verdict: Dict[str, Any], source: str) -> Dict[str, Any]:
    verdict = dict(verdict)
    verdict["source"] = source
    verdict.setdefault("severity", f.get("severity", ""))
    if not verdict.get("cvss"):
        verdict["cvss"] = cvss_for(verdict.get("severity", ""))
    f["triage"] = verdict
    return verdict


def _anthropic_batch(triager: AnthropicTriager, batch: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
    """Score a batch of findings in a single API call. None on any failure."""
    prompt = "Score each candidate below.\n\n" + "\n\n".join(
        _finding_block(i, f) for i, f in enumerate(batch)
    )
    payload = {
        "model": triager.model,
        "max_tokens": 1800,
        "system": _GB_SYSTEM,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        triager.base_url + "/v1/messages",
        data=json.dumps(payload).encode(),
        headers={
            "content-type": "application/json",
            "x-api-key": triager.api_key or "",
            "anthropic-version": ANTHROPIC_VERSION,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=triager.timeout) as resp:
            body = resp.read().decode()
        data = json.loads(body)
        text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
        start, end = text.find("["), text.rfind("]")
        if start < 0 or end <= start:
            return None
        arr = json.loads(text[start:end + 1])
        if not isinstance(arr, list) or len(arr) != len(batch):
            return None
        return arr
    except Exception:  # noqa: BLE001 - degrade gracefully to per-finding/heuristic
        return None


def analyze(findings: List[Dict[str, Any]], out_dir: str, *, provider: Optional[str],
            use_ai: bool, cache_enabled: bool = True) -> str:
    """Triage findings in place with the token-disciplined gray-box strategy.

    Returns a short source label describing which path ran.
    """
    cache = VerdictCache(out_dir, enabled=cache_enabled)

    reachable = [f for f in findings if f.get("reachable")]
    unreachable = [f for f in findings if not f.get("reachable")]

    # Unreachable findings: offline heuristic, no tokens. Reachability failure
    # caps the verdict at "inconclusive" since the surface does not reach them.
    for f in unreachable:
        heuristic_triage(f)
        if f["triage"]["verdict"] in ("confirmed", "likely"):
            f["triage"]["verdict"] = "inconclusive"
        f["triage"]["rationale"] += " No mapped endpoint reaches this sink (gray-box)."
        f["triage"]["source"] = "heuristic:unreachable"

    # Reachable findings: cache first.
    to_ai: List[Dict[str, Any]] = []
    for f in reachable:
        cached = cache.get(f)
        if cached is not None:
            f["triage"] = dict(cached)
        else:
            to_ai.append(f)

    triager = make_triager(provider, use_ai) if to_ai else None
    label = "heuristic"

    if to_ai and triager is None:
        for f in to_ai:
            heuristic_triage(f)
            cache.put(f, f["triage"])
        label = "heuristic"
    elif to_ai and isinstance(triager, AnthropicTriager):
        label = _run_tiered_api(triager, to_ai, cache)
    elif to_ai:
        # CLI backend (claude-code / codex): per-finding over the reachable set.
        for f in to_ai:
            triager.triage(f)
            cache.put(f, f["triage"])
        label = triager.name

    cache.save()
    hits = cache.hits
    suffix = f" (cache hits: {hits})" if cache_enabled and hits else ""
    scope = f"reachable {len(reachable)}/{len(findings)}"
    return f"graybox:{label} [{scope}]{suffix}"


def _run_tiered_api(screen_triager: AnthropicTriager, to_ai: List[Dict[str, Any]],
                    cache: VerdictCache) -> str:
    """Cheap batched screen, then strong per-finding verify of the hot subset."""
    screen = AnthropicTriager(api_key=screen_triager.api_key, model=SCREEN_MODEL,
                              base_url=screen_triager.base_url)
    # Screen in batches with the cheap model.
    screened_ok = False
    for i in range(0, len(to_ai), BATCH_SIZE):
        batch = to_ai[i:i + BATCH_SIZE]
        verdicts = _anthropic_batch(screen, batch)
        if verdicts is None:
            for f in batch:  # batch failed: per-finding cheap model
                screen.triage(f)
        else:
            screened_ok = True
            for f, v in zip(batch, verdicts):
                _apply(f, v, f"screen:{SCREEN_MODEL}")

    # Verify only the findings the screen flagged as worth a strong look.
    hot = [f for f in to_ai if (f.get("triage") or {}).get("verdict") in ("confirmed", "likely")]
    verify = AnthropicTriager(api_key=screen_triager.api_key, model=VERIFY_MODEL,
                              base_url=screen_triager.base_url)
    for f in hot:
        verify.triage(f)  # strong model, full per-finding prompt + reachability in evidence

    for f in to_ai:
        cache.put(f, f.get("triage") or {})

    screened = f"screen:{SCREEN_MODEL}" if screened_ok else f"screen:{SCREEN_MODEL}(per-finding)"
    return f"{screened}+verify:{VERIFY_MODEL}({len(hot)})"

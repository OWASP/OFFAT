"""Token-disciplined triage: cache + batched screening + model tiering.

Shared by the white-box and gray-box pipelines. The strategy:

1. **Cache.** Verdicts are keyed on a content hash; a re-run pays only for new or
   changed findings.
2. **Batched screen.** Uncached findings are scored in batches by a cheap model
   in a single API call per batch (one shared system prompt).
3. **Tiered verify.** Only the findings the screen rates confirmed/likely are
   re-checked per-finding by a strong model.

Every path degrades to the deterministic heuristic, so a run never breaks and
never requires a key. Only the Anthropic API backend supports true batching; CLI
backends (claude-code / codex) fall back to per-finding calls.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from .cache import VerdictCache
from .triager import (
    ANTHROPIC_VERSION,
    AnthropicTriager,
    cvss_for,
    heuristic_triage,
    make_triager,
)

SCREEN_MODEL = os.environ.get("OFFAT_SCREEN_MODEL", "claude-haiku-5")
VERIFY_MODEL = os.environ.get("OFFAT_VERIFY_MODEL", "claude-sonnet-5")
BATCH_SIZE = int(os.environ.get("OFFAT_BATCH_SIZE", "8") or "8")

_BATCH_SYSTEM = (
    "You are an expert application-security triager verifying candidate findings.\n"
    "Assume the detector may be wrong; try to REFUTE each finding first, then decide.\n"
    "For a BATCH, respond with ONLY a JSON array; element i is the verdict for "
    "candidate [i], each of the form:\n"
    '{"verdict":"confirmed|likely|inconclusive|false_positive","confidence":0.0-1.0,'
    '"cvss":0.0-10.0,"severity":"critical|high|medium|low|info","rationale":"1-2 sentences",'
    '"remediation":"one sentence"}'
)


def default_block(idx: int, f: Dict[str, Any]) -> str:
    parts = [f"[{idx}]"]
    for k in ("class", "title", "cwe", "owasp", "severity"):
        if f.get(k):
            parts.append(f"{k}={f[k]}")
    if f.get("endpoint"):
        parts.append(f"endpoint={f['endpoint']}")
    if f.get("file"):
        parts.append(f"location={f['file']}:{f.get('line', '')}")
    parts.append(f"detector_confidence={f.get('confidence', 0)}")
    head = " ".join(parts)
    code = str(f.get("code", "") or "")[:800]
    return head + (f"\ncode:\n{code}" if code else "")


def _apply(f: Dict[str, Any], verdict: Dict[str, Any], source: str) -> None:
    verdict = dict(verdict)
    verdict["source"] = source
    verdict.setdefault("severity", f.get("severity", ""))
    if not verdict.get("cvss"):
        verdict["cvss"] = cvss_for(verdict.get("severity", ""))
    f["triage"] = verdict


def _anthropic_batch(triager: AnthropicTriager, batch: List[Dict[str, Any]],
                     system: str, block_fn: Callable[[int, Dict[str, Any]], str]
                     ) -> Optional[List[Dict[str, Any]]]:
    prompt = "Score each candidate below.\n\n" + "\n\n".join(
        block_fn(i, f) for i, f in enumerate(batch)
    )
    payload = {
        "model": triager.model,
        "max_tokens": 1800,
        "system": system,
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
    except Exception:  # noqa: BLE001 - degrade to per-finding/heuristic
        return None


def tiered_triage(findings: List[Dict[str, Any]], out_dir: str, *,
                  provider: Optional[str] = None, use_ai: bool = True,
                  cache_enabled: bool = True, cache_name: Optional[str] = None,
                  system: Optional[str] = None,
                  block_fn: Optional[Callable[[int, Dict[str, Any]], str]] = None,
                  screen_model: Optional[str] = None,
                  verify_model: Optional[str] = None,
                  batch_size: Optional[int] = None) -> str:
    """Triage findings in place with cache + batched screen + tiered verify.

    Returns a short source label. ``findings`` are all AI candidates - the caller
    does any pre-filtering (e.g. gray-box reachable-only).
    """
    system = system or _BATCH_SYSTEM
    block_fn = block_fn or default_block
    screen_model = screen_model or SCREEN_MODEL
    verify_model = verify_model or VERIFY_MODEL
    batch_size = batch_size or BATCH_SIZE

    cache_kwargs = {"name": cache_name} if cache_name else {}
    cache = VerdictCache(out_dir, enabled=cache_enabled, **cache_kwargs)

    to_ai: List[Dict[str, Any]] = []
    for f in findings:
        cached = cache.get(f)
        if cached is not None:
            f["triage"] = dict(cached)
        else:
            to_ai.append(f)

    if not to_ai:
        cache.save()
        return f"cached ({cache.hits})"

    triager = make_triager(provider, use_ai)
    if triager is None:
        for f in to_ai:
            heuristic_triage(f)
            cache.put(f, f["triage"])
        cache.save()
        return "heuristic"

    if isinstance(triager, AnthropicTriager):
        label = _run_tiered_api(triager, to_ai, cache, system, block_fn,
                                screen_model, verify_model, batch_size)
    else:
        for f in to_ai:  # CLI backend: per-finding
            triager.triage(f)
            cache.put(f, f["triage"])
        label = triager.name

    cache.save()
    suffix = f" (cache hits: {cache.hits})" if cache_enabled and cache.hits else ""
    return f"{label}{suffix}"


def _run_tiered_api(src: AnthropicTriager, to_ai: List[Dict[str, Any]],
                    cache: VerdictCache, system: str,
                    block_fn: Callable[[int, Dict[str, Any]], str],
                    screen_model: str, verify_model: str, batch_size: int) -> str:
    screen = AnthropicTriager(api_key=src.api_key, model=screen_model, base_url=src.base_url)
    screened_ok = False
    for i in range(0, len(to_ai), batch_size):
        batch = to_ai[i:i + batch_size]
        verdicts = _anthropic_batch(screen, batch, system, block_fn)
        if verdicts is None:
            for f in batch:
                screen.triage(f)
        else:
            screened_ok = True
            for f, v in zip(batch, verdicts):
                _apply(f, v, f"screen:{screen_model}")

    hot = [f for f in to_ai if (f.get("triage") or {}).get("verdict") in ("confirmed", "likely")]
    verify = AnthropicTriager(api_key=src.api_key, model=verify_model, base_url=src.base_url)
    for f in hot:
        verify.triage(f)

    for f in to_ai:
        cache.put(f, f.get("triage") or {})

    screened = f"screen:{screen_model}" if screened_ok else f"screen:{screen_model}(per-finding)"
    return f"{screened}+verify:{verify_model}({len(hot)})"

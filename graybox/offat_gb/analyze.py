"""Stage 3 - AI analysis (the only token-spending stage).

Gray-box adds one filter on top of the shared token-disciplined triager
(``offat_triage.tiered_triage``): findings that no mapped endpoint can reach are
triaged offline and never sent to a model. The reachable set is handed to the
shared batched + cached + model-tiered triager with a gray-box system prompt and
a finding block that surfaces reachability, so the model judges by what the
exposed surface can actually reach.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from offat_triage import reachable_triage

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

_CACHE_NAME = ".offat-gb-cache.json"


def _gb_block(idx: int, f: Dict[str, Any]) -> str:
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
    path = (f.get("evidence") or {}).get("path") or []
    if path:   # proven on the code graph: the hops are better evidence than a snippet
        return head + "\npath:\n" + "\n".join(
            f"  {h.get('file')}:{h.get('line')} [{h.get('kind')}] {str(h.get('code', ''))[:160]}"
            for h in path[:20])
    code = str(f.get("code", "") or "")[:800]
    return head + (f"\ncode:\n{code}" if code else "")


def analyze(findings: List[Dict[str, Any]], out_dir: str, *, provider: Optional[str],
            use_ai: bool, cache_enabled: bool = True) -> str:
    """Triage findings in place with the shared reachable-only strategy, using the
    gray-box system prompt and reachability-aware finding block."""
    label = reachable_triage(
        findings, out_dir, provider=provider, use_ai=use_ai,
        cache_enabled=cache_enabled, cache_name=_CACHE_NAME,
        system=_GB_SYSTEM, block_fn=_gb_block,
        note="No mapped endpoint reaches this sink (gray-box).",
    )
    return f"graybox:{label}"

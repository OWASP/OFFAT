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

from offat_triage import heuristic_triage, tiered_triage

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
    code = str(f.get("code", "") or "")[:800]
    return head + (f"\ncode:\n{code}" if code else "")


def analyze(findings: List[Dict[str, Any]], out_dir: str, *, provider: Optional[str],
            use_ai: bool, cache_enabled: bool = True) -> str:
    """Triage findings in place with the gray-box reachable-only strategy."""
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

    label = tiered_triage(
        reachable, out_dir, provider=provider, use_ai=use_ai,
        cache_enabled=cache_enabled, cache_name=_CACHE_NAME,
        system=_GB_SYSTEM, block_fn=_gb_block,
    )
    scope = f"reachable {len(reachable)}/{len(findings)}"
    return f"graybox:{label} [{scope}]"

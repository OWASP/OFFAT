"""Triage logic shared by the DAST and white-box pipelines.

A *finding* is a plain dict. The triager reads a handful of keys
(``class``, ``severity``, ``confidence``, ``title``, ``evidence`` ...) and writes
a ``triage`` sub-dict with ``verdict``, ``confidence``, ``cvss``, ``severity``,
``rationale``, ``remediation`` and ``source``.
"""

from __future__ import annotations

import concurrent.futures
import json
import os
import urllib.request
import urllib.error
from typing import Any, Dict, Iterable, List, Optional

DEFAULT_MODEL = "claude-sonnet-5"
ANTHROPIC_VERSION = "2023-06-01"

REMEDIATION: Dict[str, str] = {
    "sqli": "Use parameterized queries / prepared statements; never concatenate untrusted input into SQL. Apply least-privilege DB accounts.",
    "nosqli": "Validate and type-check inputs; reject query operators in user data; use an ODM with strict schemas.",
    "command_injection": "Avoid shell invocation; use exec APIs with argument arrays and an allowlist; never pass untrusted input to a shell.",
    "ssti": "Do not render user input as templates; use logic-less templates and context-aware escaping; sandbox the engine.",
    "ldap_injection": "Escape LDAP special characters and use parameterized directory queries.",
    "xss": "Context-aware output encoding, a strict Content-Security-Policy, and input validation.",
    "path_traversal": "Canonicalize paths and enforce an allowlisted base directory; reject '..' and absolute paths.",
    "ssrf": "Allowlist outbound hosts, resolve and validate targets, block link-local/metadata ranges, disable unused URL schemes.",
    "open_redirect": "Use an allowlist of redirect targets or relative paths only; never redirect to raw user input.",
    "xxe": "Disable external entity resolution and DTD processing in the XML parser.",
    "access_control": "Enforce object-level authorization on every request server-side; scope queries to the authenticated principal.",
    "mass_assignment": "Bind only explicitly-allowed properties (allowlist DTOs); never bind request bodies directly to models.",
    "broken_auth": "Enforce authentication server-side on every protected route; verify JWT signatures with a fixed algorithm allowlist.",
    "security_misconfig": "Restrict HTTP methods, configure CORS with a strict origin allowlist, and enforce rate limiting.",
    "data_exposure": "Return only the fields a client needs (response DTOs); never serialize secrets or credentials.",
    "deserialization": "Never deserialize untrusted data into arbitrary types; use safe formats and allowlisted classes.",
    "secrets": "Rotate the exposed secret immediately; move secrets to a vault/secret manager; scan history and CI.",
    "crypto": "Use vetted algorithms and libraries; avoid ECB/static IVs/weak hashes; enforce TLS.",
    "injection": "Validate/encode untrusted input at the boundary appropriate to the sink.",
}

_CVSS = {"critical": 9.3, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}


def cvss_for(severity: str) -> float:
    return _CVSS.get((severity or "").lower(), 0.0)


def remediation_for(vuln_class: str) -> str:
    return REMEDIATION.get(
        (vuln_class or "").lower(),
        "Validate and sanitize all untrusted input; enforce authorization and least privilege.",
    )


def _verdict_from_confidence(c: float) -> str:
    if c >= 0.8:
        return "confirmed"
    if c >= 0.6:
        return "likely"
    if c >= 0.4:
        return "inconclusive"
    return "false_positive"


def heuristic_triage(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Deterministic offline verdict for a finding."""
    conf = float(finding.get("confidence", 0.5))
    verdict = _verdict_from_confidence(conf)
    cls = finding.get("class", "")
    if cls in ("access_control", "mass_assignment") and verdict == "confirmed":
        # Ownership-dependent classes cannot be blindly confirmed offline.
        verdict = "likely"
    sev = finding.get("severity", "")
    triage = {
        "verdict": verdict,
        "confidence": conf,
        "cvss": cvss_for(sev),
        "severity": sev,
        "rationale": _rationale(finding),
        "remediation": remediation_for(cls),
        "source": "heuristic",
    }
    finding["triage"] = triage
    return triage


def _rationale(finding: Dict[str, Any]) -> str:
    ev = finding.get("evidence", {}) or {}
    parts = []
    tech = finding.get("technique") or "analysis"
    loc = finding.get("location") or finding.get("file") or ""
    parts.append(f"Detected via {tech}" + (f" at {loc}" if loc else "") + ".")
    if ev.get("matched_signature"):
        parts.append(f"Matched signal: {ev['matched_signature']}.")
    if ev.get("notes"):
        parts.append(ev["notes"])
    return " ".join(parts).strip()


_SYSTEM = (
    "You are an expert application-security triager verifying candidate vulnerabilities.\n"
    "Assume the detector may be wrong. Try to REFUTE the finding first, then decide.\n"
    "Weigh the vulnerability class, the evidence, and whether it genuinely proves exploitability.\n"
    "Respond with ONLY a compact JSON object of the form:\n"
    '{"verdict":"confirmed|likely|inconclusive|false_positive","confidence":0.0-1.0,'
    '"cvss":0.0-10.0,"severity":"critical|high|medium|low|info","rationale":"1-2 sentences",'
    '"remediation":"one sentence"}'
)


class AnthropicTriager:
    """AI triager backed by the Anthropic Messages API (stdlib HTTP)."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: int = 60,
    ) -> None:
        self.api_key = api_key or os.environ.get("OFFAT_AI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model or os.environ.get("OFFAT_AI_MODEL") or DEFAULT_MODEL
        self.base_url = (base_url or os.environ.get("OFFAT_AI_BASE_URL")
                         or os.environ.get("ANTHROPIC_BASE_URL") or "https://api.anthropic.com").rstrip("/")
        self.timeout = timeout

    @property
    def name(self) -> str:
        return f"ai:{self.model}"

    @classmethod
    def from_env(cls) -> "Optional[AnthropicTriager]":
        t = cls()
        return t if t.api_key else None

    def triage(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        try:
            verdict = self._call(finding)
        except Exception as exc:  # noqa: BLE001 - always degrade gracefully
            heuristic_triage(finding)
            finding["triage"]["rationale"] += f" (AI triage unavailable: {str(exc)[:160]})"
            return finding["triage"]
        verdict["source"] = "ai"
        verdict.setdefault("severity", finding.get("severity", ""))
        if not verdict.get("cvss"):
            verdict["cvss"] = cvss_for(verdict.get("severity", ""))
        finding["triage"] = verdict
        return verdict

    def _call(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "max_tokens": 700,
            "system": _SYSTEM,
            "messages": [{"role": "user", "content": _build_prompt(finding)}],
        }
        req = urllib.request.Request(
            self.base_url + "/v1/messages",
            data=json.dumps(payload).encode(),
            headers={
                "content-type": "application/json",
                "x-api-key": self.api_key or "",
                "anthropic-version": ANTHROPIC_VERSION,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read().decode()
        data = json.loads(body)
        text = "".join(c.get("text", "") for c in data.get("content", []) if c.get("type") == "text")
        verdict = _parse_json_object(text)
        if not verdict or "verdict" not in verdict:
            raise ValueError("could not parse triage JSON")
        return verdict


def _build_prompt(f: Dict[str, Any]) -> str:
    ev = f.get("evidence", {}) or {}
    lines = ["Candidate finding:"]
    for k in ("class", "title", "cwe", "owasp"):
        if f.get(k):
            lines.append(f"- {k}: {f[k]}")
    if f.get("endpoint"):
        lines.append(f"- endpoint: {f['endpoint']}")
    if f.get("file"):
        lines.append(f"- location: {f['file']}:{f.get('line', '')}")
    if f.get("param"):
        lines.append(f"- parameter: {f['param']} (in {f.get('location', '')})")
    if f.get("technique"):
        lines.append(f"- technique: {f['technique']}")
    if f.get("payload"):
        lines.append(f"- payload: {str(f['payload'])[:300]}")
    lines.append(f"- detector confidence: {f.get('confidence', 0)}")
    if ev:
        lines.append("Evidence:")
        for k, v in ev.items():
            if v not in (None, "", 0):
                lines.append(f"- {k}: {str(v)[:800]}")
    if f.get("code"):
        lines.append(f"Code:\n{str(f['code'])[:1200]}")
    return "\n".join(lines)


def _parse_json_object(text: str) -> Optional[Dict[str, Any]]:
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except json.JSONDecodeError:
        return None


def make_triager(provider: Optional[str] = None, use_ai: bool = True):
    """Select a triager. ``None`` means use the heuristic.

    Providers: ``anthropic`` (API key), ``claude-code`` (the ``claude`` CLI),
    ``codex`` (the ``codex`` CLI), ``heuristic``, or ``auto`` (default) which
    prefers an API key, then Claude Code, then Codex, then the heuristic.
    """
    if not use_ai:
        return None
    provider = (provider or os.environ.get("OFFAT_AI_PROVIDER") or "auto").strip().lower()
    # Imported lazily to avoid an import cycle (cli_providers imports this module).
    from .cli_providers import ClaudeCodeTriager, CodexTriager, cli_available

    if provider in ("auto", ""):
        ai = AnthropicTriager.from_env()
        if ai is not None:
            return ai
        if cli_available("claude"):
            return ClaudeCodeTriager()
        if cli_available("codex"):
            return CodexTriager()
        return None
    if provider in ("anthropic", "api", "anthropic-api"):
        return AnthropicTriager.from_env()
    if provider in ("claude", "claude-code", "claudecode"):
        return ClaudeCodeTriager()
    if provider in ("codex", "openai-codex"):
        return CodexTriager()
    # "heuristic" / "none" / "off" / unknown -> heuristic
    return None


def triage_findings(
    findings: Iterable[Dict[str, Any]],
    use_ai: bool = True,
    concurrency: int = 4,
    provider: Optional[str] = None,
) -> str:
    """Triage a collection of findings in place. Returns the triage source label."""
    findings = list(findings)
    if not findings:
        return "none"
    triager = make_triager(provider, use_ai)
    if triager is None:
        for f in findings:
            heuristic_triage(f)
        return "heuristic"
    # CLI-backed triagers spawn a process per finding; keep concurrency modest.
    workers = min(concurrency, 2) if getattr(triager, "is_cli", False) else concurrency
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        list(pool.map(triager.triage, findings))
    return triager.name

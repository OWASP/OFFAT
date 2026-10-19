"""CLI-backed AI triagers.

Instead of a raw Anthropic API key, the triager can drive a locally-installed
agent CLI that is already authenticated:

* **Claude Code** — ``claude -p "<prompt>"`` (headless / print mode)
* **OpenAI Codex** — ``codex exec "<prompt>"``

Both are invoked non-interactively; their stdout is parsed for the compact JSON
verdict the triage prompt asks for. Any failure falls back to the deterministic
heuristic, exactly like the API triager, so a run never breaks on a missing or
misbehaving CLI.

The base command is overridable via ``OFFAT_AI_CLAUDE_CMD`` /
``OFFAT_AI_CODEX_CMD`` (whitespace-split; the prompt is appended as the final
argument), and an optional per-provider model via ``OFFAT_AI_CLAUDE_MODEL`` /
``OFFAT_AI_CODEX_MODEL``.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .triager import _SYSTEM, _build_prompt, _parse_json_object, cvss_for, heuristic_triage


def cli_available(name: str) -> bool:
    return shutil.which(name) is not None


class CLITriager:
    """Runs an agent CLI and parses a JSON verdict from its stdout."""

    is_cli = True

    def __init__(self, label: str, base_cmd: List[str], timeout: int = 180) -> None:
        self._label = label
        self.base_cmd = base_cmd
        self.timeout = timeout

    @property
    def name(self) -> str:
        return self._label

    def available(self) -> bool:
        return bool(self.base_cmd) and cli_available(self.base_cmd[0])

    def triage(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        prompt = _SYSTEM + "\n\n" + _build_prompt(finding)
        try:
            out = self._run(prompt)
            verdict = _parse_json_object(out)
            if not verdict or "verdict" not in verdict:
                raise ValueError("no JSON verdict in CLI output")
        except Exception as exc:  # noqa: BLE001 - always degrade gracefully
            heuristic_triage(finding)
            finding["triage"]["rationale"] += f" (AI CLI '{self._label}' unavailable: {str(exc)[:160]})"
            return finding["triage"]
        verdict["source"] = self._label
        verdict.setdefault("severity", finding.get("severity", ""))
        if not verdict.get("cvss"):
            verdict["cvss"] = cvss_for(verdict.get("severity", ""))
        finding["triage"] = verdict
        return verdict

    def _run(self, prompt: str) -> str:
        proc = subprocess.run(
            self.base_cmd + [prompt],
            capture_output=True, text=True, timeout=self.timeout, check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or "cli exited non-zero").strip()[:200])
        return proc.stdout or ""


def _base_cmd(env_key: str, default: List[str], model_env: str, model_flag: str) -> List[str]:
    override = os.environ.get(env_key)
    cmd = shlex.split(override) if override else list(default)
    model = os.environ.get(model_env) or ""
    if model and model_flag:
        cmd += [model_flag, model]
    return cmd


class ClaudeCodeTriager(CLITriager):
    """Triage via the Claude Code CLI (`claude -p`)."""

    def __init__(self, timeout: int = 180) -> None:
        cmd = _base_cmd("OFFAT_AI_CLAUDE_CMD", ["claude", "-p"], "OFFAT_AI_CLAUDE_MODEL", "--model")
        super().__init__(label="claude-code", base_cmd=cmd, timeout=timeout)


class CodexTriager(CLITriager):
    """Triage via the OpenAI Codex CLI (`codex exec`)."""

    def __init__(self, timeout: int = 180) -> None:
        cmd = _base_cmd("OFFAT_AI_CODEX_CMD", ["codex", "exec"], "OFFAT_AI_CODEX_MODEL", "-m")
        super().__init__(label="codex", base_cmd=cmd, timeout=timeout)

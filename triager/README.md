# offat-triage

The shared triager used by both halves of OFFAT-AI. It validates candidate
security findings and enriches each with a **verdict**, **CVSS**, and
**remediation**.

- **Heuristic triager** — deterministic, offline, no dependencies.
- **AI triager** — adversarially verifies each finding (tries to refute it
  first), backed by one of three interchangeable backends. Falls back to the
  heuristic on any error.

Pure standard library — no third-party packages.

## Backends

| Provider | How | Needs |
|---|---|---|
| `anthropic` | Anthropic Messages API | `OFFAT_AI_API_KEY` / `ANTHROPIC_API_KEY` |
| `claude-code` | `claude -p "<prompt>"` (Claude Code CLI) | the `claude` CLI, signed in |
| `codex` | `codex exec "<prompt>"` (OpenAI Codex CLI) | the `codex` CLI, signed in |
| `heuristic` | deterministic, offline | nothing |

Select with `--provider` (CLI), the `provider=` argument (library), or
`OFFAT_AI_PROVIDER`. `auto` (default) prefers an API key, then Claude Code, then
Codex, then the heuristic.

Overrides: `OFFAT_AI_MODEL` (API); `OFFAT_AI_CLAUDE_MODEL` /
`OFFAT_AI_CODEX_MODEL` (CLI model ids); `OFFAT_AI_CLAUDE_CMD` /
`OFFAT_AI_CODEX_CMD` (replace the CLI invocation, whitespace-split; the prompt is
appended as the final argument).

## Use as a CLI

```bash
# Re-triage a DAST report (or any JSON/JSONL findings file)
python -m offat_triage offat-report/report.json -o triaged.json

# Heuristic only (no network)
python -m offat_triage findings.jsonl --no-ai

# Force a specific backend
python -m offat_triage report.json --provider claude-code
python -m offat_triage report.json --provider codex
```

Enable the Anthropic-API backend by exporting a key:

```bash
export OFFAT_AI_API_KEY=sk-ant-...
export OFFAT_AI_MODEL=claude-sonnet-5   # optional; override to track latest
python -m offat_triage report.json
```

Or use a local agent CLI with no API key (`claude` / `codex` already signed in):

```bash
python -m offat_triage report.json --provider claude-code
```

## Use as a library

```python
from offat_triage import triage_findings, heuristic_triage

# provider: None/"auto" (default), "anthropic", "claude-code", "codex", "heuristic"
source = triage_findings(findings, use_ai=True, provider="claude-code")  # mutates in place
```

A *finding* is a dict; the triager writes a `triage` sub-dict:
`{verdict, confidence, cvss, severity, rationale, remediation, source}`.

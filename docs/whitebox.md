# White-box SAST (`offat-whitebox`)

A static source-code security review pipeline modeled on the
[security-harness](https://github.com/dmdhrumilmistry/security-harness)
workflow: **recon → hunt → trace → chain → verify → report**.

## Run

```bash
# From the repo (no install)
PYTHONPATH=whitebox:triager python3 -m offat_wb /path/to/repo -o offat-report/whitebox

# Installed
pip install ./triager ./whitebox
offat-whitebox /path/to/repo
```

| Flag | Default | Description |
|---|---|---|
| `target` | `.` | Path to the codebase |
| `--classes` | all | Comma-separated classes to hunt |
| `--out, -o` | `offat-report/whitebox` | Output directory |
| `--no-ai` | false | Heuristic triage only |
| `--provider` | auto | Triage backend: `auto`, `anthropic`, `claude-code`, `codex`, `heuristic` |
| `--no-semgrep` | false | Skip semgrep even if installed |
| `--no-graft` | false | Skip graft source-to-sink tracing |
| `--no-cache` | false | Do not read/write the AI-verdict cache |
| `--fail-on` | — | Exit non-zero if an actionable finding is at/above this severity (CI gate) |

AI triage runs against an Anthropic API key (`OFFAT_AI_API_KEY`) **or** a local
agent CLI — Claude Code (`claude`) or OpenAI Codex (`codex`) — selected with
`--provider` / `OFFAT_AI_PROVIDER`. See the shared triager
([`../triager`](../triager)) for the full backend list and env vars.

### Token discipline

The verify stage uses the shared token-disciplined triager: verdicts are
**cached** by a content hash (re-runs pay only for new or changed findings), and
with the Anthropic API backend uncached findings are **screened in batches by a
cheap model** then only the confirmed/likely subset is **verified by a strong
model**. Tune with `OFFAT_SCREEN_MODEL`, `OFFAT_VERIFY_MODEL`, `OFFAT_BATCH_SIZE`,
or disable with `--no-cache`.

## Stages

### recon
Detects languages by file mix, inventories dependency manifests, and — when the
tools are installed — generates an SBOM with **syft** and CVE findings with
**grype** (falling back to **trivy**, then **osv-scanner**).

### hunt
Two complementary hunters:

- **Built-in pattern hunter** (always on, no dependencies): high-signal
  multi-language rules for hardcoded secrets (AWS/Slack/GitHub/private keys),
  dangerous sinks (`eval`/`exec`, `os.system`, `shell=True`, SQL string
  building), unsafe deserialization (`pickle`, unsafe `yaml.load`,
  `ObjectInputStream`), weak crypto (MD5/SHA1), disabled TLS verification, DOM
  XSS sinks, SSRF sinks and misconfiguration.
- **semgrep** `--config auto` when installed; results are mapped into the shared
  schema with a class inferred from the rule metadata.

### trace
When **graft** is installed, each sink's enclosing symbol is checked against the
structural call graph: a sink reachable from an entry point (route handler,
controller, `main`, CLI, message consumer) gets a confidence bump and a
data-flow note. Without graft this stage is a no-op (recorded in the report).

### chain
Annotates co-located findings (same file, multiple classes) into simple attack
paths — e.g. a hardcoded secret next to an outbound request.

### verify
The shared triager adversarially validates each finding (refute first) and
assigns verdict / CVSS / remediation, with caching and model tiering (see Token
discipline). Offline heuristic when no key is set.

### report
`report.json`, `findings.jsonl`, `results.sarif`, `report.md`, `report.html`,
`report.junit.xml`. Use `--fail-on <severity>` to gate CI on actionable findings.

## Deepening results

The pipeline runs with **no external tools**, but installing them materially
improves coverage:

```bash
pip install semgrep
# syft / grype: https://github.com/anchore
```

For a deeper, agentic, multi-pass review that chains findings into full attack
scenarios, use the upstream **security-harness** Claude Code plugin; this
pipeline is its CI-runnable, automation-friendly counterpart, and both emit the
same finding/report schema.

## Relationship to `graft`

`graft` (`npx @nanonets/graft`) provides structural code mapping used by
security-harness. It requires network access and (for LLM analysis) an API key,
so OFFAT-AI treats it as an optional recon enhancer rather than a hard
dependency; the built-in recon covers language/manifest mapping without it.

---
title: White-box design
section: Deep dives
nav_order: 3
description: The offat-whitebox pipeline - recon, code graph, patterns, chain, verify, report.
---

# White-box design (`offat-whitebox`)

A static source-code security review pipeline modeled on the
[security-harness](https://github.com/dmdhrumilmistry/security-harness)
workflow: **recon → code graph + patterns → chain → verify → report**.

## Run

```bash
# From the repo (no install)
PYTHONPATH=whitebox:triager python3 -m offat_wb /path/to/repo -o offat-report/whitebox

# Installed (the [graph] extra enables the code-graph engine)
pip install ./triager './whitebox[graph]'
offat-whitebox /path/to/repo
```

| Flag | Default | Description |
|---|---|---|
| `target` | `.` | Path to the codebase |
| `--classes` | all | Comma-separated classes to hunt |
| `--out, -o` | `offat-report/whitebox` | Output directory |
| `--no-ai` | false | Heuristic triage only |
| `--provider` | auto | Triage backend: `auto`, `anthropic`, `claude-code`, `codex`, `heuristic` |
| `--no-graph` | false | Skip the code-graph taint engine |
| `--specs` | — | Extra source / sink / sanitizer specs (JSON) |
| `--local-sources` | false | Also treat argv / env / stdin as sources (CLI tools, scripts) |
| `--graph-out` | false | Export the code graph as JSON + GraphML |
| `--agent N` | 0 | Re-verify the top N graph findings with the graph-tool AI agent |
| `--infer-specs` | false | Write the taint frontier; with a provider, let AI label missing sinks / sanitizers |
| `--semgrep` | false | Also run `semgrep --config auto` (opt-in) |
| `--no-graft` | false | Skip graft tracing (only used with `--no-graph`) |
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

### code graph
The primary engine ([overview](code-graph.md)). It builds a code property graph
of the repository (Python via `ast`, JavaScript / TypeScript via tree-sitter),
marks attacker-controlled sources and dangerous sinks, and proves source → sink
paths with an interprocedural, call/return-matched search. Every finding
carries its hop-by-hop path, entry points and HTTP route.

### patterns
A dependency-free, multi-language hunter for classes that are not data flows:
hardcoded secrets (AWS / Slack / GitHub / private keys), weak crypto (MD5 /
SHA1), disabled TLS verification and misconfiguration. Pattern hits in
injection classes are fused with the graph: a hit on a proven line is dropped as
a duplicate, a hit with no source reaching it is kept but demoted, and every hit
gains graph reachability. `semgrep --config auto` can be added with `--semgrep`.

### chain
Annotates co-located findings (same file, multiple classes) into simple attack
paths — e.g. a hardcoded secret next to an outbound request.

### verify
The shared triager adversarially validates each finding (refute first) and
assigns verdict / CVSS / remediation, with caching and model tiering (see Token
discipline). It receives the proven path rather than a snippet. With
`--agent N`, a graph-tool agent re-verifies the top findings by reading callers,
callees, function bodies and backward slices. Offline heuristic when no key is
set.

### report
`report.json`, `findings.jsonl`, `results.sarif` (with `codeFlows`), `report.md`,
`report.html`, `report.junit.xml`. Use `--fail-on <severity>` to gate CI on actionable findings.

Every finding is mapped to a threat taxonomy - **OWASP API Security Top 10
(2023)**, **OWASP Top 10 (2021)** and a primary **CWE** (each with names) - in a
`threat` block, and the report includes a Threat mapping summary counting
findings per OWASP API Top 10 category.

## Deepening results

The pipeline runs with no external tools. The `[graph]` extra enables the code
graph; `syft` and `grype` (or `trivy` / `osv-scanner`) add an SBOM and dependency
CVEs; `--specs` and `--infer-specs` extend the source / sink catalog for
in-house wrappers.

For a deeper, agentic, multi-pass review, the upstream **security-harness**
Claude Code plugin emits the same finding and report schema.

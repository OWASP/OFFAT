# OFFAT-AI

**AI-augmented pentesting automation — white-box *and* black-box.**

OFFAT-AI migrates and extends [OWASP OFFAT](https://github.com/OWASP/offat)
(the OFFensive Api Tester) into a two-mode security automation platform:

- 🕳️ **Black-box (DAST)** — a fast **Go engine** that ingests an OpenAPI/Swagger
  spec, **maps every parameter into a dataflow graph**, links parameters across
  endpoints, **generates attack vectors dynamically** from a knowledge base
  (OWASP API Top 10 + bug-bounty patterns), executes them against a live target,
  and **verifies** the results.
- 🔍 **White-box (SAST)** — a **Python pipeline** modeled on the
  [security-harness](https://github.com/dmdhrumilmistry/security-harness)
  workflow (recon → hunt → **trace** → chain → verify → report), integrating
  `graft` (source-to-sink tracing), `semgrep`, `syft`/`grype` when present with a
  dependency-free fallback hunter. Token-disciplined triage (cached, batched,
  model-tiered), JUnit output and a `--fail-on` CI gate.
- 🩶 **Gray-box** — a **Python pipeline** that maps the HTTP endpoint attack
  surface from source with **graft**, fuses it with the SAST hunters, and lets AI
  judge each finding by **reachability** (which exposed endpoint reaches the
  sink). No live traffic. Token-disciplined: AI runs only on reachable findings,
  **batched, cached, and model-tiered**.
- 🤖 **AI triager** — shared across both modes. Adversarially validates each
  finding, prunes false positives, and assigns verdict / CVSS / remediation,
  producing security-harness-style reports (JSON, JSONL, SARIF, Markdown, HTML).
  Backed by an **Anthropic API key**, or a local agent CLI — **Claude Code
  (`claude`)** or **OpenAI Codex (`codex`)** — with a deterministic heuristic
  fallback, so it runs with no key at all.

> ⚠️ **Authorized use only.** The DAST engine sends real attack traffic and the
> SAST pipeline is for code you own. Only test systems and code you own or are
> explicitly authorized to assess.

---

## Architecture

```
                         ┌─────────────────────────────────────────────┐
   OpenAPI / Swagger ───▶│  BLACK-BOX (dast/, Go)                       │
                         │  spec → graph → kb → attack → engine →       │
                         │  detect → triage → report                    │──┐
                         └─────────────────────────────────────────────┘  │
                                                                           ├─▶ report.{json,jsonl,sarif,md,html}
                         ┌─────────────────────────────────────────────┐  │
   Source code       ───▶│  WHITE-BOX (whitebox/, Python)               │  │
                         │  recon → hunt → chain → verify → report      │──┘
                         └─────────────────────────────────────────────┘
                                          │
                         ┌────────────────▼───────────────┐
                         │  Shared AI triager (triager/)   │  Anthropic + heuristic fallback
                         └─────────────────────────────────┘
```

See [`docs/architecture.md`](docs/architecture.md) for the full design.

## Repository layout

| Path | What |
|---|---|
| `dast/` | Go DAST engine (`offat-dast`) — spec, graph, kb, attack, engine, detect, triage, report |
| `whitebox/` | Python SAST pipeline (`offat-whitebox`) |
| `graybox/` | Python gray-box pipeline (`offat-graybox`) — graft endpoint mapping + reachability + AI |
| `triager/` | Shared AI/heuristic triager (`offat-triage`) |
| `knowledge-base/` | Extended attack-vector library + bug-bounty patterns (`--kb`) |
| `skills/`, `commands/`, `agents/`, `.claude-plugin/` | Claude Code plugin |
| `examples/` | Sample OpenAPI spec + vulnerable code fixture |
| `docker/`, `Makefile`, `.github/` | Packaging & CI |

## Quick start

### Black-box (DAST)

```bash
make dast                          # builds bin/offat-dast (Go 1.24+)

# Preview coverage offline — parses the spec, prints the dataflow graph & plan
./bin/offat-dast --spec examples/vulnshop-openapi.yaml --kb knowledge-base --graph --dry-run

# Scan an authorized target
export OFFAT_AI_API_KEY=sk-ant-...          # optional: enables AI triage
./bin/offat-dast \
  --spec examples/vulnshop-openapi.yaml \
  --url https://api.your-authorized-target.example \
  --kb knowledge-base \
  --auth-value "Bearer $TOKEN" \
  --rate 25 --out offat-report --yes
```

### White-box (SAST)

```bash
# no install needed — run from the repo root
PYTHONPATH=whitebox:triager python3 -m offat_wb /path/to/your/repo -o offat-report/whitebox

# or install the CLIs
pip install ./triager ./whitebox
offat-whitebox /path/to/your/repo
```

### Gray-box (source + endpoint surface, AI reachability)

```bash
pip install ./triager ./whitebox ./graybox
offat-graybox /path/to/your/repo                  # AI when a provider is available
offat-graybox ./repo --no-ai                       # offline heuristic only
offat-graybox ./repo --fail-on high                # CI gate on reachable high+ findings
```

Maps endpoints with graft, links them to vulnerable sinks via the call graph,
and spends AI tokens only on reachable findings (batched, cached, model-tiered).
See [`docs/graybox.md`](docs/graybox.md).

### Re-triage existing results

```bash
pip install ./triager
offat-triage offat-report/report.json          # add/refresh AI verdicts
```

### As a Claude Code plugin

```
/plugin marketplace add dmdhrumilmistry/offat-ai
/plugin install offat-ai
/offat-scan test https://api.example.com with examples/vulnshop-openapi.yaml
```

Skills: `offat-dast`, `offat-whitebox`, `offat-triage`; agent: `offat-verifier`.

## AI triage backends

The triager picks a backend automatically, or you can force one with
`--ai-provider` (DAST) / `--provider` (white-box, triage) or `OFFAT_AI_PROVIDER`:

| Provider | How | Needs |
|---|---|---|
| `anthropic` | Anthropic Messages API | `OFFAT_AI_API_KEY` (or `ANTHROPIC_API_KEY`) |
| `claude-code` | `claude -p` (Claude Code CLI) | the `claude` CLI, already signed in |
| `codex` | `codex exec` (OpenAI Codex CLI) | the `codex` CLI, already signed in |
| `heuristic` | deterministic, offline | nothing |

`auto` (default) prefers an API key, then Claude Code, then Codex, then the
heuristic. Examples:

```bash
# Use Claude Code — no API key needed, uses your local claude login
./bin/offat-dast -f api.yaml --url "$T" --ai-provider claude-code --yes
python -m offat_wb ./repo --provider codex          # use Codex
offat-triage report.json --provider claude-code     # re-triage via Claude Code
```

Model/command overrides: `OFFAT_AI_MODEL` (API), `OFFAT_AI_CLAUDE_MODEL` /
`OFFAT_AI_CODEX_MODEL` (CLI models), `OFFAT_AI_CLAUDE_CMD` / `OFFAT_AI_CODEX_CMD`
(replace the CLI invocation entirely).

## What it tests

**Black-box (from the spec):** BOLA/IDOR, BFLA, mass assignment (BOPLA), broken
auth (missing auth, JWT `alg=none`/`kid`), SQLi (error/boolean/time/UNION),
NoSQLi, command injection, SSTI, LDAP injection, reflected XSS, path traversal,
SSRF (incl. cloud metadata), open redirect, XXE, CRLF, CORS misconfig, HTTP
method tampering, missing rate limiting, excessive data exposure, and
business-logic tampering (price/quantity).

**White-box (from source):** hardcoded secrets, injection sinks, unsafe
deserialization, weak crypto/TLS-off, DOM XSS sinks, SSRF sinks, misconfig, and
vulnerable dependencies (SCA), plus anything semgrep's `--config auto` finds.

## How dynamic generation works

1. **Parse** the spec into a version-agnostic model (Swagger 2.0 + OpenAPI 3.x).
2. **Graph** the API: producers (a response `id`) are linked to consumers
   (`GET /users/{id}`) by name/resource heuristics, so the engine seeds *real*
   identifiers at runtime — reaching business logic and enabling BOLA.
3. **Match** every parameter against knowledge-base vectors by location, type,
   name pattern and method; only applicable vectors are instantiated.
4. **Execute** concurrently under a rate limit, with a per-endpoint baseline for
   differential detection.
5. **Detect** using per-vector rules (error signatures, reflection, timing,
   boolean/diff, status), suppressing signals already present in the baseline.
6. **Triage** each candidate with the AI triager (or heuristic), then report in
   JSON, JSONL, SARIF, Markdown, HTML and JUnit XML. Pass `--fail-on <severity>`
   to exit non-zero when a finding at/above that level survives triage - a drop-in
   CI gate.

Add a new attack technique by dropping a YAML file in `knowledge-base/` — no
code changes. See [`knowledge-base/README.md`](knowledge-base/README.md).

## Threat mapping

Every finding is classified against a shared threat taxonomy — the **OWASP API
Security Top 10 (2023)**, the **OWASP Top 10 (2021)** web categories, and a
primary **CWE** (each with names). The knowledge-base vectors carry the OWASP API
Top 10 + CWE directly; the white-box and gray-box pipelines attach a `threat`
block to each finding (via `offat_triage.taxonomy`) and render a Threat mapping
summary - findings per OWASP API Top 10 category - in every report.

## Development

```bash
make help          # list targets
make test          # go test ./...
make vet fmt       # go vet + gofmt
make smoke         # offline end-to-end check
make docker        # build the combined image
```

## Credits & lineage

- **[OWASP OFFAT](https://github.com/OWASP/offat)** — the original spec-driven
  API tester this project migrates and extends.
- **[security-harness](https://github.com/dmdhrumilmistry/security-harness)** —
  the white-box multi-agent workflow this pipeline mirrors.

## License

MIT — see [LICENSE](LICENSE).

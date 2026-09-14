# Architecture

OFFAT-AI is two scanners that share a finding schema, a triager, and a report
format. This uniformity is deliberate: a single AI triager and a single set of
report writers serve both the black-box and white-box pipelines.

## Shared finding schema

Both pipelines emit findings as JSON objects with the same core keys, so
`offat-triage` and any downstream tooling work identically on either:

```jsonc
{
  "id": "…", "vector_id": "sqli-error", "class": "sqli",
  "title": "…", "severity": "high", "cwe": "CWE-89", "owasp": "API8:2023",
  "endpoint": "GET /search",        // DAST
  "file": "app.py", "line": 8,      // SAST
  "param": "q", "location": "query",
  "technique": "error", "payload": "'", "confidence": 0.85,
  "evidence": { "status_code": 500, "matched_signature": "…", "snippet": "…" },
  "triage": { "verdict": "confirmed", "cvss": 7.5, "remediation": "…", "source": "ai" }
}
```

## Black-box pipeline (`dast/`, Go)

```
spec ──▶ graph ──▶ kb ──▶ attack ──▶ engine ──▶ detect ──▶ triage ──▶ report
```

| Package | Responsibility |
|---|---|
| `internal/spec` | Parse Swagger 2.0 & OpenAPI 3.x into one model; resolve local `$ref`s |
| `internal/graph` | Link response producers to request consumers (dataflow) |
| `internal/kb` | Load embedded + external attack vectors; filter by class |
| `internal/attack` | Instantiate applicable vectors per parameter; structural attacks |
| `internal/engine` | Concurrent, rate-limited executor; runtime value store; auth/JWT |
| `internal/detect` | Baseline-differential detectors → candidate findings |
| `internal/triage` | AI (Anthropic) + heuristic verdict/CVSS/remediation |
| `internal/report` | JSON / JSONL / SARIF / Markdown / HTML |

**Why Go:** the engine is an I/O-bound concurrent HTTP fuzzer; Go's goroutines
and single-binary distribution fit. The only dependency is `gopkg.in/yaml.v3`;
the OpenAPI parser is self-contained for robustness.

## White-box pipeline (`whitebox/`, Python)

```
recon ──▶ hunt ──▶ chain ──▶ verify (triage) ──▶ report
```

Mirrors the security-harness stages. External tools (`semgrep`, `syft`,
`grype`/`trivy`/`osv-scanner`, `graft`) are used when present; a dependency-free
multi-language pattern hunter guarantees output otherwise. **Why Python:** easy
subprocess orchestration of the security toolchain and zero-dependency
distribution.

## Shared triager (`triager/`, Python) & the Go triager

The triager exists twice by design, once per runtime, with identical behavior:

- **Go** (`dast/internal/triage`) keeps the DAST binary self-contained.
- **Python** (`triager/offat_triage`) serves the white-box pipeline and the
  standalone `offat-triage` CLI (re-triage any findings file).

Both support three interchangeable AI backends behind one selection function
(`triage.Select` in Go, `make_triager` in Python):

- **`anthropic`** — the Anthropic Messages API (needs a key).
- **`claude-code`** — shells out to the Claude Code CLI (`claude -p`).
- **`codex`** — shells out to the OpenAI Codex CLI (`codex exec`).

All use the same *adversarial* prompt (refute first) and parse a compact JSON
verdict from the response, and all fall back to the same deterministic heuristic
(verdict from confidence, CVSS from severity, per-class remediation) so a run
never fails and never requires a key. `auto` (default) prefers a key, then
Claude Code, then Codex, then the heuristic. CLI backends are capped at low
concurrency since each finding spawns a process.

## Extensibility

- **New attack vector:** add YAML to `knowledge-base/` (black-box) — no code.
- **New SAST rule:** add a pattern to `whitebox/offat_wb/hunt.py`, or install
  semgrep for its full ruleset.
- **New report format:** add a writer in `internal/report` / `report.py`.
- **Different AI backend:** point `OFFAT_AI_BASE_URL` at an Anthropic-compatible
  endpoint, or set `OFFAT_AI_MODEL`.

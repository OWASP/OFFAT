# Architecture

OFFAT-AI is a staged platform whose tools share one finding schema, one triager,
and one interchange document (the [Bundle](../bundle/README.md)). The uniformity
is deliberate: a single AI triager and a single set of report writers serve the
live platform pipeline and the source-only modes alike. The full platform design
is in [`platform.md`](platform.md).

## Shared finding schema

Findings are JSON objects with the same core keys, so `offat-triage` and any
downstream tooling work identically on either a live (DAST) or a source (SAST)
finding:

```jsonc
{
  "id": "...", "vector_id": "sqli-error", "class": "sqli",
  "title": "...", "severity": "high", "cwe": "CWE-89", "owasp": "API8:2023",
  "endpoint": "ep-...",             // live finding (references an ASM endpoint)
  "file": "app.py", "line": 8,      // source finding
  "param": "q", "location": "query",
  "technique": "error", "payload": "'", "confidence": 0.85,
  "source_mode": "dast",            // dast | sast | graybox
  "evidence": { "status_code": 500, "matched_signature": "...", "snippet": "..." },
  "threat": { "owasp_api": "API8:2023", "owasp_web": "A03:2021", "cwe": "CWE-89" },
  "triage": { "verdict": "confirmed", "cvss": 7.5, "remediation": "...", "source": "ai" }
}
```

## Platform pipeline (`platform/` + `engine-rs/`)

```
map --> prg --> threat-model --> test-gen --> execute --> triage --> report
```

| Stage | Where | Responsibility |
|---|---|---|
| map | `platform` (reuses `graybox.graph_map`, `whitebox.hunt`) | endpoints (routes + OpenAPI/Swagger specs, params, response fields), sink/source inventory |
| prg | `platform.prg` | link response-field producers to request-param consumers (dataflow across endpoints) |
| threat-model | `platform.threat_model` | STRIDE threats, OWASP API Top 10 + CWE, risk, Mermaid DFD |
| test-gen | `platform.testgen` | injection vectors, PRG chains, identity-aware BOLA/BFLA/RBAC/auth/business cases |
| execute | `engine-rs` (`offat-engine`) | Rust async executor: multi-identity requests + differential baseline, response capture |
| triage | `platform.consolidate` + `triager` | detect findings, attach threat mapping, triage (AI/heuristic) |
| report | `reporter` (`offat-report`) | SARIF / Markdown / HTML (with DFD) / compliance / PDF |

**Why Rust for the engine:** the executor is an I/O-bound concurrent HTTP client
where performance, memory safety and a single static binary matter; `tokio` +
`reqwest` (rustls) provide HTTP/1.1 + HTTP/2 today, with gRPC / WebSocket /
HTTP-3+QUIC as the next protocol increments.

## Source-only modes

### White-box pipeline (`whitebox/`, Python)

```
recon --> hunt --> trace --> chain --> verify (triage) --> report
```

External tools (`semgrep`, `syft`, `grype`/`trivy`/`osv-scanner`, `graft`) are used
when present; a dependency-free multi-language pattern hunter guarantees output
otherwise. The **trace** stage uses graft (when installed) to bump confidence on
sinks reachable from an entry point; **verify** uses the shared token-disciplined
triager and the reporter emits JUnit plus a `--fail-on` CI gate.

### Gray-box pipeline (`graybox/`, Python)

```
recon --> map endpoints (graft) --> hunt --> reachability --> analyze (AI) --> report
```

Fuses the source view with a graft-mapped endpoint surface and judges each finding
by reachability (which exposed endpoint reaches the sink). No live traffic. AI runs
only on reachable findings - reachable-only, batched, cached and model-tiered.

## Shared triager (`triager/`, Python)

The triager enriches each finding with a verdict, CVSS and remediation, and carries
the threat taxonomy (OWASP API Top 10 2023, OWASP Top 10 2021, CWE). It supports
interchangeable backends behind one selection function (`make_triager`):

- **`anthropic`** - the Anthropic Messages API (needs a key).
- **`claude-code`** - shells out to the Claude Code CLI (`claude -p`).
- **`codex`** - shells out to the OpenAI Codex CLI (`codex exec`).
- **`heuristic`** - deterministic, offline, always available.

All use the same adversarial prompt (refute first) and fall back to the heuristic,
so a run never fails and never requires a key. `tiered_triage` adds a content-hash
verdict cache plus a cheap-model screen before a strong-model verify.

## Extensibility

- **New attack vector / test case:** extend `platform.testgen` (vectors matched to
  params, or a new generator).
- **New SAST rule:** add a pattern to `whitebox/offat_wb/hunt.py`, or install
  semgrep for its full ruleset.
- **New report format:** add a writer in `reporter/offat_report/render.py`.
- **New threat mapping:** extend `triager/offat_triage/taxonomy.py`.
- **Different AI backend:** point `OFFAT_AI_BASE_URL` at an Anthropic-compatible
  endpoint, or set `OFFAT_AI_MODEL`.

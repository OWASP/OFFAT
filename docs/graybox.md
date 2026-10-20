---
title: Gray-box design
section: Deep dives
nav_order: 4
description: offat-graybox - SAST fused with the endpoint attack surface and judged by reachability.
---

# Gray-box design (`offat-graybox`)

Gray-box fuses the **white-box** view (source, proven data flows) with a
**black-box** view (the HTTP endpoint attack surface, mapped from source) and
analyzes them together with AI. It sends **no live traffic** - reachability is
established statically from the code graph.

```
recon -> map endpoints -> code graph + patterns -> reachability -> analyze (AI) -> report
```

## The idea

SAST alone reports "a dangerous sink exists at `file:line`". Gray-box answers the
question that decides severity: **can an exposed endpoint actually reach it?** It
maps every route from source to its handler, links handlers to sinks through the
call graph, and has the AI judge each finding with that reachability context. A
sink reachable from an unauthenticated route is escalated; a dead-code sink is
capped at inconclusive.

## Run

```bash
pip install ./triager './whitebox[graph]' ./graybox
offat-graybox /path/to/repo                 # AI when a provider is available
offat-graybox ./repo --no-ai                # offline heuristic only
offat-graybox ./repo --provider claude-code # drive a local agent CLI
offat-graybox ./repo --fail-on high         # CI gate on reachable high+ findings
```

| Flag | Description |
|---|---|
| `--classes` | comma-separated vuln classes to hunt (default: all) |
| `-o, --out` | output directory (default `offat-report/graybox`) |
| `--no-ai` | heuristic triage only (no tokens) |
| `--provider` | `auto` (default), `anthropic`, `claude-code`, `codex`, `heuristic` |
| `--no-graph` | skip the code graph (falls back to graft / same-file reachability) |
| `--semgrep` | also run semgrep (opt-in) |
| `--no-graft` | map endpoints natively instead of via graft |
| `--no-cache` | do not read/write the AI-verdict cache |
| `--fail-on` | exit non-zero if an actionable finding is at/above this severity |

## Endpoint mapping

A native parser maps every route deterministically. Supported route forms: Flask/FastAPI decorators, Django
`path()`, Express `app/router.verb()`, Spring `@*Mapping`, Go routers
(`GET/POST/Handle/HandleFunc`), Rails `routes.rb`, **and OpenAPI/Swagger specs
shipped in the repo** (YAML or JSON - covers spec-driven frameworks like
connexion, where the `operationId` becomes the handler).

Reachability comes from the [code graph](code-graph.md): a proven flow carries
the routes that reach it, and every pattern hit is linked through its enclosing
function's callers up to the route handlers. Dead code stays unreachable instead
of being promoted because it shares a file with a route. With `--no-graph` the
older heuristics (handler-name match, graft callers, same-file) are used.

## Token discipline

AI analysis is the only token-spending stage, and it is kept cheap by design:

| Lever | Effect |
|---|---|
| Reachable-only | unreachable sinks are triaged offline (0 tokens) |
| Batched + tiered | a cheap model screens in batches; a strong model verifies only the confirmed/likely subset |
| Cached | verdicts keyed on a content hash; re-runs pay only for new/changed findings |

Tune with `OFFAT_SCREEN_MODEL`, `OFFAT_VERIFY_MODEL`, `OFFAT_BATCH_SIZE`,
or `--no-cache`. Every AI path degrades to a deterministic heuristic, so a run
never breaks and never requires a key.

## Output

`report.json`, `findings.jsonl`, `endpoints.json`, `results.sarif`, `report.md`,
`report.html`, `report.junit.xml`. Each finding carries `reachable`,
`reachable_from` (the endpoints that reach the sink), `source_mode: graybox`, and
a `threat` block mapping it to the **OWASP API Security Top 10 (2023)**, **OWASP
Top 10 (2021)** and a primary **CWE**. The report includes a Threat mapping
summary counting findings per OWASP API Top 10 category.

## Lineage

The multi-stage methodology mirrors the public
[security-harness](https://github.com/dmdhrumilmistry/security-harness) workflow
(recon -> hunt -> chain -> verify -> report).

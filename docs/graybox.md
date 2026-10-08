# Gray-box (`offat-graybox`)

Gray-box fuses the **white-box** view (source, data-flow sinks) with a
**black-box** view (the HTTP endpoint attack surface, mapped from source with
[graft](https://github.com/NanoNets/Graft)) and analyzes them together with AI.
It sends **no live traffic** - reachability is established statically from the
call graph.

```
recon -> map endpoints (graft) -> hunt (SAST) -> reachability -> analyze (AI) -> report
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
pip install ./triager ./whitebox ./graybox
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
| `--no-semgrep` | skip semgrep even if installed |
| `--no-graft` | map endpoints natively instead of via graft |
| `--no-cache` | do not read/write the AI-verdict cache |
| `--fail-on` | exit non-zero if an actionable finding is at/above this severity |

## Endpoint mapping

graft builds a structural graph for free (tree-sitter, no API key, no LLM
tokens); the pipeline queries it and confirms each route with a native parser so
output is deterministic. Supported route forms: Flask/FastAPI decorators, Django
`path()`, Express `app/router.verb()`, Spring `@*Mapping`, Go routers
(`GET/POST/Handle/HandleFunc`), and Rails `routes.rb`. When graft is absent the
native parser runs alone and reachability falls back to a conservative same-file
heuristic (noted in the report).

## Token discipline

AI analysis is the only token-spending stage, and it is kept cheap by design:

| Lever | Effect |
|---|---|
| Reachable-only | unreachable sinks are triaged offline (0 tokens) |
| Batched + tiered | a cheap model screens in batches; a strong model verifies only the confirmed/likely subset |
| Cached | verdicts keyed on a content hash; re-runs pay only for new/changed findings |

Tune with `OFFAT_GB_SCREEN_MODEL`, `OFFAT_GB_VERIFY_MODEL`, `OFFAT_GB_BATCH_SIZE`,
or `--no-cache`. Every AI path degrades to a deterministic heuristic, so a run
never breaks and never requires a key.

## Output

`report.json`, `findings.jsonl`, `endpoints.json`, `results.sarif`, `report.md`,
`report.html`, `report.junit.xml`. Each finding carries `reachable`,
`reachable_from` (the endpoints that reach the sink) and `source_mode: graybox`.

## Lineage

The multi-stage methodology mirrors the public
[security-harness](https://github.com/dmdhrumilmistry/security-harness) workflow
(recon -> hunt -> chain -> verify -> report).

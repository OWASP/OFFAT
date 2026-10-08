# Black-box DAST (`offat-dast`)

An OpenAPI-driven dynamic API security scanner.

## Build

```bash
make dast            # -> bin/offat-dast   (Go 1.24+)
# or
cd dast && go build -o offat-dast ./cmd/offat-dast
```

## Usage

```
offat-dast --spec <file> [--url <base>] [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--spec, -f` | — | OpenAPI/Swagger file (JSON or YAML) **(required)** |
| `--url` | spec server | Target base URL (overrides the spec) |
| `--classes` | all | Comma-separated classes to test |
| `--kb` | — | Extra knowledge-base directory to merge |
| `--out, -o` | `offat-report` | Report output directory |
| `--concurrency` | 10 | Concurrent requests |
| `--rate` | 25 | Max requests/sec (0 = unlimited) |
| `--timeout` | 15 | Per-request timeout (s) |
| `--auth-header` | `Authorization` | Auth header name |
| `--auth-value` | — | Auth value, e.g. `Bearer <token>` |
| `-H` | — | Extra header `Name: Value` (repeatable) |
| `--proxy` | — | HTTP(S) proxy (Burp/ZAP) |
| `--insecure` | false | Skip TLS verification |
| `--no-ai` | false | Heuristic triage only |
| `--ai-provider` | auto | Triage backend: `auto`, `anthropic`, `claude-code`, `codex`, `heuristic` |
| `--ai-model` | `OFFAT_AI_MODEL` | API model id for AI triage |
| `--dry-run` | false | Generate the plan, send nothing |
| `--graph` | false | Print the dataflow graph |
| `--list-classes` | false | List vuln classes and exit |
| `--max-payloads` | 0 | Cap payloads per vector |
| `--fail-on` | — | Exit non-zero if any actionable finding is at/above this severity (CI gate) |
| `--yes` | false | **Confirm authorization** to scan |

### AI triage backends

The triager runs against an Anthropic API key **or** a local agent CLI:

| Provider | Invocation | Needs |
|---|---|---|
| `anthropic` | Anthropic Messages API | `OFFAT_AI_API_KEY` / `ANTHROPIC_API_KEY` |
| `claude-code` | `claude -p "<prompt>"` | the `claude` CLI, signed in |
| `codex` | `codex exec "<prompt>"` | the `codex` CLI, signed in |
| `heuristic` | offline, deterministic | nothing |

`--ai-provider auto` (default) prefers an API key, then `claude`, then `codex`,
then the heuristic. CLI backends spawn one process per finding, so the engine
caps their concurrency at 2 automatically.

Environment: `OFFAT_AI_API_KEY`/`ANTHROPIC_API_KEY` (API); `OFFAT_AI_PROVIDER`;
`OFFAT_AI_MODEL`/`OFFAT_AI_BASE_URL` (API model/endpoint);
`OFFAT_AI_CLAUDE_MODEL`/`OFFAT_AI_CODEX_MODEL` (CLI model);
`OFFAT_AI_CLAUDE_CMD`/`OFFAT_AI_CODEX_CMD` (override the whole CLI invocation).

## Examples

```bash
# Offline: parse + graph + plan (no traffic)
offat-dast -f api.yaml --graph --dry-run

# Focused authenticated scan through Burp
offat-dast -f api.yaml --url https://api.example.com \
  --classes sqli,access_control,ssrf --auth-value "Bearer $T" \
  --proxy http://127.0.0.1:8080 --yes

# CI-friendly SARIF for code scanning
offat-dast -f api.yaml --url "$STAGING" --yes && cat offat-report/results.sarif

# Gate a pipeline: non-zero exit when a high+ finding survives triage
offat-dast -f api.yaml --url "$STAGING" --fail-on high --yes
# JUnit results for the CI test-report UI are written to report.junit.xml
```

## Dataflow graph & chaining

The graph links a value produced in one endpoint's response to a parameter that
consumes it elsewhere:

```
POST /users [id] --> GET /users/{id}.id           (exact name match)
POST /users [userId] --> POST /orders.userId      (exact name match)
```

At runtime the engine harvests identifier-like fields from 2xx responses into a
value store and substitutes them into later requests. This (a) makes requests
reach real objects instead of 404s, and (b) powers **BOLA/IDOR** testing: the
engine replays an endpoint with a *foreign* identifier (a different object's id,
or an adjacent/enumerated value) and watches for unauthorized 2xx access.

## Detection techniques

| Technique | Signal |
|---|---|
| `error` | A known DB/engine error signature appears (and is absent from baseline) |
| `reflection` | The payload/marker is echoed (XSS in HTML; SSTI arithmetic; SSRF metadata) |
| `time` | Response delayed past a threshold vs. baseline (blind SQLi/cmdi) |
| `boolean` | True/false payloads yield materially different responses |
| `status` | An unexpected status (e.g. a 3xx `Location` for open redirect) |
| `diff` | Response differs meaningfully from baseline |

Structural attacks (BOLA, BFLA, mass assignment, auth bypass, JWT `none`, method
tampering, rate limiting, CORS, data exposure) use request structure and the
graph rather than payload injection.

## Output

`offat-report/` contains `report.json`, `findings.jsonl`, `results.sarif`,
`report.md`, a styled `report.html`, and `report.junit.xml` (for CI test-report
UIs). Findings are sorted by verdict, then severity, then confidence.

Use `--fail-on <severity>` to turn the scan into a CI gate: the process exits
non-zero when any finding at or above that severity survives triage (i.e. is not
ruled a false positive), so a pipeline step fails on real findings.

## Extending

Add or tune vectors under `knowledge-base/` and pass `--kb knowledge-base`.
See [`knowledge-base/README.md`](../knowledge-base/README.md) for the schema.

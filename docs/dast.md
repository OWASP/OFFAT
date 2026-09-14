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
| `--ai-model` | `OFFAT_AI_MODEL` | Model id for AI triage |
| `--dry-run` | false | Generate the plan, send nothing |
| `--graph` | false | Print the dataflow graph |
| `--list-classes` | false | List vuln classes and exit |
| `--max-payloads` | 0 | Cap payloads per vector |
| `--yes` | false | **Confirm authorization** to scan |

Environment: `OFFAT_AI_API_KEY` / `ANTHROPIC_API_KEY` enable AI triage;
`OFFAT_AI_MODEL`, `OFFAT_AI_BASE_URL` override the model/endpoint.

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
`report.md`, and a styled `report.html`. Findings are sorted by verdict, then
severity, then confidence.

## Extending

Add or tune vectors under `knowledge-base/` and pass `--kb knowledge-base`.
See [`knowledge-base/README.md`](../knowledge-base/README.md) for the schema.

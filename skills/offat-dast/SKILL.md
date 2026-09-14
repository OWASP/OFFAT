---
name: offat-dast
description: >
  Run the OFFAT-AI black-box DAST engine against an API from its OpenAPI/Swagger
  spec. Use when the user wants to dynamically test a running API for security
  issues (BOLA/IDOR, SQLi, injection, XSS, SSRF, mass assignment, auth bypass,
  data exposure, misconfig) generated from the spec, or asks to "scan/pentest an
  API", "test my OpenAPI/swagger", or "run DAST".
---

# OFFAT-AI — Black-box DAST

Drive the Go DAST engine that parses an OpenAPI/Swagger spec, builds a parameter
dataflow graph, generates attack vectors from the knowledge base, executes them,
and triages findings into reports.

## Authorization gate (required)

Active scanning sends attack traffic. **Confirm the user owns or is explicitly
authorized to test the target** before running. The CLI refuses to scan without
`--yes`; only pass it once authorization is confirmed.

## Steps

1. **Locate inputs.** Find the spec file (`.json`/`.yaml`) and the target base
   URL. If the base URL is missing, ask; the spec's `servers`/`host` is only a
   default and may point at production.

2. **Build the engine** (first run):
   ```bash
   cd dast && go build -o ../bin/offat-dast ./cmd/offat-dast
   ```

3. **Preview the plan** (no traffic) to sanity-check coverage:
   ```bash
   ./bin/offat-dast --spec <spec> --kb knowledge-base --graph --dry-run
   ```

4. **Run the scan** (after authorization):
   ```bash
   ./bin/offat-dast --spec <spec> --url <base-url> --kb knowledge-base \
     --auth-value "Bearer <token>" --rate 25 --concurrency 10 \
     --out offat-report --yes
   ```
   - AI triage turns on automatically when `OFFAT_AI_API_KEY` (or
     `ANTHROPIC_API_KEY`) is set; otherwise the heuristic triager is used. Pass
     `--no-ai` to force heuristic.
   - No API key? Use a local agent CLI instead: `--ai-provider claude-code`
     (uses the signed-in `claude` CLI) or `--ai-provider codex`. `auto`
     (default) prefers a key, then `claude`, then `codex`, then heuristic.
   - Limit scope with `--classes sqli,access_control,ssrf`.
   - Route through a proxy for inspection with `--proxy http://127.0.0.1:8080`.

5. **Report.** Read `offat-report/report.md` and summarize confirmed/likely
   findings with endpoint, parameter, evidence and remediation. Point the user
   at `report.html` (styled), `report.json`/`findings.jsonl` (machine) and
   `results.sarif` (code scanning).

## Notes

- The dataflow graph links producers (e.g. `POST /users` → `id`) to consumers
  (`GET /users/{id}`), enabling identifier chaining and BOLA/IDOR probing.
- Add or tune attack vectors in `knowledge-base/` (see its README); re-run with
  `--kb knowledge-base`.
- Re-triage existing results without rescanning via the `offat-triage` skill.

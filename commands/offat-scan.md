---
description: Run an OFFAT-AI security scan - white-box SAST over a codebase, gray-box source-plus-surface analysis, the full Bundle platform pipeline against a live API, or re-triage an existing findings file.
---

You are running an **OFFAT-AI** security scan. Interpret the user's request
(`$ARGUMENTS`) and pick the mode:

- A source directory / repository, static review only -> **white-box SAST**
  (invoke the `offat-whitebox` skill).
- A source directory, reachability-aware analysis (endpoints mapped from code,
  AI-judged by what the exposed surface can reach, no live traffic) -> **gray-box**
  (invoke the `offat-graybox` skill).
- A live API to test (source and/or an OpenAPI spec, plus a base URL) -> the
  **platform pipeline** over one Bundle:
  ```
  offat-platform map <source> --threat-model -o app.offat.json
  offat-platform test-gen app.offat.json [--identities identities.json]
  offat-engine --bundle app.offat.json --url <base-url> [--identities identities.json] --yes
  offat-platform triage app.offat.json [--fail-on high]
  offat-report app.offat.json -o reports --formats all
  ```
  Supply `--identities` (name, role, headers, owns) to enable BOLA / BFLA / RBAC /
  broken-auth tests. See `examples/identities.example.json`.
- An existing findings file -> **re-triage** (invoke the `offat-triage` skill).

Rules:

1. **Authorization first.** The engine sends active traffic; confirm the user owns
   or is authorized to test the target before running `offat-engine` (it requires
   `--yes`). Never scan a third party.
2. Prefer AI triage when a provider is available (`OFFAT_AI_API_KEY`, or
   `--provider claude-code` / `codex`); otherwise the heuristic runs offline.
3. Report back: counts by severity and verdict, the top confirmed/likely findings
   (endpoint or `file:line`, evidence, remediation), the OWASP API Top 10 mapping,
   and the paths to the generated reports.

If required inputs are missing (source path, base URL, or findings file), ask for
them before running.

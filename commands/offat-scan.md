---
description: Run an OFFAT-AI security scan (black-box DAST from an OpenAPI spec, white-box SAST over a codebase, gray-box source-plus-surface, or both) and summarize triaged findings.
---

You are running an **OFFAT-AI** security scan. Interpret the user's request
(`$ARGUMENTS`) and pick the mode:

- An OpenAPI/Swagger spec + a target URL → **black-box DAST** (invoke the
  `offat-dast` skill).
- A source directory / repository → **white-box SAST** (invoke the
  `offat-whitebox` skill).
- A source directory and the user wants reachability-aware or "gray-box"
  analysis (endpoints mapped from code, AI-judged by what the exposed surface can
  reach, no live traffic): invoke the `offat-graybox` skill. This is also the
  most token-efficient AI pass over code.
- Both provided, or "full scan" → run **both**, then merge the summaries.
- An existing findings file → **re-triage** (invoke the `offat-triage` skill).

Rules:

1. **Authorization first.** For DAST (active traffic), confirm the user owns or
   is authorized to test the target before sending any request. Never scan a
   third party.
2. Follow the relevant skill's steps exactly (build once, dry-run to preview,
   then scan). Prefer AI triage when `OFFAT_AI_API_KEY` is set.
3. Report back: counts by severity and verdict, the top confirmed/likely
   findings (endpoint or `file:line`, evidence, remediation), and the paths to
   the generated `report.md` / `report.html` / `results.sarif`.

If required inputs are missing (spec, URL, or path), ask for them before
running.

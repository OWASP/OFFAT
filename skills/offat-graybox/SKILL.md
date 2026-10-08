---
name: offat-graybox
description: >
  Run the OFFAT-AI gray-box pipeline over a codebase - map the HTTP endpoint
  attack surface from source with graft, fuse it with the SAST hunters, and
  AI-analyze only the findings reachable from a mapped endpoint (batched, cached,
  model-tiered). No live traffic. Use when the user wants a combined
  source-plus-surface review, "both modes", reachability-aware triage, or the
  most token-efficient AI security pass over code they own.
---

# OFFAT-AI - Gray-box

Drive the Python gray-box pipeline. It fuses the white-box view (source, sinks)
with a black-box view (endpoints mapped from source via graft) and lets the AI
judge each finding by whether an exposed endpoint can actually reach the sink.

Scope is **owned or authorized code only**. The pipeline sends no live traffic;
reachability is established statically from the call graph.

## Steps

1. **Point at the codebase** (a local path). graft is optional - if it is on
   PATH the endpoint map and reachability use its structural graph (free, no
   key); otherwise a native regex mapper and a same-file heuristic are used and
   the report notes the degradation. Do not auto-install graft without saying so.

2. **Run the pipeline:**
   ```bash
   python -m offat_gb <path-to-repo> --out offat-report/graybox
   ```
   Run from the repo root, or `pip install ./triager ./whitebox ./graybox` first
   so `offat-graybox` is on PATH.
   - AI engages when a provider is available (`OFFAT_AI_API_KEY`, or
     `--provider claude-code` / `codex`); `--no-ai` forces the offline heuristic.
   - Token controls: `--no-cache`, `OFFAT_GB_SCREEN_MODEL`, `OFFAT_GB_VERIFY_MODEL`.
   - `--fail-on high` turns the run into a CI gate on reachable high+ findings.

3. **Report.** Read `offat-report/graybox/report.md`. Summarize the endpoint
   attack surface, then the findings by severity and verdict, and for each call
   out `reachable_from` (which endpoints reach the sink), `file:line`, and the
   remediation. The run also emits `endpoints.json`, `report.html`,
   `report.json`, `findings.jsonl`, `results.sarif` and `report.junit.xml`.

## Stages

| Stage | What it does |
|---|---|
| recon | language mix, dependency manifests, SBOM/CVEs when tools present |
| map | graft builds the structural graph; every route is mapped to its handler |
| hunt | the white-box SAST hunters (built-in + semgrep) find candidate sinks |
| reachability | link each sink to the endpoints that reach it via the call graph |
| analyze | AI triages reachable findings only - batched, cached, model-tiered |
| report | endpoint-centric JSON, JSONL, SARIF, Markdown, HTML, JUnit |

## Token discipline (why gray-box is cheap)

- **Reachable-only:** unreachable sinks are triaged offline, never sent to a model.
- **Batched + tiered:** a cheap model screens in batches; a strong model verifies
  only the confirmed/likely subset.
- **Cached:** verdicts are keyed on a content hash, so re-runs pay only for new or
  changed findings.

The methodology mirrors the public
[security-harness](https://github.com/dmdhrumilmistry/security-harness) workflow.

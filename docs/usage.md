---
title: Usage
section: Start
nav_order: 3
description: Run the full pipeline, individual stages, and the source-only modes.
---

# Usage

> **Authorized use only.** `--url` sends real requests to the target and
> requires `--yes`. Only test systems and code you own or are explicitly
> authorized to assess.

## The whole pipeline

```bash
offat-platform run /path/to/your/repo \
  --url https://api.your-authorized-target.test \
  --identities examples/identities.example.json \
  --yes -o app.offat.json --report-dir reports --fail-on high
```

This writes `app.offat.json` (the Bundle) and a `reports/` directory with SARIF,
Markdown, HTML, an OWASP API Top 10 compliance report and a best-effort PDF.

**Omit `--url` for a source-only run.** Mapping, test planning, triage and
reporting still happen; nothing is sent over the network.

## Stage by stage

```bash
# 1. map the attack surface, parameter relation graph and threat model
offat-platform map /path/to/your/repo --threat-model -o app.offat.json

# 2. plan tests (identities unlock BOLA / BFLA / RBAC / auth cases)
offat-platform test-gen app.offat.json --identities examples/identities.example.json

# 3. execute against an authorized target with the Rust engine
offat-engine --bundle app.offat.json --url https://api.your-authorized-target.test \
  --identities examples/identities.example.json --yes

# 4. consolidate and triage, then render reports
offat-platform triage app.offat.json --fail-on high
offat-report app.offat.json -o reports --formats all
```

Every stage reads and writes the same Bundle, so you can stop, inspect, edit and
resume anywhere. `offat-platform validate app.offat.json` checks it against the
schema.

## Identities

`--identities` points at a JSON file. Each identity has a name, a role, request
`headers` (its credentials) and optionally `owns` (object ids it holds). With two
or more identities OFFAT plans **BOLA (API1)**, **broken authentication (API2)**,
**BFLA and RBAC (API5)** and **business-logic (API6)** cases, and the engine runs
a differential baseline for each. Credentials stay in that file and never enter
the Bundle. See
[`examples/identities.example.json`](../examples/identities.example.json).

## Source-only modes

```bash
offat-whitebox /path/to/repo                   # code-graph SAST + AI triage
offat-whitebox /path/to/repo --agent 10        # graph-tool agent re-verifies the top 10
offat-whitebox /path/to/repo --infer-specs     # AI labels unknown sinks / sanitizers
offat-whitebox /path/to/repo --graph-out       # export the code graph (JSON + GraphML)
offat-graybox  /path/to/repo --fail-on high    # SAST prioritized by endpoint reachability
```

See [Code graph](code-graph.md) and [Source modes](source-modes.md).

## AI triage

The triager picks a backend automatically (`auto`: API key, then Claude Code,
then Codex, then the offline heuristic), or force one with `--provider` /
`OFFAT_AI_PROVIDER`. Verdicts are cached by content hash, screened in batches by
a fast model, and only the confirmed / likely subset is re-verified by a strong
model.

```bash
offat-triage findings.json --provider claude-code
```

## Visualize

```bash
python -m http.server -d viz 8080   # open http://localhost:8080 and import a *.offat.json
```

## CI gate

`--fail-on <severity>` exits non-zero when an actionable finding (not triaged as
a false positive) is at or above that severity. For GitHub, use the
[GitHub Action](github-action.md).

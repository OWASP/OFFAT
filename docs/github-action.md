---
title: GitHub Action
section: Integrate
nav_order: 1
description: Run OFFAT in CI with the OWASP/OFFAT action and publish results to code scanning.
---

# GitHub Action

The `OWASP/OFFAT` action installs the platform, runs the pipeline over your
repository and uploads the reports. By default it is **source-only**: nothing is
sent over the network.

## Source-only scan

```yaml
name: offat
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # only for upload_sarif

jobs:
  offat:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OWASP/OFFAT@dev
        with:
          path: .
          fail_on: high
          upload_sarif: 'true'
        env:
          OFFAT_AI_API_KEY: ${{ secrets.OFFAT_AI_API_KEY }}   # optional: AI triage
```

Findings appear in **Security → Code scanning**, with each proven source-to-sink
path rendered as a code flow.

## Live scan of a staging deployment

A live run needs both `url` and `authorized: 'true'`. The action refuses a URL
without the explicit confirmation, mirroring the CLI's `--yes` gate.

```yaml
      - uses: OWASP/OFFAT@dev
        with:
          path: .
          url: https://staging.api.example.test
          authorized: 'true'
          identities: .github/offat-identities.json
          fail_on: high
```

Only point it at environments you own or are explicitly authorized to test.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | source tree and/or OpenAPI spec to analyze |
| `url` | empty | base URL of an authorized target; empty = source-only |
| `authorized` | `false` | must be `'true'` for live runs |
| `identities` | empty | identities JSON for access-control checks |
| `fail_on` | empty | fail on findings at or above `critical`, `high`, `medium` or `low` |
| `formats` | `all` | `sarif,md,html,compliance,pdf` or `all` |
| `upload_sarif` | `false` | upload `results.sarif` to code scanning |
| `artifact_retention_days` | `7` | retention for the `offat-reports` artifact |

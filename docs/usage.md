---
title: Usage
nav_order: 3
description: "Running the OFFAT CLI and the OFFAT-AI platform pipeline."
---

# Usage
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Authorization
{: .text-red-200 }

OFFAT sends real requests to the target. The platform engine sends active attack
traffic and requires `--yes`. Only test systems and code you own or are
explicitly authorized to assess.

---

## Classic CLI

Generate and run tests from an OpenAPI/Swagger file or URL.

```bash
offat -f swagger_file.json                 # from a file
offat -f https://example.com/docs.json     # from a URL
offat -h                                    # all options
```

### Output formats

```bash
offat -f swagger_file.json -o output.json -of json   # json (default)
offat -f swagger_file.json -o output.html -of html   # html
offat -f swagger_file.json -o output.yaml -of yaml   # yaml
```

### Common options

```bash
# only test endpoint paths matching a regex
offat -f swagger_file.json -pr '/user'

# add request headers (auth, content type, ...)
offat -f swagger_file.json -H 'Authorization: Bearer <token>' -H 'Accept: application/json'

# rate-limit requests (per second)
offat -f swagger_file.json -rl 1000

# route through a proxy (SSL checks off by default; add --ssl to enforce)
offat -f swagger_file.json -p http://localhost:8080 -o out.json -of json
```

### User-provided test data

Drive tests with your own actors, headers, and inputs (also powers broken
access control via `unauthorized_endpoints`):

```bash
offat -f swagger_file.json -tdc test_data_config.yaml
```

```yaml
actors:
  - actor1:
      request_headers:
        - name: Authorization
          value: Bearer <token-1>
      query:
        - name: id
          value: 145
          type: int
      unauthorized_endpoints:   # for broken access control
        - "/store/order/.*"
  - actor2:
      request_headers:
        - name: Authorization
          value: Bearer <token-2>
```

### REST API

```bash
offat-api                 # or: python -m offat.api
# docs at http://localhost:8000/docs
```

---

## OFFAT-AI platform

The platform runs a staged pipeline over one canonical
[Bundle](https://github.com/OWASP/OFFAT/tree/dev/bundle) file:

```
map -> parameter relation graph -> threat model -> test-gen -> execute -> triage -> report
```

See [How it works](how-it-works) for what each stage does.

### The whole pipeline in one command

```bash
offat-platform run /path/to/your/repo \
  --url https://api.your-authorized-target.test \
  --identities examples/identities.example.json \
  --yes -o app.offat.json --report-dir reports --fail-on high
```

This writes `app.offat.json` and a full `reports/` set (SARIF, Markdown, HTML,
compliance, best-effort PDF). `--url` sends real traffic, so it requires
`--yes`. **Omit `--url` for a source-only run** (map -> test-gen -> triage ->
report with SAST findings only).

### Or run the stages individually

```bash
# 1. map the attack surface + PRG + threat model (from source and/or a spec)
offat-platform map /path/to/your/repo --threat-model -o app.offat.json

# 2. generate the test plan (add --identities to enable BOLA/BFLA/RBAC/auth tests)
offat-platform test-gen app.offat.json --identities examples/identities.example.json

# 3. execute against an authorized target (sends real traffic; --yes required)
offat-engine --bundle app.offat.json --url https://api.your-authorized-target.test \
  --identities examples/identities.example.json --yes

# 4. consolidate + triage, then render reports
offat-platform triage app.offat.json --fail-on high
offat-report app.offat.json -o reports --formats all
```

### Identities (access-control and auth tests)

`--identities` points at a JSON file where each identity has a name, role,
request `headers` (its credentials), and optional `owns` (object ids it holds).
This unlocks **BOLA (API1)**, **broken authentication (API2)**, **BFLA and RBAC
(API5)**, and **business-logic (API6)** tests. Credentials stay in that file and
never enter the Bundle. See
[`examples/identities.example.json`](https://github.com/OWASP/OFFAT/blob/dev/examples/identities.example.json).

### Source-only modes

No live traffic - analyze code you own:

```bash
offat-whitebox /path/to/your/repo --no-ai      # SAST; drop --no-ai for AI triage
offat-graybox  /path/to/your/repo --fail-on high  # SAST + endpoint reachability
```

See [Source modes](source-modes).

### Re-triage and visualize

```bash
offat-triage findings.json --provider claude-code   # add/refresh verdicts
python -m http.server -d viz 8080                    # open http://localhost:8080, import *.offat.json
```

### AI triage backends

The triager picks a backend automatically, or force one with `--provider` /
`OFFAT_AI_PROVIDER`. `auto` prefers an API key, then Claude Code, then Codex,
then the offline heuristic. Verdicts are cached by content hash and screened by a
cheap model before a strong model verifies the confirmed/likely subset.

---

## CI gate

Both the classic CLI and the platform support failing a build on findings:

```bash
offat-platform triage app.offat.json --fail-on high   # exit non-zero on high+ findings
```

For spec-driven scans in CI, see the [GitHub Action](github-action).

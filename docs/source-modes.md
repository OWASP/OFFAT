---
title: Source modes
nav_order: 5
description: "White-box (SAST) and gray-box (SAST + reachability) - no live traffic."
---

# Source modes
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

Two modes analyze code you own without sending any live traffic. Both reuse the
same libraries, triager, and reporters as the live platform.

## White-box (SAST)

```bash
offat-whitebox /path/to/your/repo --no-ai      # heuristic; drop --no-ai for AI triage
offat-whitebox /path/to/your/repo --fail-on high
```

Pipeline:

```
recon -> hunt -> trace -> chain -> verify (triage) -> report
```

- **recon / hunt** - find sinks and sources with a dependency-free,
  multi-language pattern hunter, plus `semgrep --config auto` when installed.
- **trace** - use `graft` (when installed) to raise confidence on sinks reachable
  from an entry point.
- **verify** - the shared token-disciplined triager assigns a verdict, CVSS, and
  remediation.
- **report** - findings plus JUnit and a `--fail-on` CI gate.

Catches: hardcoded secrets, injection sinks, unsafe deserialization, weak crypto
/ TLS-off, DOM XSS sinks, SSRF sinks, misconfiguration, and vulnerable
dependencies (SCA).

## Gray-box (SAST + reachability)

```bash
offat-graybox /path/to/your/repo --fail-on high
offat-graybox /path/to/your/repo --no-ai -o out/report   # offline
```

Pipeline:

```
recon -> map endpoints (graft) -> hunt -> reachability -> analyze (AI) -> report
```

Gray-box fuses the source view with a `graft`-mapped endpoint surface and judges
each finding by **reachability** - which exposed endpoint reaches the sink. AI
runs only on reachable findings, batched, cached, and model-tiered, so it stays
token-disciplined. No live traffic is sent.

## When to use which

| Mode | Live traffic | Best for |
|---|:--:|---|
| Classic CLI | yes | A running API with an OpenAPI/Swagger spec |
| Platform `run --url` | yes | Deep, source-aware testing of an API you can reach |
| Platform `run` (no `--url`) | no | Source-only pass, SAST findings only |
| White-box | no | Fast SAST over any codebase |
| Gray-box | no | SAST prioritized by endpoint reachability |

## Deep dives

- [White-box design](https://github.com/OWASP/OFFAT/blob/dev/docs/whitebox.md)
- [Gray-box design](https://github.com/OWASP/OFFAT/blob/dev/docs/graybox.md)

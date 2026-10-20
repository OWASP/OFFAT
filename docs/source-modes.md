---
title: Source modes
section: Concepts
nav_order: 3
description: White-box and gray-box analysis of code you own, with no live traffic.
---

# Source modes

Two modes analyze code you own without sending any traffic. Both share the
platform's code graph, triager and report writers.

## White-box

```bash
offat-whitebox /path/to/your/repo                 # AI triage when a provider is available
offat-whitebox /path/to/your/repo --no-ai         # offline heuristic only
offat-whitebox /path/to/your/repo --fail-on high  # CI gate
```

```
recon -> code graph + patterns -> chain -> verify (triage / agent) -> report
```

- **recon** - detect the stack, inventory manifests, generate an SBOM and
  dependency CVEs when `syft` / `grype` / `trivy` / `osv-scanner` are installed.
- **code graph** - prove source-to-sink flows and attach routes
  ([details](code-graph.md)).
- **patterns** - secrets, weak crypto, TLS-off and misconfiguration. Injection
  hits the graph cannot connect to a source are kept, but demoted.
- **verify** - the shared triager assigns verdict, CVSS and remediation;
  `--agent N` re-verifies the top findings with graph tools.
- **report** - JSON, JSONL, SARIF (with code flows), Markdown, HTML and JUnit.

semgrep is no longer part of the default pipeline; pass `--semgrep` to add it.

## Gray-box

```bash
offat-graybox /path/to/your/repo --fail-on high
offat-graybox /path/to/your/repo --no-ai -o out/report
```

```
recon -> map endpoints -> code graph + patterns -> reachability -> analyze (AI) -> report
```

Gray-box judges every finding by **reachability**: which exposed endpoint
reaches it through the call graph. Only reachable findings are sent to a model,
batched, cached and model-tiered; unreachable ones are triaged offline at zero
token cost.

## Which mode

| Mode | Live traffic | Best for |
|---|:--:|---|
| `offat-platform run --url` | yes | deep, source-aware testing of an API you are authorized to test |
| `offat-platform run` | no | the full pipeline as a planning and SAST pass |
| `offat-whitebox` | no | fast SAST over any codebase |
| `offat-graybox` | no | SAST prioritized by endpoint reachability |

## Deep dives

[White-box design](whitebox.md) · [Gray-box design](graybox.md)

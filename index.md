---

layout: col-sidebar
title: OWASP OFFAT
tags: api-security
level: 2
type: code, tool
pitch: Source-aware API security testing - maps your API from code, proves source-to-sink flows on a code graph, executes tests with a Rust engine and triages with AI.

---

OWASP OFFAT (OFFensive Api Tester) tests APIs for common vulnerabilities from
their source code and OpenAPI specifications. It maps the attack surface, proves
source-to-sink data flows on a code property graph, generates and executes tests
with a Rust engine, and triages the results with AI or an offline heuristic.

**Documentation:** [owasp.github.io/OFFAT](https://owasp.github.io/OFFAT/)

## How it works

```
map -> code graph -> threat model -> test-gen -> execute (Rust) -> triage (AI) -> report
```

- Attack-surface mapping from source: routes, routers, decorators and OpenAPI specs
- Interprocedural taint analysis for Python and JavaScript/TypeScript
- Identity-aware access-control testing (BOLA, BFLA, RBAC)
- Rust execution engine: HTTP/1.1, HTTP/2, WebSocket, gRPC (HTTP/3 opt-in)
- AI triage with caching and model tiering, or a fully offline heuristic
- SARIF, Markdown, HTML and OWASP API Top 10 compliance reports
- GitHub Action for CI

## Try it

```bash
git clone https://github.com/OWASP/OFFAT.git && cd OFFAT
pip install ./bundle ./triager './whitebox[graph]' ./graybox ./platform ./reporter
offat-platform run /path/to/repo -o app.offat.json --report-dir reports
```

Only test systems and code you own or are authorized to assess.

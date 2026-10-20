---
title: AI roadmap
section: Deep dives
nav_order: 5
description: Where AI sits in OFFAT, what the code graph adds, and what comes next.
---

# OFFAT-AI: code-graph white-box and AI roadmap

Status: proposal + first implementation (`whitebox/offat_wb/cpg/`), October 2026.

## 1. Where AI sits in OFFAT today

| Stage | What the model does | Limitation |
|---|---|---|
| `whitebox` hunt | nothing (regex + semgrep wrapper) | per-line matches, no data flow; noisy |
| `whitebox` trace | nothing (graft `callers` by *name*, "looks like a handler" regex) | name collisions, no proof the *data* reaches the sink |
| triage (`offat_triage`) | batched screen + tiered verify of each finding | sees an 800-char snippet; cannot look anything up |
| `graybox` analyze | same triager, reachable-only | reachability = graft names or "same file as a route" |
| `platform` test-gen | proposes extra payloads per endpoint (700 tokens) | no idea which sink sits behind the param |

The model is asked to judge exploitability without the one artifact that decides
it: the path from attacker input to the sink and what happens along it.

## 2. What this change adds

**A code-graph taint engine replaces semgrep as the white-box core.**

- `cpg/graph.py`: a networkx `MultiDiGraph` code property graph. Nodes are
  functions, params, *versioned* locals, `self` fields, call sites, args, returns
  and sources. Edges are `flow` (with per-class `sanitizes`), `call`/`ret`
  labelled by call site, and `calls`. Exportable as JSON or GraphML (Gephi, yEd,
  Neo4j import).
- `cpg/py_frontend.py`: stdlib `ast`. Covers Flask, FastAPI, Django/DRF,
  Tornado, aiohttp and Lambda, `src/` layouts, nested functions, and deferred
  calls (`queue.enqueue(fn, x)`, `fn.delay(x)`, `Thread(target=fn)`,
  executors, `BackgroundTasks`).
- `cpg/js_frontend.py`: tree-sitter JS/TS. Covers Express routers including
  handler factories and wrappers, `require`/`import`/`export`, TS destructured
  `req`, and callbacks.
- `cpg/taint.py`: an interprocedural BFS with a call-site stack, so calls and
  returns stay matched (`f(tainted)` does not leak into `f("const")`), plus
  per-class sanitizers and reaching definitions (`x = int(x)` kills taint).
  BOLA candidates are suppressed when the lookup is scoped to the caller or an
  ownership check follows. Mass assignment (API3) fires only on whole-body
  sources.
- Pattern hits are fused, not discarded: a regex hit on a proven line is
  dropped as a duplicate. A regex injection hit with no source is kept but
  demoted, and gains graph reachability.
- SARIF now carries `codeFlows`, so GitHub code scanning renders the path.

**Three AI features built on the graph:**

1. **Graph-grounded triage**: the batch prompt receives the proven hop-by-hop
   path, routes and authz context instead of a snippet.
2. **Graph-tool agent** (`--agent N`, `cpg/agent.py`): a tool-use loop with
   read-only, repo-confined tools (`get_function`, `callers`, `callees`,
   `read_lines`, `flows_into`). It tries to refute first, then submits a
   verdict and a PoC request. Repo content is framed as untrusted data, since
   comments are a prompt-injection channel. It uses `claude-opus-5-5` with
   server-side refusal fallback.
3. **Spec inference** (`--infer-specs`, `cpg/infer.py`): the *taint frontier*
   is the set of unknown callees that receive attacker data. The model labels
   each one sink, sanitizer or propagator once per API, and the result is
   written to `inferred-specs.json` and fed back via `--specs`. This targets
   the main source of misses (in-house wrappers) and of noise (lookups such as
   `authenticatedUsers.get(token)` that return server-owned data).

Also fixed: the default screen model `claude-haiku-5` is not a valid model ID,
so batched screening always failed over to per-finding calls. It is now
`claude-haiku-5-5`.

## 3. Benchmarks (no AI, graph engine only)

| Target | Size | Time | Entry points | Flows | Notes |
|---|---|---|---|---|---|
| fixture (`whitebox/tests/fixtures/taint_app`) | Flask+FastAPI+Express | <1s | 29 | 16 | 16/16 planted vulns found, 0/12 safe twins flagged |
| OWASP Juice Shop (TS) | 4,260 fns | 6.3s | 91 | 56 (17 in intentionally vulnerable `codefixes/`) | login + search SQLi, SSRF, open redirect, 3× `$where`/Mongo NoSQLi, eval + pug SSTI, basket IDOR, YAML deser; every finding mapped to its route |
| we45 Vulnerable-Flask-App | 969 fns | 1.1s | 11 | 4 | 4/5 taint-style vulns, 0 FP; miss: SSTI via `str(exception)` |
| dvpwa (aiohttp) | 978 fns | 1.3s | 8 | 1 | the SQLi |
| pygoat (Django) | 293 fns | 0.5s | 131 | 25 | SQLi, cmdi, eval, pickle/yaml, SSRF, path traversal, XSS |

Known gaps: taint through exceptions, key-sensitive containers (dict fields),
second-order (DB write -> read), and `vm` sandbox contexts.

## 4. Roadmap

### P0: close the loop between white-box and DAST

- **Graph finding -> targeted test case.** Each graph finding already has a
  route, a param and a sink class (plus a PoC from the agent). Emit these into
  the Bundle as test cases so the Rust engine confirms them against an
  authorized deployment, and mark them `confirmed-dynamic`. Today test-gen
  guesses vectors from parameter *names*.
- **Sink-aware payload generation.** Give `platform/testgen._augment_with_ai`
  the sink code at the end of the path, not just the endpoint (SQL dialect,
  shell vs argv, template engine, `$where` vs operator smuggling).
- **Agent verification for DAST findings.** For a dynamic hit, start the agent
  from the route's handler node in the graph so it can explain *why* the
  response looked vulnerable, or refute it.

### P1: precision and coverage where AI is the right tool

- **Authorization model extraction.** Collect per-route decorators/middleware
  from the graph (`login_required`, `isAuthorized()`, `Depends(current_user)`)
  into an auth matrix. Let the model flag outliers ("every `/api/Cards/*`
  route has `isAuthorized` except this one") and feed BOLA/BFLA test-gen with
  `--identities`.
- **Business-logic hypotheses.** Hand the model graph slices of
  state-changing handlers (checkout, coupon, wallet, transfer) and ask for
  multi-step abuse cases (negative quantities, replayed coupons, race windows),
  then emit PRG chains.
- **Second-order sources.** Treat data read back from the DB, and, for
  security tools and API clients, *responses from the scanned server*, as
  sources. That would have caught the report XSS in §5.
- **Key-sensitive containers.** Track `d["field"]` separately and use the
  agent to refute container over-taint (e.g. `post_test_processor.py:189`).
- **Shared spec registry.** Cache AI-inferred specs per package and version
  and share them across runs and projects, with human review.
- **PR / diff mode.** Slice the graph to changed functions plus everything
  they reach. Comment with SARIF code flows and the agent's verdict.

### P2: platform and safety of the AI layer

- **Expose the graph to agents over MCP.** The repo already ships Claude Code
  skills and a plugin. An `offat-graph` MCP server (`callers`, `slice`,
  `paths_to(sink)`) would let interactive agents use the same graph.
- **Sanitizer validation by execution.** The model writes a harness, a sandbox
  runs the project's custom validator against a payload corpus, and the
  interpreter, not the model, decides whether it holds.
- **Cost controls.** Prompt-cache the system prompt and tools across agent
  turns, use the Message Batches API for nightly runs, and set a per-run token
  budget.
- **Eval harness.** Juice Shop, pygoat, VFA, dvpwa and OWASP Benchmark with
  expected findings: track graph precision/recall and AI verdict accuracy per
  release, including prompt-injection canaries planted in code comments.

## 5. Self-scan of OFFAT

Running the engine on this repository proves flows from `POST /api/v1/scan`
through the RQ job queue into the classic tester (the job function is reached via
`task_queue.enqueue(scan_api, ...)`, which the deferred-call modelling resolves).
Security-relevant results have been reported privately to the maintainers.
Functional bugs surfaced on the way:

- `src/offat/api/jobs.py:16` calls `generate_and_run_tests()` without the required
  `http_methods` argument (since `acd733b`), so every REST-API scan job errors out.
- A non-URL `openapi` string is passed as `spec=` and `BaseParser` calls `.get` on a
  `str`, so inline specs via the API cannot work.
- `report/generator.py:47` appends each result once per key (duplicated rows).
- `post_test_processor.py:184`: `HEADER_REGEX_FILTER` matches the body, not headers.

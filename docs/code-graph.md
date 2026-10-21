---
title: Code graph
section: Concepts
nav_order: 2
description: How OFFAT proves source-to-sink data flows on a code property graph, and how AI builds on it.
---

# Code graph

The white-box core of OFFAT is a code property graph with an interprocedural
taint search. Instead of matching dangerous lines, it proves that attacker
input actually *reaches* a dangerous call, and records the path.

```
request field / route param  ->  locals, helpers, other modules  ->  sink argument
          (source)                     (proven path)                   (sink)
```

## What goes in the graph

| Node | Meaning |
|---|---|
| `function` | a function or method, with its route if it is an HTTP handler |
| `param`, `var` | parameters and *versioned* locals (`x = int(x)` really cuts the flow) |
| `field` | attributes on `self`, keyed by class |
| `call`, `arg`, `return` | a call site, its arguments (sinks are marked here), return values |
| `source` | attacker-controlled input: request fields, handler params |

Edges are `flow` (optionally carrying the classes a sanitizer neutralizes),
`call` / `ret` labelled with their call site, and `calls` for the call graph.

## Languages and frameworks

- **Python** (stdlib `ast`): Flask, FastAPI / Starlette, Django / DRF, Tornado,
  aiohttp, AWS Lambda; `src/` layouts; nested functions; work handed to job
  queues, threads and executors.
- **JavaScript / TypeScript** (tree-sitter): Express-style routers including
  handler factories and wrappers, `require` / `import` / `export`, callbacks,
  destructured `req`.
- **Go** (tree-sitter): `net/http` and router frameworks (gin, echo, chi,
  gorilla/mux) routes, request accessors as sources, interprocedural call/return.

## Precision

- **Matched calls and returns.** A call-site stack keeps `f(tainted)` from
  leaking into an unrelated `f("constant")`.
- **Per-class sanitizers.** `shlex.quote` stops command injection, not SQL
  injection.
- **Coerced inputs.** `int`-typed params and `<int:id>` converters cannot carry
  an injection payload, but still count for BOLA.
- **Authorization context.** Object lookups keyed by a client id are reported as
  BOLA candidates only when the query is not scoped to the caller and no
  ownership check follows. Route handlers guarded by a class-level
  policy (DRF `permission_classes` / `authentication_classes`, an enclosing-class auth
  marker) are recognized as authenticated, so a guarded lookup is not flagged as
  unauthenticated-reachable.

## Classes

SQL and NoSQL injection, command and code injection, SSTI, XPath injection,
path traversal, SSRF, unsafe deserialization, XXE, XSS, open redirect, LDAP
injection, ReDoS, prototype pollution (JS), mass assignment (API3) and BOLA
candidates (API1). The pattern hunter adds secrets, weak crypto, insecure
randomness, disabled JWT signature verification and misconfiguration.

Extend the catalog without code:

```json
{
  "sinks": [{"vclass": "sqli", "cwe": "CWE-89", "names": ["internal.dbx.raw_exec"], "args": [0]}],
  "sanitizers": [{"names": ["mylib.clean_html"], "classes": ["xss"]}]
}
```

```bash
offat-whitebox ./repo --specs specs.json
```

## AI on top of the graph

- **Graph-grounded triage.** The triager sees the proven hop-by-hop path, the
  route and its authorization context instead of a code snippet.
- **Graph-tool agent** (`--agent N`). A verifier with read-only tools
  (`get_function`, `callers`, `callees`, `read_lines`, `flows_into`) walks the
  code around each path, tries to refute it, and submits a verdict with a proof
  request. Repository content is treated as untrusted data. It runs against an Anthropic API key, **or with no key through the Claude Code / Codex CLI** (`--provider claude-code|codex`), which investigates the repository with its own file tools.
- **Spec inference** (`--infer-specs`). OFFAT lists the *taint frontier*, the
  unknown library calls that receive attacker data, and the model labels each
  one as a sink, sanitizer or plain propagator. The result is written to
  `inferred-specs.json` and fed back into the next run.

## Output

Every finding carries `evidence.path` (each hop's file, line and code), the
entry points and HTTP routes that reach it, and appears in SARIF as a
`codeFlow`, so GitHub code scanning renders the path. `--graph-out` exports the
whole graph as JSON and GraphML for Gephi, yEd or Neo4j.

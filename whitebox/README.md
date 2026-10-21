# offat-whitebox

The white-box (SAST) half of OFFAT-AI. A multi-stage source-code security
review modeled on the [security-harness](https://github.com/dmdhrumilmistry/security-harness)
workflow:

```
recon  ->  graph (code-graph taint)  +  hunt (patterns)  ->  chain  ->  verify (triage / agent)  ->  report
```

- **recon** — detect the tech stack, inventory dependency manifests, generate an
  SBOM (syft) and CVE findings (grype / trivy / osv-scanner) when installed.
- **graph** — the primary engine. Builds a code property graph of the repo
  (Python via `ast`; JavaScript/TypeScript, Go, Ruby, PHP and others via tree-sitter) in networkx,
  marks attacker-controlled **sources** (request fields, route-handler params,
  destructured `req`) and dangerous **sinks**, then proves source -> sink paths
  with an interprocedural, call/return-matched search. Every finding carries the
  hop-by-hop path, the entry point and the HTTP route that reaches it.
- **hunt** — a dependency-free regex hunter for non-flow classes (secrets, weak
  crypto, TLS-off, misconfig). Pattern hits in injection classes that the graph
  could not connect to a source are kept but demoted. semgrep is **opt-in**
  (`--semgrep`); it is not part of the default pipeline.
- **chain** — annotate co-located findings into simple attack paths.
- **verify** — the shared AI/heuristic triager, fed the proven path instead of a
  snippet; optionally a graph-tool **agent** (`--agent N`) that walks callers,
  callees and backward slices to refute or confirm, and emits a PoC request.
- **report** — JSON, JSONL, SARIF 2.1.0 (with `codeFlows`), Markdown and HTML.

## Code-graph engine

| | |
|---|---|
| Graph | networkx `MultiDiGraph`: functions, params, versioned locals, fields, call sites, args, returns, sources |
| Edges | `flow` (with per-class `sanitizes`), `call` / `ret` labelled by call site, `calls` (call graph) |
| Python | Flask, FastAPI/Starlette, Django/DRF, Tornado, aiohttp, AWS Lambda; `src/` layouts; nested functions; RQ/Celery/threads/executors (`enqueue(fn, x)`, `fn.delay(x)`, `Thread(target=fn)`) |
| Ruby/PHP/Java | profile-driven frontend: Rails/Sinatra `params`, PHP superglobals, Spring `@*Mapping` routes + annotated sources; best-effort catch-all for Kotlin/C#/Rust/Scala |
| Go | net/http, gin, echo, chi, gorilla/mux routes; request accessors as sources; interprocedural call/return; `strconv`/`filepath.Base` sanitizers |
| JS/TS | Express-style routers incl. handler factories and wrappers (`app.get(p, asyncHandler(login()))`), `require`/`import`/`export`, callbacks |
| Classes | sqli, nosqli, command/code injection, SSTI, path traversal, SSRF, deserialization, XXE, XSS, open redirect, LDAP, ReDoS, mass assignment (API3), BOLA candidates (API1, with ownership-check detection) |
| Precision | reaching definitions (`x = int(x)` kills taint), matched call/return, per-class sanitizers, type-coerced params (`int`, `<int:id>`) |

Extend the catalog without code: `--specs specs.json`
(`{"sinks": [{"vclass", "cwe", "names", "args"}], "sanitizers": [{"names", "classes"}]}`).

## AI features

- **Graph-grounded triage** — batched screening sees the proven path, routes and
  authz context, not an 800-char snippet.
- **Graph-tool agent** (`--agent N`) — re-verifies the top N graph findings with
  read-only tools (`get_function`, `callers`, `callees`, `read_lines`,
  `flows_into`) confined to the repo, then `submit_verdict` with a PoC request.
  Repository content is treated as untrusted data in the prompt.
- **Spec inference** (`--infer-specs`) — writes the *taint frontier* (unknown
  library calls that receive attacker data) and, with an API key, has the model
  label each callee as sink / sanitizer / propagator into `inferred-specs.json`,
  then re-runs with it. Tokens are spent once per API, not per finding.

## Usage

```bash
python -m offat_wb /path/to/repo                 # from the repo (no install)
offat-whitebox /path/to/repo --no-ai -o out/     # if installed

# hunt only specific classes
python -m offat_wb . --classes sqli,secrets,command_injection

# graph engine extras, AI agent on the 10 hottest flows, export the graph
pip install './whitebox[graph]'
offat-whitebox ./repo --agent 10 --infer-specs --graph-out -o out/
```

Enable AI triage with `OFFAT_AI_API_KEY` (see `../triager`).

## Tool integration

| Stage | Preferred | Alternatives | Fallback |
|---|---|---|---|
| SBOM | syft | — | manifest inventory |
| CVEs | grype | trivy, osv-scanner | skipped |
| Taint | built-in code graph (`[graph]` extra) | — | pattern hunter only |
| Hunt | built-in pattern hunter | semgrep `--config auto` (`--semgrep`, opt-in) | — |
| Trace | code graph | graft (only with `--no-graph`) | — |

Install the scanners to deepen results, e.g. `brew install syft grype`.

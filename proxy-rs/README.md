# OFFAT Intercepting Proxy (`offat-proxy`)

An intercepting HTTP(S) proxy for **authorized** API security testing, built to
feed the [OFFAT Bundle](../bundle/README.md) pipeline, with a **live terminal UI**
and an **inbuilt MCP server** so an AI agent can drive capture → map → test →
triage → report end to end.

Think of it as the "map from live traffic" front-end: point a client (browser,
mobile app, test suite) at the proxy, exercise the API, and every request/response
is captured, turned into `asm.endpoints` + `results` captures, and handed to the
same test-gen / engine / triage / reporter stages the rest of OFFAT already uses.

> **Authorized use only.** Passive capture records the traffic you route through
> it. *Active* behaviour — replay/fuzz, running the engine, and TLS interception —
> is gated on an explicit host **scope** and confirmation, and credentials are
> redacted from stored and exported data by default.

## Build

```bash
cd proxy-rs
cargo build --release            # -> target/release/offat-proxy
# or: make proxy   (from the repo root)
```

The `mitm` feature (TLS interception) is on by default at build time but **off at
runtime** until you pass `--mitm` and install the generated CA. Build without it
(`--no-default-features`) for a capture-only proxy with a smaller surface.

## Use

### 1. Capture live traffic into a Bundle

```bash
# loopback-only, in-scope host, persist sanitized flows to ~/.offat/proxy/flows.jsonl
offat-proxy run --scope api.your-authorized-target.test --persist

# point your client at http://127.0.0.1:8080, exercise the API, then:
offat-proxy export --out app.offat.json
```

`export` produces a schema-valid Bundle (`asm.endpoints` with templated paths like
`/users/{id}`, plus `results.executions` captures). Feed it straight into
`offat-platform test-gen` / `offat-engine`.

### 2. Drive the whole pipeline from an AI agent (MCP)

```bash
offat-proxy mcp --scope api.your-authorized-target.test
```

This runs the proxy **and** an MCP server on stdio. Register it with any MCP
client, e.g. Claude Code:

```json
{
  "mcpServers": {
    "offat-proxy": {
      "command": "offat-proxy",
      "args": ["mcp", "--scope", "api.your-authorized-target.test"]
    }
  }
}
```

Tools exposed:

| Tool | What it does |
|---|---|
| `proxy_status` | listen addr, flow count, scope, mitm/redaction state |
| `set_scope` | set the authorized host allowlist (gates all active actions) |
| `list_flows` / `get_flow` | browse captured exchanges (redacted); `list_flows` takes a `filter` expression |
| `get_rules` / `set_rules` / `test_expr` | manage live rules and validate/evaluate expressions |
| `export_bundle` | write captured flows to an OFFAT Bundle |
| `replay_flow` | re-send a captured request with overrides (Repeater) |
| `fuzz_flow` | iterate payloads over a query/header/body insertion point (Intruder) |
| `ca_cert` | the CA PEM to install into a test trust store (mitm) |
| `open_browser` | launch a browser wired to the proxy, pin-trusting the CA (mitm) |
| `run_platform` | run `offat-platform` (map/PRG/threat-model/test-gen/triage) |
| `run_engine` | execute a Bundle's test plan with `offat-engine` |

`run_platform` / `run_engine` shell out to the existing tools (argv, never a
shell), so **AI routing stays in `offat_triage`** — the proxy never calls a model
API directly.

### 3. Rules: live block / allow / drop / tag / match-and-replace

`offat-proxy` has a small, safe expression interpreter ("bambdas") that matches
flows and acts on them live — and the same expressions filter captured history.
It is an interpreter over a fixed set of flow fields, not an eval of arbitrary
code: no I/O, no host access, nothing executes.

```bash
offat-proxy run --scope api.example.test \
  --rule 'block respond 403 "no" when path contains "/admin" && header["x-role"] != "admin"' \
  --rule 'tag "login" when path endswith "/login"' \
  --rule 'replace-resp "secret" -> "<redacted>" when status == 200' \
  --rule 'set-req-header "X-OFFAT: 1" when in_scope'

# or load a file of rules, one per line:
offat-proxy run --rules myrules.txt --scope api.example.test

# allowlist mode: block anything whose host isn't in --scope
offat-proxy run --scope api.example.test --block-out-of-scope
```

**Actions:** `block [respond <status> "body"]`, `drop`, `allow`, `tag "name"`,
`set-req-header "Name: v"`, `set-resp-header "Name: v"`,
`replace-req "find" -> "repl"`, `replace-resp "find" -> "repl"` — each followed by
an optional `when <expr>`.

**Expression language** (also used as history filters): fields `method`, `host`,
`path`, `url`, `scheme`, `query`, `body`, `status`, `content_type`, `in_scope`,
`intercepted`, `tags`, `resp_body`, and indexed `header["name"]`,
`resp_header["name"]`, `query["name"]`; operators `==`, `!=`, `contains`,
`startswith`, `endswith`, `matches` (glob), `<`, `>`, `<=`, `>=`; combine with
`&&`, `||`, `!`, parentheses.

Agents get `get_rules`, `set_rules`, `test_expr`, and a `filter` argument on
`list_flows` over MCP.

### 4. Launch a browser already wired to the proxy

```bash
# starts the proxy AND opens a browser pointed at it, trusting the CA automatically
offat-proxy run --mitm --scope api.your-authorized-target.test --open-browser
```

`--open-browser` finds a Chromium-family browser (Chrome, Chromium, Edge, Brave, or
Playwright's bundled Chromium) and launches it in a **dedicated throwaway profile**
pointed at the proxy. When MITM is on, it passes Chrome's
`--ignore-certificate-errors-spki-list=<CA SPKI hash>` so the browser trusts
certificates minted by *this* CA **only** — never a blanket "ignore all cert
errors", and never touching your real browser's trust store. When MITM is off,
HTTPS tunnels through untouched and the real certificate is validated normally.

Flags: `--browser <chrome|chromium|edge|brave|path>`, `--browser-profile <dir>`,
`--browser-url <url>`, `--browser-headless`, `--browser-no-sandbox` (for
containers/CI). The agent can do the same with the `open_browser` MCP tool.

### 5. Live terminal UI (`offat-proxy tui`)

```bash
offat-proxy tui --scope api.example.test
```

Runs the proxy with a built-in terminal UI (ratatui): a live flow list (colored by
status, marked for scope, annotated with tags), a detail pane showing the selected
request/response, and a header with listen address, counts, scope, MITM/redaction
state and rule count. Press `/` to filter with the same expression language as the
rules engine (e.g. `status >= 500 && path contains "/api"`).

```
 offat-proxy  listen=127.0.0.1:8080  flows=12/37  scope=api.example.test  mitm=on  redact=on  rules=3
 ┌flows───────────────────────┐┌detail──────────────────────────────┐
 > *GET  200 api.example.test/users/1   REQUEST
   *POST 500 api.example.test/login [..] GET https://api.example.test/users/1
   ...                                   RESPONSE status=200 ...
 j/k move  Tab focus  / filter  c clear  g/G top/bottom  f/b scroll  ? help  q quit
```

Keys: `j`/`k` move, `Tab` switch focus, `/` filter, `c` clear, `g`/`G` first/last,
`f`/`b` scroll detail, `?` help, `q` quit.

### 6. TLS interception (optional)

```bash
offat-proxy ca            # prints the local CA (PEM); install it into a TEST profile only
offat-proxy run --mitm --scope api.your-authorized-target.test
```

With `--mitm`, in-scope `CONNECT` tunnels are terminated with a leaf certificate
minted by a locally generated CA, so HTTPS exchanges are captured in plaintext.
Out-of-scope tunnels stay opaque (metadata only — no TLS is broken).

## Security model

- **Not an open relay.** Binds `127.0.0.1` by default; a non-loopback bind needs
  `--allow-public` *and* `--proxy-auth user:pass`.
- **Scope-gated active actions.** Replay, fuzz, the engine and MITM all refuse
  hosts outside `--scope`. An empty scope means passive capture only.
- **Credential redaction** (`Authorization`, `Cookie`, `Set-Cookie`, common token
  headers) on everything persisted or exported, unless `--no-redact`.
- **Local, owner-only CA.** The CA private key is generated locally, stored
  `0600` under the state dir, and never transmitted. Install the CA cert only into
  a throwaway test trust store for targets you are authorized to assess.
- **Bounded memory.** Ring-buffered flows (`--max-flows`) and capped bodies
  (`--body-cap`).
- **Untrusted by construction.** Captured content is forwarded and recorded, never
  interpreted or executed; upstream TLS is verified unless `--insecure-upstream`.
- **Rules are sandboxed.** The rule/filter language is an interpreter over fixed
  flow fields — no code execution, I/O, or host access.

## Protocols

| Protocol | Handling |
|---|---|
| HTTP/1.1 | captured (and MITM-decrypted over TLS) |
| HTTP/2 | negotiated to the upstream; captured |
| HTTPS (TLS) | intercepted and captured with `--mitm`; otherwise tunneled opaquely |
| WebSocket | handshake captured; frames relayed (see `docs/proxy.md`) |
| gRPC / HTTP/3 / other TCP+TLS | tunneled opaquely via `CONNECT` (metadata recorded) |

The `offat-engine` executor covers full HTTP/2, WebSocket and gRPC (and opt-in
HTTP/3) when running a test plan.

## Flags

See `offat-proxy --help`. Common ones: `--listen`, `--scope`, `--exclude`,
`--mitm`, `--no-redact`, `--insecure-upstream`, `--allow-public`, `--proxy-auth`,
`--state-dir`, `--persist`, `--body-cap`, `--max-flows`.

## Tests

```bash
cargo test            # unit tests (scope, redaction, bundle mapping, CA, MCP helpers)
```

End-to-end checks (capture→export→schema-validate, the MCP loop, and TLS
interception) live in the development notes; they run a throwaway local origin and
validate exported Bundles against `bundle/offat_bundle/schema`.

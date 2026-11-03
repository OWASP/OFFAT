# OFFAT Intercepting Proxy (`offat-proxy`)

An intercepting HTTP(S) proxy for **authorized** API security testing, built to
feed the [OFFAT Bundle](../bundle/README.md) pipeline, with an **inbuilt MCP
server** so an AI agent can drive capture → map → test → triage → report end to
end.

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
| `list_flows` / `get_flow` | browse captured exchanges (redacted) |
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

### 3. Launch a browser already wired to the proxy

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

### 4. TLS interception (optional)

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

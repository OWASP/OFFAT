---
title: Intercepting proxy + MCP
section: Integrate
nav_order: 2
description: Capture live API traffic into a Bundle with the OFFAT intercepting proxy, and drive the whole pipeline from an AI agent over MCP.
---

# Intercepting proxy + MCP (`offat-proxy`)

OFFAT maps an API from source. The **intercepting proxy** adds the other way in:
map it from **live traffic**. Point a client at the proxy, exercise the API, and
every exchange is captured and turned into the same [Bundle](../bundle/README.md)
the rest of the pipeline consumes — so test-gen, the engine, triage and the
reporter all work on proxy-captured traffic unchanged.

It also ships an **inbuilt MCP server**, so an MCP-speaking agent (Claude Code,
etc.) can run the whole loop end to end: set an authorized scope, capture, export a
Bundle, run the source-aware pipeline and the Rust engine, and replay or fuzz
individual requests.

> **Authorized use only.** Passive capture records the traffic you route through
> the proxy. Active behaviour — replay/fuzz, running the engine, and TLS
> interception — is refused for hosts outside an explicit `--scope`, and
> credentials are redacted from stored and exported data by default. This mirrors
> the engine's `--yes` gate: only test systems you own or are permitted to assess.

## Where it sits in the pipeline

```
          (source)  map ─────────────┐
                                      ├─> Bundle ─> test-gen ─> execute ─> triage ─> report
   (live traffic)  offat-proxy ───────┘
```

The proxy writes the `asm.endpoints` and `results` sections. Observed paths are
templated (`/users/1` and `/users/2` collapse to `/users/{id}`) and query/path
parameters are inferred, so test-gen has real endpoints and parameters to work
from.

## Capture → Bundle

```bash
make proxy                       # build -> proxy-rs/target/release/offat-proxy

offat-proxy run --scope api.your-authorized-target.test --persist
# point the client at http://127.0.0.1:8080, exercise the API, then:
offat-proxy export --out app.offat.json

# hand off to the existing pipeline
offat-platform test-gen app.offat.json
offat-engine --bundle app.offat.json --url https://api.your-authorized-target.test --yes
```

## Drive it from an agent (MCP)

```bash
offat-proxy mcp --scope api.your-authorized-target.test
```

runs the proxy and an MCP server on stdio in one process. Register it with an MCP
client:

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

Tools: `proxy_status`, `set_scope`, `list_flows`, `get_flow`, `export_bundle`,
`replay_flow` (Repeater), `fuzz_flow` (Intruder), `ca_cert`, `run_platform`,
`run_engine`. The last two shell out to the existing tools with an argv array (no
shell), so **model calls stay inside `offat_triage`** — the proxy never talks to a
model API itself, and captured target content is always treated as untrusted data.

## Launch a browser, zero setup

```bash
offat-proxy run --mitm --scope api.your-authorized-target.test --open-browser
```

`--open-browser` finds a Chromium-family browser (or Playwright's bundled
Chromium) and opens it in a dedicated throwaway profile already pointed at the
proxy. With MITM on, it trusts the CA automatically via Chrome's
`--ignore-certificate-errors-spki-list=<CA SPKI hash>` — scoped to *this* CA only,
never a blanket "ignore all certificate errors", and never touching your real
browser's trust store. Pick the browser with `--browser`, the landing page with
`--browser-url`, and add `--browser-headless` / `--browser-no-sandbox` for
containers. Agents can do the same through the `open_browser` MCP tool.

## TLS interception

```bash
offat-proxy ca              # prints the local CA (PEM) — install into a TEST profile only
offat-proxy run --mitm --scope api.your-authorized-target.test
```

In-scope `CONNECT` tunnels are terminated with a leaf certificate minted by a
locally generated CA, so HTTPS is captured as plaintext. Out-of-scope tunnels stay
opaque — no TLS is broken. The CA private key is generated locally, stored
owner-only under the state dir, and never leaves the machine; install the CA
certificate only into a dedicated throwaway trust store.

## Security defaults

| Default | Why |
|---|---|
| binds `127.0.0.1` | not an open relay; a public bind needs `--allow-public` + `--proxy-auth` |
| empty active scope | passive capture only until you authorize hosts with `--scope` |
| redaction on | `Authorization` / `Cookie` / `Set-Cookie` / token headers never hit disk or a Bundle |
| MITM off | no TLS is intercepted until `--mitm` and an installed CA |
| upstream TLS verified | unless `--insecure-upstream` (loud warning) |
| bounded memory | ring-buffered flows and capped bodies |

See [`proxy-rs/README.md`](https://github.com/OWASP/OFFAT/tree/dev/proxy-rs) for
the full flag reference.

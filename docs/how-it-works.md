---
title: How it works
nav_order: 4
description: "The OFFAT-AI platform pipeline, the Bundle contract, and the Rust engine."
---

# How it works
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

OFFAT-AI is a staged platform. Every stage reads and writes one canonical
document - the **OFFAT Bundle** (`*.offat.json`) - so the pipeline composes
cleanly and each stage is a pure transform over the file.

```
 source ─┐
 spec   ─┤ 1. MAP                 -> endpoints, params, sinks/sources, auth, protocols
 traffic─┘
          2. PARAM RELATION GRAPH -> producer -> consumer param edges
          3. THREAT MODEL         -> STRIDE threats, OWASP API Top 10 + CWE, DFD
          4. TEST-GEN             -> test plan (injection + multi-step + identity-aware)
          5. EXECUTE (Rust)       -> request/response captures
          6. TRIAGE               -> canonical findings + verdict/confidence
          7. REPORT               -> SARIF / HTML / Markdown / compliance / PDF
```

## The stages

1. **Map** - parse source and any OpenAPI/Swagger spec into endpoints (with
   params and response fields) and a sink/source inventory; build the structural
   graph with `graft` when present.
2. **Parameter relation graph (PRG)** - link producers (an endpoint's response
   fields) to consumers (another endpoint's request params) by name, resource, or
   type, so cases can chain across endpoints and replay a foreign id for BOLA.
3. **Threat model** - derive STRIDE threats, the OWASP API Top 10 (2023) + CWE
   mapping, a likelihood x impact risk score, and a Mermaid data-flow diagram.
4. **Test-gen** - instantiate injection vectors per applicable param, multi-step
   chains from the PRG, and, with `--identities`, access-control / auth /
   business-logic cases. Optional AI payload augmentation.
5. **Execute** - the Rust engine sends each case (and, for authz cases, a
   differential baseline as the authorized identity), capturing status, body, and
   timing.
6. **Triage** - detect findings (error signatures, reflection, timing, status,
   authorization differentials), attach the threat mapping, and triage with AI or
   the offline heuristic.
7. **Report** - SARIF 2.1.0, Markdown, a self-contained HTML report (with the
   DFD), an OWASP API Top 10 / ASVS compliance report, and best-effort PDF.
   `--fail-on <severity>` exits non-zero when an actionable finding survives.

## The Bundle

One JSON document. `schema_version` and `meta` are required; every other
section is optional, so a partial Bundle produced after an early stage is still
valid and later stages fill in their sections.

| Section | Written by | Holds |
|---|---|---|
| `meta` | every stage | target, run id, tool/versions, timestamps |
| `asm` | map | endpoints (method, path, protocol, params, auth, responses) |
| `inventory` | map | sinks and sources (class, symbol, file:line, CWE) |
| `prg` | PRG | param nodes + producer -> consumer edges |
| `threat_model` | threat model | assets, boundaries, data flows, ranked threats, DFD |
| `test_plan` | test-gen | test cases (endpoint/param, technique, payload, protocol) |
| `results` | engine | request/response captures with timing and protocol |
| `findings` | triage | canonical findings + threat refs + verdict/confidence |
| `summary` | any writer | rolled-up counts (severity, verdict, OWASP API, totals) |

The authoritative schema is
[`bundle/offat_bundle/schema/offat-bundle-v1.schema.json`](https://github.com/OWASP/OFFAT/blob/dev/bundle/offat_bundle/schema/offat-bundle-v1.schema.json).

## The execution engine (Rust)

The executor is an I/O-bound concurrent client where performance, memory safety,
and a single static binary matter. `tokio` + `reqwest` (rustls) drive HTTP/1.1 +
HTTP/2; `tokio-tungstenite` drives WebSocket (ws/wss); `tonic` drives gRPC with a
schema-less bytes codec (no `.proto` compilation); HTTP/3 + QUIC is an opt-in
build feature (reqwest http3 -> h3 + quinn). Each case carries a `protocol` and
is dispatched to the matching driver; a protocol the binary was not built with is
recorded as skipped so the Bundle stays complete.

## What it tests

**Live (test-gen + engine):** SQLi (error / boolean / reflection), NoSQLi,
command injection, SSTI, LDAP injection, reflected XSS, path traversal, SSRF,
open redirect, XXE - plus, with `--identities`, BOLA (API1), broken
authentication (API2), BFLA and RBAC (API5), and business-logic value tampering +
privilege-field escalation (API6). WebSocket endpoints get a no-credential
handshake probe and message-content injection; gRPC methods get an
unauthenticated-invocation probe and an unprivileged BFLA invocation judged by the
returned `grpc-status`.

**Source (white-box / gray-box):** hardcoded secrets, injection sinks, unsafe
deserialization, weak crypto / TLS-off, DOM XSS sinks, SSRF sinks, misconfig, and
vulnerable dependencies (SCA), plus anything `semgrep --config auto` finds. See
[Source modes](source-modes.html).

## Threat mapping

Every finding is classified against a shared taxonomy - the OWASP API Security
Top 10 (2023), the OWASP Top 10 (2021) web categories, and a primary CWE. Reports
include a threat-mapping summary and a compliance report that maps coverage to the
OWASP API Top 10 with ASVS notes.

## Design docs

For contributors, the full design and the shared finding schema live in the repo:

- [Platform design](https://github.com/OWASP/OFFAT/blob/dev/docs/platform.md)
- [Architecture](https://github.com/OWASP/OFFAT/blob/dev/docs/architecture.md)

# OFFAT-AI Platform (v2) - design

This document describes the staged platform OFFAT-AI is evolving into, and the
single data contract that holds it together. It is the reference for the phased
build; each phase ships independently and writes into one shared file.

> Status: **all phases (0-7) landed** (P4 engine covers HTTP/1.1 + HTTP/2; more
> protocols are the documented next increment). The Bundle contract
> ([`bundle/`](../bundle)); the mapping, PRG, threat-modeling, test-generation and
> consolidation+triage stages ([`platform/`](../platform)); the Rust execution
> engine ([`engine-rs/`](../engine-rs)); the reporter ([`reporter/`](../reporter));
> and the visualizer ([`viz/`](../viz)). The pipeline runs `map -> prg ->
> threat-model -> test-gen -> execute -> triage -> report` over one Bundle, which
> the visualizer imports.

## Principle: contracts over components

A multi-tool pipeline only works if every stage reads and writes the same
versioned structure. The platform defines one canonical interchange file - the
**OFFAT Bundle** (`*.offat.json`) - and makes every tool a pure transform over
it. The Bundle is also the import/export format for the reporter and the
visualizer, and the "single file" handed between stages.

```
 source ─┐
 spec   ─┤ 1. MAP (graft + AI + spec)          -> ASM: endpoints, params, sinks, sources, auth, protocols
 traffic─┘
          2. PARAM RELATION GRAPH (PRG)         -> producer->consumer param edges (X output feeds Y input)
          3. THREAT MODEL (STRIDE + OWASP/ASVS) -> DFD, trust boundaries, ranked threats
          4. TEST-CASE GEN (KB rules + AI)      -> test plan (DAST multi-step + SAST checks)
          5. EXECUTION ENGINE (Rust)            -> captures [HTTP/1.1,2,3/QUIC, gRPC, WS, SSE, GraphQL]
          6. CONSOLIDATE + AI TRIAGE            -> canonical findings + confidence
                         v
              +------ one BUNDLE file ------+   (asm + prg + threat_model + test_plan + results + findings)
              v                             v
     7. REPORTER (SARIF/HTML/MD/PDF/   8. VISUALIZER (static web app: attack surface
        compliance: API Top 10/ASVS)      + PRG + threat model; import/export bundle)
```

## Locked decisions

| Decision | Choice | Rationale |
|---|---|---|
| Execution engine language | **Rust** | Best-in-class HTTP/3 (quinn/h3), top async perf + memory safety for a fuzzer, single static binary. |
| Build sequencing | **Backbone-first** | Contracts -> mapping -> threat model -> test-gen -> engine -> triage -> reporter -> viz. Each phase ships and feeds the next. |
| Visualization | **Static SPA** | Browser-only app that imports/exports the Bundle; nothing to operate; a backend can be added later. |
| First delivery | **Design doc + P0 contracts** | Lock the architecture and the Bundle schema before heavier phases. |

## The Bundle

One JSON document. `schema_version` and `meta` are required; every other section
is optional, so a partial Bundle produced after an early phase is still valid and
later phases fill in their sections. The authoritative schema is
[`bundle/offat_bundle/schema/offat-bundle-v1.schema.json`](../bundle/offat_bundle/schema/offat-bundle-v1.schema.json);
the Python helpers in [`bundle/offat_bundle`](../bundle/offat_bundle) build,
validate, load, save and merge it.

| Section | Written by | Holds |
|---|---|---|
| `meta` | every stage (appends to `meta.stages`) | target, run id, tool/versions, timestamps |
| `asm` | map | endpoints (method, path, protocol, params, auth, responses, source) |
| `inventory` | map | sinks and sources (class, symbol, file:line, CWE) |
| `prg` | PRG | param nodes + producer->consumer edges (confidence, basis) |
| `threat_model` | threat modeling | assets, trust boundaries, data flows, ranked threats, Mermaid DFD |
| `test_plan` | test-gen | test cases (endpoint/param, technique, payload, protocol, origin, chain) |
| `results` | engine | request/response captures with timing and protocol |
| `findings` | triage | canonical findings + threat refs + triage verdict/confidence |
| `summary` | any writer | rolled-up counts (severity, verdict, OWASP API, totals) |

Identifiers are stable, prefixed, content-derived where possible (`ep-`, `sink-`,
`src-`, `prg-`, `th-`, `tc-`, `ex-`) so sections cross-reference by id and merges
are idempotent.

### Parameter Relation Graph (PRG)

The PRG is the backbone of chaining and a first-class, exportable graph. Nodes are
typed param refs: consumers `(endpoint, location, name, type)` and producers
`(endpoint, response-field)`. An edge links a producer to a consumer when names,
resources or types match - e.g. `POST /users` returns `id`, so `GET /users/{id}`
can be seeded from it. Each edge carries a confidence and a basis (`exact-name`,
`resource-id`, `type-semantic`). The PRG seeds real identifiers for multi-step
test cases, powers BOLA/IDOR (replay a foreign id), and is rendered by the
visualizer. It generalizes the existing Go `dast/internal/graph` package.

## Components

| # | Component | Language | Reuses |
|---|---|---|---|
| 1 | Mapping | Python | `offat_gb.graph_map` + graft + spec parsing + AI classification |
| 2 | PRG builder | Go/Python | `dast/internal/graph` producer->consumer heuristics |
| 3 | Threat modeling | Python | `offat_triage.taxonomy` (OWASP API/Web + CWE) |
| 4 | Test-case generation | Python | KB vectors + `offat_triage` batched/cached AI |
| 5 | Execution engine | **Rust** | new; tokio + hyper/reqwest (H1/H2), quinn+h3 (H3/QUIC), tonic (gRPC), tungstenite (WS), SSE, GraphQL |
| 6 | Consolidation + triage | Python | `offat_triage.tiered_triage` |
| 7 | Reporter | Go | bundle -> SARIF 2.1.0, HTML, Markdown, PDF, compliance (OWASP API Top 10, ASVS) |
| 8 | Visualizer | Web (static SPA) | React + a graph lib; imports/exports the Bundle |

## Phasing

- [x] **P0 Contracts** - Bundle schema + Python helpers (build/validate/load/save/merge) + tests.
- [x] **P1 Mapping + PRG** - `offat-platform map` writes `asm`, `inventory` and `prg` into the Bundle (endpoints with params + response fields; sinks/sources; producer->consumer edges).
- [x] **P2 Threat model** - `offat-platform threat-model` writes `threat_model` (assets, trust boundaries, data flows, STRIDE threats mapped to OWASP API + CWE with likelihood x impact risk, and a Mermaid DFD).
- [x] **P3 Test-gen** - `offat-platform test-gen` writes `test_plan`: meaningful rule-based cases (vectors matched to params by location + name hints), multi-step chains seeded from the PRG, BOLA/IDOR cases on id path params, and optional `--ai` payload augmentation.
- [~] **P4 Rust engine** - `offat-engine` ([`engine-rs/`](../engine-rs)) reads the `test_plan`, executes against an authorized target and writes `results`. **HTTP/1.1 + HTTP/2 implemented**; gRPC (tonic), WebSocket (tungstenite) and HTTP/3/QUIC (quinn + h3) are the next protocol increments (recognized and recorded as skipped until wired).
- [x] **P5 Consolidate + triage** - `offat-platform triage` detects DAST findings from `results` (signature/reflection/status heuristics), folds in SAST sinks, attaches the OWASP/CWE threat mapping, triages with the shared tiered triager, and writes `findings` + `summary` (with `--fail-on`).
- [x] **P6 Reporter** - `offat-report` ([`reporter/`](../reporter)) renders a Bundle into SARIF 2.1.0, Markdown, a self-contained HTML report (with the threat-model DFD), an OWASP API Top 10 / ASVS compliance report, and best-effort PDF.
- [x] **P7 Visualizer** - [`viz/`](../viz): a dependency-free static web app that imports/exports the Bundle and renders the attack surface, the PRG (inline SVG), the threat model (DFD + ranked threats) and filterable findings.

Each phase is independently shippable and leaves the repo green.

## Authorization

Unchanged from the rest of OFFAT-AI: the execution engine sends real traffic and
is for targets you own or are authorized to test; the static pipeline is for code
you own. The platform never exfiltrates source or findings to third parties.

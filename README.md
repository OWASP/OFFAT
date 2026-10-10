# OFFAT-AI

**AI-augmented API pentesting - a Bundle-driven platform.**

OFFAT-AI extends [OWASP OFFAT](https://github.com/OWASP/offat) (the OFFensive Api
Tester) into a staged platform. Every stage reads and writes one canonical
[Bundle](bundle/README.md) file, so the pipeline composes cleanly:

```
map  ->  parameter relation graph  ->  threat model  ->  test-gen  ->  execute  ->  triage  ->  report
                                                                  (Rust engine)      (AI/heuristic)
```

- **Map** the attack surface from source: endpoints (decorator routes **and**
  OpenAPI/Swagger specs, with params + response fields), sinks and sources, via
  `graft` when present.
- **Parameter relation graph (PRG)** links an endpoint's response fields
  (producers) to another endpoint's request params (consumers), so a later stage
  can seed Y's input from X's output - and replay foreign identifiers for BOLA.
- **Threat model** - STRIDE threats mapped to the OWASP API Top 10 (2023) + CWE
  with likelihood x impact risk, plus a Mermaid data-flow diagram.
- **Test-gen** - injection vectors matched to params, multi-step chains from the
  PRG, and (with `--identities`) **BOLA / BFLA / RBAC / broken-auth /
  business-logic** cases. Optional AI augmentation.
- **Execute** - a **Rust engine** sends the requests (HTTP/1.1 + HTTP/2),
  multi-identity with a differential baseline, and captures every response.
- **Triage** - detect findings, attach the threat mapping, and triage with a
  token-disciplined AI triager (cached, batched, model-tiered) or a deterministic
  offline heuristic - backed by an **Anthropic API key**, a local **Claude Code**
  / **Codex** CLI, or nothing at all.
- **Report** - SARIF 2.1.0, Markdown, a self-contained HTML report (with the DFD),
  an OWASP API Top 10 / ASVS compliance report, and best-effort PDF. A static
  **visualizer** imports the Bundle to explore it.

Two source-only modes reuse the same libraries and Bundle: **white-box** (SAST)
and **gray-box** (SAST fused with a graft-mapped endpoint surface, AI-judged by
reachability, no live traffic).

> **Authorized use only.** The execution engine sends real attack traffic (it
> requires `--yes`); the source modes are for code you own. Only test systems and
> code you own or are explicitly authorized to assess.

---

## Architecture

The platform is a set of focused tools connected by one canonical Bundle. See
[`docs/platform.md`](docs/platform.md) for the full design and
[`docs/architecture.md`](docs/architecture.md) for the shared finding schema.

```
 source --> map (graft + spec) --> asm + inventory + PRG --> threat model --> test plan
                                                                                   |
   report  <-- triage  <-- results  <-- Rust engine (execute) <------------- test plan
   (SARIF/HTML/MD/compliance/PDF)                                      one BUNDLE file
                                                                                   |
                                                                 static visualizer (import/export)
```

## Repository layout

| Path | What |
|---|---|
| `bundle/` | Canonical interchange document (`offat-bundle`) - the platform's data contract |
| `platform/` | Platform orchestrator (`offat-platform`) - map, PRG, threat-model, test-gen (incl. BOLA/BFLA/RBAC/auth/business-logic via `--identities`), triage |
| `engine-rs/` | Rust execution engine (`offat-engine`) - request executor over the Bundle |
| `reporter/` | Reporter (`offat-report`) - Bundle -> SARIF/HTML/Markdown/compliance/PDF |
| `viz/` | Static visualizer - import a Bundle; view attack surface, PRG, threat model, findings |
| `whitebox/` | White-box SAST pipeline + hunters (`offat-whitebox`; also a platform library) |
| `graybox/` | Gray-box pipeline + graft endpoint mapping/reachability (`offat-graybox`; also a platform library) |
| `triager/` | Shared AI/heuristic triager + threat taxonomy (`offat-triage`) |
| `skills/`, `commands/`, `agents/`, `.claude-plugin/` | Claude Code plugin |
| `examples/` | Vulnerable code fixture + sample identities file |
| `docker/`, `Makefile`, `.github/` | Packaging & CI |

## Quick start

```bash
# install the platform and its libraries
pip install ./bundle ./triager ./whitebox ./graybox ./platform ./reporter
# build the execution engine (Rust 1.88+)
make engine        # -> engine-rs/target/release/offat-engine
```

### Full pipeline against a live API

```bash
# 1. map the attack surface + PRG + threat model (from source and/or a spec)
offat-platform map /path/to/your/repo --threat-model -o app.offat.json

# 2. generate the test plan (add --identities to enable BOLA/BFLA/RBAC/auth tests)
offat-platform test-gen app.offat.json --identities examples/identities.example.json

# 3. execute against an authorized target (sends real traffic; --yes required)
offat-engine --bundle app.offat.json --url https://api.your-authorized-target.example \
  --identities examples/identities.example.json --yes

# 4. consolidate + triage, then render reports
offat-platform triage app.offat.json --fail-on high
offat-report app.offat.json -o reports --formats all
```

`--identities` (name, role, `headers`, `owns`) unlocks access-control and auth
tests; credentials stay in that file and never enter the Bundle. See
[`platform/README.md`](platform/README.md) and
[`engine-rs/README.md`](engine-rs/README.md).

### White-box (SAST) - source only

```bash
offat-whitebox /path/to/your/repo --no-ai            # heuristic; drop --no-ai for AI triage
```

### Gray-box (source + endpoint surface, AI reachability)

```bash
offat-graybox /path/to/your/repo --fail-on high      # maps endpoints, judges by reachability
```

See [`docs/whitebox.md`](docs/whitebox.md) and [`docs/graybox.md`](docs/graybox.md).

### Re-triage an existing findings file

```bash
offat-triage findings.json --provider claude-code    # add/refresh verdicts
```

### Visualize a Bundle

```bash
python -m http.server -d viz 8080                    # open http://localhost:8080, import *.offat.json
```

### As a Claude Code plugin

```
/plugin marketplace add dmdhrumilmistry/offat-ai
/plugin install offat-ai
/offat-scan review /path/to/repo and test https://api.example.com
```

Skills: `offat-whitebox`, `offat-graybox`, `offat-triage`; agent: `offat-verifier`.

## AI triage backends

The triager picks a backend automatically, or force one with `--provider` /
`OFFAT_AI_PROVIDER`:

| Provider | How | Needs |
|---|---|---|
| `anthropic` | Anthropic Messages API | `OFFAT_AI_API_KEY` (or `ANTHROPIC_API_KEY`) |
| `claude-code` | `claude -p` (Claude Code CLI) | the `claude` CLI, already signed in |
| `codex` | `codex exec` (OpenAI Codex CLI) | the `codex` CLI, already signed in |
| `heuristic` | deterministic, offline | nothing |

`auto` (default) prefers an API key, then Claude Code, then Codex, then the
heuristic. Token discipline: verdicts are cached by content hash and screened by a
cheap model before a strong model verifies the confirmed/likely subset. Overrides:
`OFFAT_AI_MODEL`, `OFFAT_SCREEN_MODEL`, `OFFAT_VERIFY_MODEL`, `OFFAT_AI_CLAUDE_CMD`
/ `OFFAT_AI_CODEX_CMD`.

## What it tests

**Live (via test-gen + engine):** SQLi (error/boolean/reflection), NoSQLi, command
injection, SSTI, LDAP injection, reflected XSS, path traversal, SSRF, open
redirect, XXE - plus, with `--identities`, **BOLA** (API1), **broken
authentication** (API2), **BFLA** and **RBAC** (API5), and **business-logic**
value tampering + privilege-field escalation (API6).

**Source (white-box / gray-box):** hardcoded secrets, injection sinks, unsafe
deserialization, weak crypto / TLS-off, DOM XSS sinks, SSRF sinks, misconfig, and
vulnerable dependencies (SCA), plus anything `semgrep --config auto` finds. The
gray-box mode adds reachability: which exposed endpoint reaches each sink.

## How the pipeline works

1. **Map** - parse source and any OpenAPI/Swagger spec into endpoints (with params
   and response fields) and a sink/source inventory; build the structural graph
   with `graft` when present.
2. **PRG** - link producers (response fields) to consumers (request params) by
   name / resource / type, so cases can chain across endpoints and replay foreign
   ids for BOLA.
3. **Threat model** - derive STRIDE threats, OWASP API Top 10 + CWE mapping, a
   risk score, and a Mermaid DFD.
4. **Test-gen** - instantiate injection vectors per applicable param, multi-step
   chains from the PRG, and identity-aware access-control / auth / business-logic
   cases.
5. **Execute** - the Rust engine sends each case (and, for authz cases, a
   differential baseline as the authorized identity), capturing status, body and
   timing.
6. **Triage** - detect findings (error signatures, reflection, timing, status,
   authorization differentials), attach the threat mapping, and triage with AI or
   the offline heuristic.
7. **Report** - SARIF, Markdown, HTML (with the DFD), compliance, PDF; `--fail-on
   <severity>` exits non-zero when an actionable finding survives triage.

## Threat mapping

Every finding is classified against a shared taxonomy - the **OWASP API Security
Top 10 (2023)**, the **OWASP Top 10 (2021)** web categories, and a primary **CWE**
(each with names) - via `offat_triage.taxonomy`. Reports include a Threat mapping
summary (findings per OWASP API Top 10 category) and the compliance report maps
coverage to the OWASP API Top 10 with ASVS notes.

## Benchmarks

Validated offline against public deliberately-vulnerable apps, exercising endpoint
mapping, detection, reachability and threat mapping (heuristic triage, no tokens).
Pinned revisions:

| App | Stack | Revision |
|---|---|---|
| [VAmPI](https://github.com/erev0s/VAmPI) | Python / Flask + connexion (OpenAPI) | `f16052d` |
| [DSVW](https://github.com/stamparm/DSVW) | Python / custom WSGI | `9ca3c9a` |
| [vulpy](https://github.com/fportantier/vulpy) | Python / Flask | `5249cc8` |

**Gray-box** (endpoints mapped from source, findings linked by reachability):

| App | Endpoints | Findings | Reachable | Crit/High/Med/Low | OWASP API cats |
|---|--:|--:|--:|:--:|--:|
| VAmPI | 14 | 15 | 0 | 1/5/6/3 | 1 |
| DSVW | 0 | 7 | 0 | 0/6/1/0 | 2 |
| vulpy | 40 | 14 | 4 | 0/6/4/4 | 2 |

**Live platform** (map -> test-gen --identities -> engine -> triage) against a
purpose-built multi-role app detects **BOLA (API1), BFLA (API5), RBAC (API5),
broken authentication (API2)** and **business-logic (API6)** flaws via differential
analysis, with the compliance report flagging each category.

Notes, read honestly: VAmPI defines its routes in an OpenAPI spec (connexion), so
all 14 are mapped from the spec; DSVW uses a hand-rolled WSGI dispatcher that no
generic mapper resolves (0 endpoints is the honest result). VAmPI's findings are
dependency CVEs and global misconfig that no single endpoint "reaches", so its
reachable count is 0. The offline heuristic marks ownership-dependent authz as
"likely" / "inconclusive", never blindly "confirmed" - an AI provider promotes the
real ones.

Reproduce:

```bash
git clone --depth 1 https://github.com/erev0s/VAmPI
offat-graybox ./VAmPI --no-ai -o out/VAmPI           # gray-box, source only
# or the full live pipeline (needs a running target you are authorized to test)
```

## Development

```bash
make help              # list targets
make engine            # build the Rust execution engine
make engine-test       # cargo test
make python-check      # byte-compile the Python packages
make smoke             # offline platform end-to-end check
make viz-test          # visualizer render smoke
make docker            # build the platform image
```

Per-package unit tests: `PYTHONPATH=<pkg...> python -m unittest discover -s <pkg>/tests`.

## Credits & lineage

- **[OWASP OFFAT](https://github.com/OWASP/offat)** - the original spec-driven API
  tester this project extends.
- **[security-harness](https://github.com/dmdhrumilmistry/security-harness)** - the
  multi-stage workflow the source modes mirror.

## License

MIT - see [LICENSE](LICENSE).

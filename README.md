<p align="center">
  <img src="./assets/images/logos/offat.png" alt="OWASP OFFAT" width="120">
</p>

<h1 align="center">OWASP OFFAT</h1>

<p align="center">
  <b>OFFensive Api Tester</b> &mdash; source-aware API security testing.<br>
  Maps your API from code, proves source&rarr;sink paths on a code graph, executes tests with a Rust engine,
  and triages the results with AI.
</p>

<p align="center">
  <a href="https://owasp.github.io/OFFAT/"><b>Documentation</b></a> &middot;
  <a href="https://owasp.github.io/OFFAT/installation.html">Install</a> &middot;
  <a href="https://owasp.github.io/OFFAT/usage.html">Usage</a> &middot;
  <a href="https://owasp.github.io/OFFAT/github-action.html">GitHub Action</a>
</p>

---

> **Authorized use only.** Live runs send real requests to the target you point
> OFFAT at and require an explicit `--yes`. Only test systems and code you own or
> are authorized to assess.

## What it does

```
map -> code graph -> threat model -> test-gen -> execute (Rust) -> triage (AI) -> report
```

- **Map** the attack surface straight from source (decorator routes, routers,
  OpenAPI/Swagger specs) into one canonical [Bundle](./bundle/README.md) file.
- **Prove** source-to-sink data flows on a code property graph (Python, JS/TS) and
  attach every finding to the HTTP route that reaches it.
- **Execute** the test plan with a Rust engine over HTTP/1.1, HTTP/2, WebSocket and
  gRPC (HTTP/3 + QUIC opt-in), with identity-aware differential checks for
  BOLA / BFLA.
- **Triage** with a token-disciplined AI triager (cached, batched, model-tiered)
  or a deterministic offline heuristic.
- **Report** as SARIF 2.1.0 (with code flows), Markdown, HTML, an OWASP API Top 10
  compliance report, and JUnit.

## Quick start

```bash
git clone https://github.com/OWASP/OFFAT.git && cd OFFAT
pip install ./bundle ./triager './whitebox[graph]' ./graybox ./platform ./reporter
make engine                                   # Rust engine, only for live runs

# source-only: no traffic is sent
offat-platform run /path/to/repo -o app.offat.json --report-dir reports

# live, against a target you are authorized to test
offat-platform run /path/to/repo --url https://api.your-authorized-target.test \
  --identities examples/identities.example.json --yes -o app.offat.json --fail-on high
```

Source-only modes:

```bash
offat-whitebox /path/to/repo          # code-graph SAST + AI triage
offat-graybox  /path/to/repo          # SAST prioritized by endpoint reachability
```

Or use the container: `docker build -t offat -f docker/Dockerfile .`

## Repository layout

| Path | What |
|---|---|
| [`bundle/`](./bundle) | the Bundle contract (schema, IO, validation) |
| [`platform/`](./platform) | `offat-platform`: map, PRG, threat model, test-gen, triage |
| [`engine-rs/`](./engine-rs) | `offat-engine`: Rust execution engine |
| [`whitebox/`](./whitebox) | `offat-whitebox`: code-graph taint engine + SAST pipeline |
| [`graybox/`](./graybox) | `offat-graybox`: SAST fused with endpoint reachability |
| [`triager/`](./triager) | shared AI / heuristic triager |
| [`reporter/`](./reporter) | SARIF, Markdown, HTML, compliance reports |
| [`viz/`](./viz) | static Bundle visualizer |
| [`docs/`](./docs) | documentation site sources |

> The classic spec-only Python CLI (`pip install offat`, `src/`) has been retired
> in favour of the platform. Its last release remains on PyPI.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). Issues and pull requests are welcome.

## License

OWASP OFFAT is distributed under the [MIT License](./LICENSE.md).

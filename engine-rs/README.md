# OFFAT-AI Execution Engine (`offat-engine`)

The platform's high-performance request executor (Phase 4), written in Rust. It
reads an [OFFAT Bundle](../bundle/README.md), executes its `test_plan` cases
against an authorized target, captures each request/response, and writes the
`results` section back into the Bundle.

> **Authorized use only.** This sends real attack traffic. Pass `--yes` to confirm
> you own or are permitted to test the target.

## Build

```bash
cd engine-rs
cargo build --release      # -> target/release/offat-engine
```

## Run

```bash
offat-engine --bundle app.offat.json --url https://api.your-authorized-target.example --yes \
  --concurrency 20 --rate 50 -H "Authorization: Bearer $TOKEN"
```

| Flag | Default | Description |
|---|---|---|
| `--bundle` | - | input Bundle (required) |
| `--url` | - | target base URL (required) |
| `--out` | input | output Bundle (default: overwrite input) |
| `--concurrency` | 10 | concurrent requests |
| `--rate` | 25 | max requests/sec (0 = unlimited) |
| `--timeout` | 15 | per-request timeout (s) |
| `-H` | - | extra header `Name: Value` (repeatable) |
| `--insecure` | false | skip TLS verification |
| `--yes` | false | confirm authorization |

## Protocols

Built on `tokio` + `reqwest` (`rustls`), async and rate-limited.

| Protocol | Status |
|---|---|
| HTTP/1.1 | implemented |
| HTTP/2 | implemented (negotiated over TLS) |
| gRPC (tonic) | planned |
| WebSocket (tungstenite) | planned |
| HTTP/3 / QUIC (quinn + h3) | planned |

Protocol dispatch is keyed on each case's `protocol`; cases for a protocol that is
not yet wired are recorded as skipped with a note, so the Bundle stays complete.

## Pipeline

```
offat-platform map --threat-model -> test-gen  =>  bundle.offat.json
offat-engine --bundle bundle.offat.json --url <target> --yes   # fills results
# (next) offat-platform triage + offat reporter consume the same bundle
```

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
| `--identities` | - | JSON file of identities ({name, role, headers, owns}) for BOLA/BFLA/RBAC/auth tests |
| `--insecure` | false | skip TLS verification |
| `--yes` | false | confirm authorization |

## Protocols

Built on `tokio` + `reqwest` (`rustls`), async and rate-limited. Dispatch is keyed
on each case's `protocol`; a case for a protocol the binary was not built with is
recorded as skipped with a note, so the Bundle stays complete.

| Protocol | Status | Driver |
|---|---|---|
| HTTP/1.1 | implemented | reqwest |
| HTTP/2 | implemented (negotiated over TLS) | reqwest |
| WebSocket (ws/wss) | implemented | tokio-tungstenite |
| gRPC | implemented | tonic (schema-less bytes codec) |
| HTTP/3 / QUIC | opt-in build feature | reqwest http3 (h3 + quinn) |

- **WebSocket:** opens the handshake as the case's identity, sends the payload as
  a message (JSON when the case names a param), and captures the handshake status
  plus the first response frames. A `no-auth` case records whether the handshake
  succeeded with no credentials.
- **gRPC:** invokes `/package.Service/Method` over HTTP/2 with a minimal message
  and the identity's metadata, then reads the `grpc-status`. No `.proto`
  compilation is needed - the codec ships raw bytes. A method that is not denied
  (UNAUTHENTICATED / PERMISSION_DENIED) when called with no, or an unprivileged,
  identity is the broken-auth / BFLA signal.

`--timeout` applies to every protocol (HTTP, WebSocket handshake, gRPC connect +
call). `--insecure` (accept an invalid / self-signed certificate) applies to HTTP,
HTTP/3 and `wss://`; gRPC over TLS always verifies the certificate, so point at a
`grpc://` URL for a plaintext test target.

### HTTP/3 build

reqwest's HTTP/3 support is behind its own unstable cfg, so it is an opt-in cargo
feature and the build must also pass `--cfg reqwest_unstable`:

```bash
RUSTFLAGS="--cfg reqwest_unstable" cargo build --release --features http3
```

Without the feature, `http/3` cases are recorded as skipped. `make engine-http3`
runs the command above.

## Pipeline

```
offat-platform map --threat-model -> test-gen  =>  bundle.offat.json
offat-engine --bundle bundle.offat.json --url <target> --yes   # fills results
# (next) offat-platform triage + offat reporter consume the same bundle
```

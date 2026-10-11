//! gRPC driver (schema-less).
//!
//! gRPC is HTTP/2 carrying length-prefixed protobuf. We invoke a unary method by
//! its full path (`/package.Service/Method`) with a minimal (empty) message and
//! the case's identity metadata, then read the `grpc-status`. A method that
//! returns OK (or anything other than UNAUTHENTICATED / PERMISSION_DENIED) when
//! invoked with no - or an unprivileged - identity is the broken-auth / BFLA
//! signal the consolidation stage looks for.
//!
//! The codec is deliberately schema-less: it ships whatever bytes the case
//! carries (none, by default - a valid "all-defaults" protobuf message) and
//! returns the raw response bytes, so no .proto compilation is needed.

use std::collections::HashMap;
use std::str::FromStr;
use std::time::Instant;

use serde_json::{json, Value};
use tonic::codec::{Codec, DecodeBuf, Decoder, EncodeBuf, Encoder};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

use crate::exec::{short, EndpointInfo};

/// A codec that encodes/decodes raw bytes, so arbitrary methods can be invoked
/// without their generated message types.
#[derive(Default)]
struct BytesCodec;

impl Codec for BytesCodec {
    type Encode = Vec<u8>;
    type Decode = Vec<u8>;
    type Encoder = BytesCoder;
    type Decoder = BytesCoder;
    fn encoder(&mut self) -> Self::Encoder {
        BytesCoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        BytesCoder
    }
}

struct BytesCoder;

impl Encoder for BytesCoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, dst: &mut EncodeBuf<'_>) -> Result<(), Status> {
        use bytes::BufMut;
        dst.put_slice(&item);
        Ok(())
    }
}

impl Decoder for BytesCoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn decode(&mut self, src: &mut DecodeBuf<'_>) -> Result<Option<Vec<u8>>, Status> {
        use bytes::Buf;
        let n = src.remaining();
        let mut v = vec![0u8; n];
        src.copy_to_slice(&mut v);
        Ok(Some(v))
    }
}

/// gRPC authority: http(s) base URL -> a tonic endpoint URL (plaintext h2 for
/// http:// / grpc://, TLS for https:// / grpcs://). `--insecure` selects plaintext
/// via a grpc:// URL; gRPC-over-TLS always verifies the certificate (a tonic
/// transport limitation), so point at grpc:// for a plaintext test target.
fn grpc_endpoint(base_url: &str, timeout_s: u64) -> Result<Endpoint, String> {
    let url = base_url.trim_end_matches('/').to_string();
    let (url, tls) = if let Some(rest) = url.strip_prefix("grpcs://") {
        (format!("https://{}", rest), true)
    } else if let Some(rest) = url.strip_prefix("grpc://") {
        (format!("http://{}", rest), false)
    } else {
        (url.clone(), url.starts_with("https://"))
    };
    let mut ep = Channel::from_shared(url).map_err(|e| e.to_string())?;
    ep = ep
        .timeout(std::time::Duration::from_secs(timeout_s.max(1)))
        .connect_timeout(std::time::Duration::from_secs(timeout_s.max(1)));
    if tls {
        ep = ep
            .tls_config(ClientTlsConfig::new().with_webpki_roots())
            .map_err(|e| e.to_string())?;
    }
    Ok(ep)
}

/// Build the method path. The mapper stores it in the endpoint path already
/// (`/pkg.Service/Method`); fall back to method+path if someone hand-wrote it.
fn method_path(ep: &EndpointInfo) -> String {
    if ep.path.starts_with('/') && ep.path.matches('/').count() >= 2 {
        ep.path.clone()
    } else {
        format!("/{}", ep.path.trim_start_matches('/'))
    }
}

/// Execute one gRPC case.
pub async fn execute(
    base_url: &str,
    endpoints: &HashMap<String, EndpointInfo>,
    case: &Value,
    extra_headers: &[(String, String)],
    identities: &HashMap<String, Vec<(String, String)>>,
    timeout_s: u64,
) -> Value {
    let case_id = case.get("id").and_then(Value::as_str).unwrap_or("");
    let ep_id = case.get("endpoint").and_then(Value::as_str).unwrap_or("");
    let ep = match endpoints.get(ep_id) {
        Some(e) => e.clone(),
        None => {
            return json!({
                "id": format!("ex-{}", short(case_id)),
                "case_id": case_id, "protocol": "grpc",
                "response": {"error": format!("unknown endpoint {}", ep_id)},
            })
        }
    };

    let id_name = case.get("identity").and_then(Value::as_str).unwrap_or("");
    let mut headers: Vec<(String, String)> = extra_headers.to_vec();
    if !id_name.is_empty() {
        if let Some(h) = identities.get(id_name) {
            headers.extend(h.iter().cloned());
        }
    }

    let path = method_path(&ep);
    let response = invoke(base_url, &path, &headers, timeout_s).await;

    json!({
        "id": format!("ex-{}", short(case_id)),
        "case_id": case_id, "protocol": "grpc",
        "request": {"method": path, "identity": id_name},
        "response": response,
        "baseline": {},
    })
}

async fn invoke(base_url: &str, path: &str, headers: &[(String, String)], timeout_s: u64) -> Value {
    let endpoint = match grpc_endpoint(base_url, timeout_s) {
        Ok(e) => e,
        Err(e) => return json!({"error": format!("bad grpc target: {}", e)}),
    };
    let started = Instant::now();
    let channel = match endpoint.connect().await {
        Ok(c) => c,
        Err(e) => return json!({"error": format!("grpc connect: {}", e), "connected": false}),
    };

    let mut client = tonic::client::Grpc::new(channel);
    if let Err(e) = client.ready().await {
        return json!({"error": format!("grpc not ready: {}", e), "connected": true});
    }

    // Empty message = a valid protobuf with every field at its default.
    let mut req = Request::new(Vec::<u8>::new());
    for (k, v) in headers {
        let key = k.to_ascii_lowercase();
        if let (Ok(name), Ok(val)) = (
            tonic::metadata::MetadataKey::from_str(&key),
            v.parse::<tonic::metadata::MetadataValue<_>>(),
        ) {
            req.metadata_mut().insert(name, val);
        }
    }

    let pq = match http::uri::PathAndQuery::from_str(path) {
        Ok(p) => p,
        Err(e) => return json!({"error": format!("bad method path: {}", e)}),
    };

    let result = client.unary(req, pq, BytesCodec).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(resp) => {
            let body = resp.into_inner();
            json!({
                "connected": true,
                "grpc_status": "OK",
                "grpc_code": 0,
                "body_bytes": body.len(),
                "latency_ms": latency_ms,
            })
        }
        Err(status) => json!({
            "connected": true,
            "grpc_status": format!("{:?}", status.code()),
            "grpc_code": status.code() as i32,
            "grpc_message": status.message(),
            "latency_ms": latency_ms,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_scheme() {
        assert!(grpc_endpoint("http://localhost:50051", 15).is_ok());
        assert!(grpc_endpoint("https://api.example:443", 15).is_ok());
        assert!(grpc_endpoint("grpc://localhost:50051", 15).is_ok());
    }
}

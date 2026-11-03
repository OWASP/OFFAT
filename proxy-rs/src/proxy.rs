//! The intercepting proxy core.
//!
//! Handles ordinary forward requests (absolute-form `GET http://host/path`) and
//! `CONNECT` tunnels. By default a CONNECT is tunneled opaquely and only its
//! connection metadata is recorded - no TLS is broken. With the `mitm` feature
//! built, the `--mitm` flag set, an installed CA, and the target in active
//! scope, the tunnel is terminated so the plaintext exchange can be captured.
//!
//! Everything proxied is treated as untrusted data: it is captured and
//! forwarded, never interpreted or executed.

use crate::flow::{cap_body, Flow, Header, Request as FlowRequest, Response as FlowResponse};
use crate::store::SharedState;
use crate::util::now_ms;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{TcpListener, TcpStream};

type ClientBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// Hop-by-hop headers that must not be forwarded (RFC 7230 §6.1) plus the
/// proxy's own auth header.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Shared proxy runtime: flow store/config + the upstream client + optional CA.
pub struct ProxyRuntime {
    pub state: SharedState,
    pub client: reqwest::Client,
    #[cfg(feature = "mitm")]
    pub ca: Option<Arc<crate::ca::CertAuthority>>,
}

/// Build the upstream client once, honoring the TLS-verification setting.
pub fn build_client(verify_upstream_tls: bool) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(concat!("offat-proxy/", env!("CARGO_PKG_VERSION")))
        .danger_accept_invalid_certs(!verify_upstream_tls)
        // The proxy terminates and re-issues requests; don't auto-redirect, so the
        // tested client's own redirect behaviour is what we capture.
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

impl ProxyRuntime {
    pub fn new(state: SharedState) -> Result<Arc<Self>> {
        let client = build_client(state.config.verify_upstream_tls)?;
        Ok(Arc::new(Self {
            state,
            client,
            #[cfg(feature = "mitm")]
            ca: None,
        }))
    }

    /// Construct a runtime with a CA for TLS interception.
    #[cfg(feature = "mitm")]
    pub fn with_ca(state: SharedState, ca: Arc<crate::ca::CertAuthority>) -> Result<Arc<Self>> {
        let client = build_client(state.config.verify_upstream_tls)?;
        Ok(Arc::new(Self {
            state,
            client,
            ca: Some(ca),
        }))
    }
}

/// Bind and serve until the process is stopped.
pub async fn serve(runtime: Arc<ProxyRuntime>) -> Result<()> {
    let addr = runtime.state.config.listen;
    let listener = TcpListener::bind(addr).await?;
    eprintln!("offat-proxy listening on http://{addr} (set it as your HTTP/HTTPS proxy)");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let rt = runtime.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| handle(req, rt.clone(), peer));
            if let Err(e) = http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(io, service)
                .with_upgrades()
                .await
            {
                // Clients disconnect mid-tunnel routinely; keep this quiet-ish.
                let msg = e.to_string();
                if !msg.contains("connection closed") {
                    eprintln!("connection error from {peer}: {msg}");
                }
            }
        });
    }
}

async fn handle(
    req: Request<Incoming>,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
) -> Result<Response<ClientBody>, Infallible> {
    // Proxy authentication, when configured.
    if let Some((user, pass)) = &rt.state.config.proxy_auth {
        if !proxy_auth_ok(&req, user, pass) {
            return Ok(resp_status(
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                "proxy authentication required",
            )
            .map(|h| h));
        }
    }

    if req.method() == Method::CONNECT {
        return Ok(handle_connect(req, rt, peer));
    }
    Ok(forward(req, rt, peer).await)
}

fn proxy_auth_ok(req: &Request<Incoming>, user: &str, pass: &str) -> bool {
    let want = base64_basic(user, pass);
    req.headers()
        .get("proxy-authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim() == format!("Basic {want}"))
        .unwrap_or(false)
}

/// Forward an ordinary (absolute-form) request and capture the exchange.
async fn forward(
    req: Request<Incoming>,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
) -> Response<ClientBody> {
    let uri = req.uri().clone();
    let scheme = uri.scheme_str().unwrap_or("http").to_string();
    let host = uri.authority().map(|a| a.to_string()).unwrap_or_default();
    if host.is_empty() {
        return resp_status(
            StatusCode::BAD_REQUEST,
            "proxy requires absolute-form request URIs",
        );
    }
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let url = format!("{scheme}://{host}{path}");
    forward_url(req, rt, peer, &scheme, &host, &path, &url, false).await
}

/// Core forward+capture used by both plain forwarding and the MITM path.
#[allow(clippy::too_many_arguments)]
async fn forward_url(
    req: Request<Incoming>,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
    scheme: &str,
    host: &str,
    path: &str,
    url: &str,
    intercepted: bool,
) -> Response<ClientBody> {
    let in_scope = rt.state.scope_snapshot().allows(host);
    let method = req.method().clone();
    let version = format!("{:?}", req.version());

    // Capture request headers before consuming the body.
    let req_headers: Vec<Header> = req
        .headers()
        .iter()
        .map(|(k, v)| Header {
            name: k.as_str().to_string(),
            value: v.to_str().unwrap_or("").to_string(),
        })
        .collect();

    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return resp_status(
                StatusCode::BAD_GATEWAY,
                &format!("reading request body: {e}"),
            )
        }
    };
    let (req_body_text, req_trunc) = cap_body(&body_bytes, rt.state.config.body_cap);

    let mut flow = Flow::new(
        peer.to_string(),
        FlowRequest {
            method: method.as_str().to_string(),
            scheme: scheme.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            http_version: version,
            headers: req_headers,
            body: req_body_text,
            body_truncated: req_trunc,
        },
        in_scope,
        intercepted,
    );

    // Build the upstream request.
    let r_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut rb = rt.client.request(r_method, url);
    for (name, value) in parts.headers.iter() {
        if is_hop_by_hop(name.as_str()) {
            continue;
        }
        rb = rb.header(name, value);
    }
    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes.to_vec());
    }

    let started = Instant::now();
    let upstream = rb.send().await;
    let latency = started.elapsed().as_millis() as u64;

    match upstream {
        Ok(resp) => {
            let status = resp.status();
            let up_version = format!("{:?}", resp.version());
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let resp_headers: Vec<Header> = resp
                .headers()
                .iter()
                .map(|(k, v)| Header {
                    name: k.as_str().to_string(),
                    value: v.to_str().unwrap_or("").to_string(),
                })
                .collect();

            // Build the client-facing response, dropping framing/encoding headers
            // (reqwest has already decoded the body).
            let mut builder = Response::builder().status(status.as_u16());
            for h in &resp_headers {
                if is_hop_by_hop(&h.name) || is_encoding_header(&h.name) {
                    continue;
                }
                builder = builder.header(&h.name, &h.value);
            }

            let bytes = resp.bytes().await.unwrap_or_default();
            let (resp_body_text, resp_trunc) = cap_body(&bytes, rt.state.config.body_cap);

            flow.latency_ms = Some(latency);
            flow.response = Some(FlowResponse {
                status: status.as_u16(),
                http_version: up_version,
                content_type,
                headers: resp_headers,
                body: resp_body_text,
                body_truncated: resp_trunc,
            });
            rt.state.record(flow);

            builder
                .body(full(bytes))
                .unwrap_or_else(|_| resp_status(StatusCode::BAD_GATEWAY, "building response"))
        }
        Err(e) => {
            flow.error = Some(e.to_string());
            flow.latency_ms = Some(latency);
            rt.state.record(flow);
            resp_status(StatusCode::BAD_GATEWAY, &format!("upstream error: {e}"))
        }
    }
}

/// Handle a CONNECT: respond 200, then tunnel (opaque by default, MITM if enabled).
fn handle_connect(
    req: Request<Incoming>,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
) -> Response<ClientBody> {
    let authority = match req.uri().authority() {
        Some(a) => a.to_string(),
        None => return resp_status(StatusCode::BAD_REQUEST, "CONNECT requires authority"),
    };
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| authority.clone());
    let in_scope = rt.state.scope_snapshot().allows(&host);
    let do_mitm = rt.state.config.mitm && in_scope && mitm_available(&rt);

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if do_mitm {
                    #[cfg(feature = "mitm")]
                    if let Err(e) = mitm_tunnel(io, &host, &authority, rt.clone(), peer).await {
                        eprintln!("mitm tunnel {authority}: {e}");
                    }
                    #[cfg(not(feature = "mitm"))]
                    let _ = io;
                } else {
                    if let Err(e) = blind_tunnel(io, &authority, rt.clone(), peer).await {
                        eprintln!("tunnel {authority}: {e}");
                    }
                }
            }
            Err(e) => eprintln!("CONNECT upgrade error: {e}"),
        }
    });

    // 200 with an empty body switches the client into tunnel mode.
    Response::builder()
        .status(StatusCode::OK)
        .body(empty())
        .expect("static 200 builds")
}

/// Opaque tunnel: pipe bytes both ways and record connection metadata only.
async fn blind_tunnel<I>(
    client_io: I,
    authority: &str,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let host = authority
        .rsplit_once(':')
        .map(|(h, _)| h.to_string())
        .unwrap_or_else(|| authority.to_string());
    let in_scope = rt.state.scope_snapshot().allows(&host);

    let mut server = TcpStream::connect(authority).await?;
    let mut client_io = client_io;
    let (c2s, s2c) = tokio::io::copy_bidirectional(&mut client_io, &mut server)
        .await
        .unwrap_or((0, 0));

    // Metadata-only flow: we did not look inside the TLS.
    let mut flow = Flow::new(
        peer.to_string(),
        FlowRequest {
            method: "CONNECT".into(),
            scheme: "https".into(),
            host: host.clone(),
            path: String::new(),
            http_version: "tunnel".into(),
            headers: vec![],
            body: String::new(),
            body_truncated: false,
        },
        in_scope,
        false,
    );
    flow.at_ms = now_ms();
    flow.response = Some(FlowResponse {
        status: 0,
        http_version: "tunnel".into(),
        content_type: String::new(),
        headers: vec![Header {
            name: "x-offat-tunnel-bytes".into(),
            value: format!("c2s={c2s} s2c={s2c}"),
        }],
        body: String::new(),
        body_truncated: false,
    });
    rt.state.record(flow);
    Ok(())
}

#[cfg(feature = "mitm")]
fn mitm_available(rt: &Arc<ProxyRuntime>) -> bool {
    rt.ca.is_some()
}

#[cfg(not(feature = "mitm"))]
fn mitm_available(_rt: &Arc<ProxyRuntime>) -> bool {
    false
}

/// Terminate the client's TLS with a minted leaf cert, serve HTTP over the
/// decrypted stream, and forward each request upstream over HTTPS.
#[cfg(feature = "mitm")]
async fn mitm_tunnel<I>(
    client_io: I,
    host: &str,
    authority: &str,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
) -> Result<()>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ca = rt
        .ca
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("mitm requested without a CA"))?;
    let acceptor = ca.acceptor_for(host)?;
    let tls = acceptor.accept(client_io).await?;
    let io = TokioIo::new(tls);
    let host = host.to_string();
    let authority = authority.to_string();

    let service = service_fn(move |req: Request<Incoming>| {
        let rt = rt.clone();
        let host = host.clone();
        let authority = authority.clone();
        async move {
            let path = req
                .uri()
                .path_and_query()
                .map(|pq| pq.as_str().to_string())
                .unwrap_or_else(|| "/".to_string());
            // Host header the client sent wins over the CONNECT authority for vhosts.
            let eff_host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .unwrap_or_else(|| authority.clone());
            let _ = &host;
            let url = format!("https://{eff_host}{path}");
            Ok::<_, Infallible>(
                forward_url(req, rt, peer, "https", &eff_host, &path, &url, true).await,
            )
        }
    });

    http1::Builder::new()
        .serve_connection(io, service)
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    Ok(())
}

// --- small helpers ---

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| h.eq_ignore_ascii_case(name))
}

fn is_encoding_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-encoding") || name.eq_ignore_ascii_case("content-length")
}

fn full(bytes: Bytes) -> ClientBody {
    Full::new(bytes).map_err(|e: Infallible| match e {}).boxed()
}

fn empty() -> ClientBody {
    Full::new(Bytes::new())
        .map_err(|e: Infallible| match e {})
        .boxed()
}

fn resp_status(status: StatusCode, msg: &str) -> Response<ClientBody> {
    let mut builder = Response::builder().status(status);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        builder = builder.header("proxy-authenticate", "Basic realm=\"offat-proxy\"");
    }
    builder
        .header("content-type", "text/plain; charset=utf-8")
        .body(full(Bytes::from(format!("offat-proxy: {msg}\n"))))
        .expect("status response builds")
}

/// Minimal base64 for Basic auth comparison (RFC 4648, standard alphabet).
fn base64_basic(user: &str, pass: &str) -> String {
    base64_encode(format!("{user}:{pass}").as_bytes())
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHA: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(ALPHA[((n >> 18) & 63) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHA[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHA[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_detection() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("proxy-authorization"));
        assert!(!is_hop_by_hop("authorization"));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }
}

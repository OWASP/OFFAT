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

    /// The CA SPKI hash to pin-trust in a launched browser, when MITM is active.
    #[cfg(feature = "mitm")]
    pub fn ca_spki(&self) -> Option<String> {
        self.ca.as_ref().map(|c| c.spki_sha256_b64())
    }

    /// Without the MITM feature there is no CA, so nothing to pin-trust.
    #[cfg(not(feature = "mitm"))]
    pub fn ca_spki(&self) -> Option<String> {
        None
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

    let (_parts, body) = req.into_parts();
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

    // --- request-phase rules: block / allow / drop / tag / match-and-replace ---
    let rules = rt.state.rules_snapshot();
    let (decision, req_mods) = rules.apply_request(&flow);
    push_unique_tags(&mut flow.tags, &req_mods.tags);
    match decision {
        crate::rule::ReqDecision::Block { status, body } => {
            return blocked(&rt, flow, status, &body)
        }
        crate::rule::ReqDecision::Drop => return dropped(&rt, flow),
        crate::rule::ReqDecision::Allow => {}
        crate::rule::ReqDecision::Forward => {
            if rt.state.config.block_out_of_scope && !in_scope {
                return blocked(&rt, flow, 403, "host not in allowlist (scope)");
            }
        }
    }

    // Apply request match-and-replace to the stored + forwarded request.
    if !req_mods.set_headers.is_empty() {
        crate::rule::apply_header_mods(&mut flow.request.headers, &req_mods.set_headers);
    }
    let mut fwd_body = body_bytes.to_vec();
    if !req_mods.replace_body.is_empty() {
        let replaced = crate::rule::apply_body_mods(&flow.request.body, &req_mods.replace_body);
        flow.request.body = replaced.clone();
        fwd_body = replaced.into_bytes();
    }

    // Build the upstream request from the (possibly modified) request headers.
    let r_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut rb = rt.client.request(r_method, url);
    for h in &flow.request.headers {
        // Let reqwest set framing/length itself (body may have been rewritten).
        if is_hop_by_hop(&h.name) || h.name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        rb = rb.header(h.name.as_str(), h.value.as_str());
    }
    if !fwd_body.is_empty() {
        rb = rb.body(fwd_body);
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

            // --- response-phase rules: tag / set-resp-header / replace-resp ---
            let resp_mods = rules.apply_response(&flow);
            push_unique_tags(&mut flow.tags, &resp_mods.tags);
            if let Some(r) = flow.response.as_mut() {
                if !resp_mods.set_headers.is_empty() {
                    crate::rule::apply_header_mods(&mut r.headers, &resp_mods.set_headers);
                }
            }
            let client_bytes = if resp_mods.replace_body.is_empty() {
                bytes
            } else {
                let replaced = crate::rule::apply_body_mods(
                    &String::from_utf8_lossy(&bytes),
                    &resp_mods.replace_body,
                );
                if let Some(r) = flow.response.as_mut() {
                    let (t, tr) = cap_body(replaced.as_bytes(), rt.state.config.body_cap);
                    r.body = t;
                    r.body_truncated = tr;
                }
                Bytes::from(replaced.into_bytes())
            };

            // Build the client-facing response from the (possibly modified) headers,
            // dropping framing/encoding headers (reqwest already decoded the body).
            let mut builder = Response::builder().status(status.as_u16());
            if let Some(r) = flow.response.as_ref() {
                for h in &r.headers {
                    if is_hop_by_hop(&h.name) || is_encoding_header(&h.name) {
                        continue;
                    }
                    builder = builder.header(&h.name, &h.value);
                }
            }
            rt.state.record(flow);

            builder
                .body(full(client_bytes))
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

/// Append tags, skipping any already present (a tag rule can match in both the
/// request and response phases).
fn push_unique_tags(tags: &mut Vec<String>, new: &[String]) {
    for t in new {
        if !tags.contains(t) {
            tags.push(t.clone());
        }
    }
}

/// Record a rule-blocked request and return the canned response to the client.
fn blocked(
    rt: &Arc<ProxyRuntime>,
    mut flow: Flow,
    status: u16,
    body: &str,
) -> Response<ClientBody> {
    flow.tags.push("blocked".into());
    flow.response = Some(FlowResponse {
        status,
        http_version: "HTTP/1.1".into(),
        content_type: "text/plain; charset=utf-8".into(),
        headers: vec![Header {
            name: "x-offat-proxy".into(),
            value: "blocked".into(),
        }],
        body: body.to_string(),
        body_truncated: false,
    });
    rt.state.record(flow);
    let sc = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
    Response::builder()
        .status(sc)
        .header("content-type", "text/plain; charset=utf-8")
        .header("x-offat-proxy", "blocked")
        .body(full(Bytes::from(format!("{body}\n"))))
        .unwrap_or_else(|_| resp_status(sc, body))
}

/// Record a rule-dropped request and close the connection.
fn dropped(rt: &Arc<ProxyRuntime>, mut flow: Flow) -> Response<ClientBody> {
    flow.tags.push("dropped".into());
    flow.error = Some("dropped by rule".into());
    rt.state.record(flow);
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("connection", "close")
        .header("x-offat-proxy", "dropped")
        .body(empty())
        .unwrap_or_else(|_| resp_status(StatusCode::FORBIDDEN, "dropped"))
}

/// Minimal base64 for Basic auth comparison (RFC 4648, standard alphabet).
fn base64_basic(user: &str, pass: &str) -> String {
    crate::util::base64(format!("{user}:{pass}").as_bytes())
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
    fn basic_auth_header_value() {
        assert_eq!(base64_basic("user", "pass"), "dXNlcjpwYXNz");
    }
}

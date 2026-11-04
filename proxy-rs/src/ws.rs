//! WebSocket interception.
//!
//! Browsers open WebSockets with an HTTP `Upgrade` handshake. reqwest can't carry
//! an upgrade, so for these requests the proxy speaks the handshake itself: it
//! opens its own connection to the upstream (TCP for `ws://`, TLS for `wss://`
//! reached through MITM), relays the 101, records the handshake as a flow, then
//! pipes frames both ways. Frames are tunneled, not parsed - but the connection
//! is visible in history and subject to the same scope gate.

use crate::flow::{Flow, Header, Request as FlowRequest, Response as FlowResponse};
use crate::proxy::ProxyRuntime;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

type ClientBody = http_body_util::combinators::BoxBody<Bytes, hyper::Error>;

/// True if the request headers describe a WebSocket upgrade.
pub fn is_upgrade(headers: &hyper::HeaderMap) -> bool {
    let has_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);
    let is_ws = headers
        .get(hyper::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    has_upgrade && is_ws
}

/// Intercept a WebSocket handshake and relay the connection.
///
/// `tls` selects the upstream transport (`wss` vs `ws`). `host_port` is the
/// upstream authority (host or host:port); `path` is the request target.
pub async fn proxy_websocket(
    mut req: Request<Incoming>,
    rt: Arc<ProxyRuntime>,
    peer: SocketAddr,
    tls: bool,
    host_port: String,
    path: String,
) -> Response<ClientBody> {
    let (host, port) = split_host_port(&host_port, if tls { 443 } else { 80 });
    let scheme = if tls { "wss" } else { "ws" };
    let in_scope = rt.state.scope_snapshot().allows(&host);

    // Capture request headers for history.
    let req_headers: Vec<Header> = req
        .headers()
        .iter()
        .map(|(k, v)| Header {
            name: k.as_str().to_string(),
            value: v.to_str().unwrap_or("").to_string(),
        })
        .collect();

    let handshake = build_handshake(req.method().as_str(), &path, &host_port, &req_headers);

    let mut flow = Flow::new(
        peer.to_string(),
        FlowRequest {
            method: req.method().as_str().to_string(),
            scheme: scheme.into(),
            host: host.clone(),
            path: path.clone(),
            http_version: "websocket".into(),
            headers: req_headers,
            body: String::new(),
            body_truncated: false,
        },
        in_scope,
        true,
    );
    flow.tags.push("websocket".into());

    // Grab the upgrade future before we move `req` out of scope.
    let on_upgrade = hyper::upgrade::on(&mut req);

    // Connect upstream and perform the handshake.
    let result = if tls {
        #[cfg(feature = "mitm")]
        {
            connect_tls(&host, port, !rt.state.config.verify_upstream_tls)
                .await
                .map(|s| StreamKind::Tls(Box::new(s)))
        }
        #[cfg(not(feature = "mitm"))]
        {
            Err("wss interception needs the mitm build feature".to_string())
        }
    } else {
        TcpStream::connect((host.as_str(), port))
            .await
            .map(StreamKind::Plain)
            .map_err(|e| e.to_string())
    };

    let mut upstream = match result {
        Ok(s) => s,
        Err(e) => {
            flow.error = Some(format!("ws upstream connect: {e}"));
            rt.state.record(flow);
            return resp(StatusCode::BAD_GATEWAY, &format!("ws upstream error: {e}"));
        }
    };

    if let Err(e) = upstream.write_all(&handshake).await {
        flow.error = Some(format!("ws handshake write: {e}"));
        rt.state.record(flow);
        return resp(StatusCode::BAD_GATEWAY, "ws handshake failed");
    }

    let (status, resp_headers, leftover) = match read_head(&mut upstream).await {
        Ok(v) => v,
        Err(e) => {
            flow.error = Some(format!("ws handshake read: {e}"));
            rt.state.record(flow);
            return resp(StatusCode::BAD_GATEWAY, "ws handshake read failed");
        }
    };

    flow.response = Some(FlowResponse {
        status,
        http_version: "websocket".into(),
        content_type: String::new(),
        headers: resp_headers
            .iter()
            .map(|(k, v)| Header {
                name: k.clone(),
                value: v.clone(),
            })
            .collect(),
        body: String::new(),
        body_truncated: false,
    });
    rt.state.record(flow);

    if status != 101 {
        // Not a successful upgrade; surface the upstream status to the client.
        let mut b = Response::builder().status(status);
        for (k, v) in &resp_headers {
            if !is_framing(k) {
                b = b.header(k, v);
            }
        }
        return b
            .body(full(Bytes::from(leftover)))
            .unwrap_or_else(|_| resp(StatusCode::BAD_GATEWAY, "ws"));
    }

    // Build the 101 response mirroring the upstream handshake headers.
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (k, v) in &resp_headers {
        if !is_framing(k) {
            builder = builder.header(k, v);
        }
    }

    // After the client is upgraded, pipe frames both ways.
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut client = TokioIo::new(upgraded);
                if !leftover.is_empty() {
                    let _ = client.write_all(&leftover).await;
                }
                let _ = upstream.copy_bidirectional(&mut client).await;
            }
            Err(e) => eprintln!("ws client upgrade: {e}"),
        }
    });

    builder
        .body(empty())
        .unwrap_or_else(|_| resp(StatusCode::INTERNAL_SERVER_ERROR, "ws 101 build"))
}

/// One of the two upstream transports, unified so the relay code is shared.
enum StreamKind {
    Plain(TcpStream),
    #[cfg(feature = "mitm")]
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl StreamKind {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            StreamKind::Plain(s) => s.write_all(buf).await,
            #[cfg(feature = "mitm")]
            StreamKind::Tls(s) => s.write_all(buf).await,
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            StreamKind::Plain(s) => s.read(buf).await,
            #[cfg(feature = "mitm")]
            StreamKind::Tls(s) => s.read(buf).await,
        }
    }
    /// Copy bytes in both directions between this upstream and the client.
    async fn copy_bidirectional<C>(&mut self, client: &mut C) -> std::io::Result<(u64, u64)>
    where
        C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        match self {
            StreamKind::Plain(s) => tokio::io::copy_bidirectional(client, s).await,
            #[cfg(feature = "mitm")]
            StreamKind::Tls(s) => tokio::io::copy_bidirectional(client, s.as_mut()).await,
        }
    }
}

/// Read an HTTP response head (up to CRLFCRLF); return (status, headers, leftover).
async fn read_head(
    upstream: &mut StreamKind,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = upstream.read(&mut tmp).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("upstream closed during handshake".into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).to_string();
            let leftover = buf[pos + 4..].to_vec();
            let mut lines = head.split("\r\n");
            let status_line = lines.next().unwrap_or("");
            let status = status_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .ok_or_else(|| format!("bad status line: {status_line}"))?;
            let headers = lines
                .filter_map(|l| {
                    l.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            return Ok((status, headers, leftover));
        }
        if buf.len() > 64 * 1024 {
            return Err("handshake response too large".into());
        }
    }
}

fn build_handshake(method: &str, path: &str, host_port: &str, headers: &[Header]) -> Vec<u8> {
    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    let mut have_host = false;
    for h in headers {
        let lname = h.name.to_ascii_lowercase();
        if lname == "proxy-connection" || lname == "proxy-authorization" {
            continue;
        }
        if lname == "host" {
            have_host = true;
        }
        out.push_str(&format!("{}: {}\r\n", h.name, h.value));
    }
    if !have_host {
        out.push_str(&format!("Host: {host_port}\r\n"));
    }
    out.push_str("\r\n");
    out.into_bytes()
}

fn split_host_port(authority: &str, default: u16) -> (String, u16) {
    // IPv6 literal like [::1]:443
    if let Some(end) = authority.rfind(']') {
        let host = authority[..=end].to_string();
        let port = authority[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default);
        return (host, port);
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default)),
        None => (authority.to_string(), default),
    }
}

fn is_framing(name: &str) -> bool {
    name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("content-length")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn full(bytes: Bytes) -> ClientBody {
    Full::new(bytes).map_err(|e: Infallible| match e {}).boxed()
}
fn empty() -> ClientBody {
    Full::new(Bytes::new())
        .map_err(|e: Infallible| match e {})
        .boxed()
}
fn resp(status: StatusCode, msg: &str) -> Response<ClientBody> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full(Bytes::from(format!("offat-proxy: {msg}\n"))))
        .expect("status response builds")
}

#[cfg(feature = "mitm")]
async fn connect_tls(
    host: &str,
    port: u16,
    insecure: bool,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    use rustls::pki_types::ServerName;
    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| e.to_string())?;
    let config = client_config(insecure);
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(host.to_string()).map_err(|e| e.to_string())?;
    connector
        .connect(name, tcp)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(feature = "mitm")]
fn client_config(insecure: bool) -> rustls::ClientConfig {
    if insecure {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }
}

/// Accept-any-certificate verifier for `--insecure-upstream` only.
#[cfg(feature = "mitm")]
#[derive(Debug)]
struct NoVerify;

#[cfg(feature = "mitm")]
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end: &rustls::pki_types::CertificateDer<'_>,
        _inter: &[rustls::pki_types::CertificateDer<'_>],
        _name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _m: &[u8],
        _c: &rustls::pki_types::CertificateDer<'_>,
        _d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_upgrade() {
        let mut h = hyper::HeaderMap::new();
        h.insert(hyper::header::CONNECTION, "Upgrade".parse().unwrap());
        h.insert(hyper::header::UPGRADE, "websocket".parse().unwrap());
        assert!(is_upgrade(&h));
        let mut h2 = hyper::HeaderMap::new();
        h2.insert(
            hyper::header::CONNECTION,
            "keep-alive, Upgrade".parse().unwrap(),
        );
        h2.insert(hyper::header::UPGRADE, "WebSocket".parse().unwrap());
        assert!(is_upgrade(&h2));
        assert!(!is_upgrade(&hyper::HeaderMap::new()));
    }

    #[test]
    fn host_port_parsing() {
        assert_eq!(split_host_port("api.test", 443), ("api.test".into(), 443));
        assert_eq!(
            split_host_port("api.test:8443", 443),
            ("api.test".into(), 8443)
        );
        assert_eq!(split_host_port("[::1]:9000", 443), ("[::1]".into(), 9000));
    }

    #[test]
    fn handshake_includes_host_and_skips_proxy_headers() {
        let headers = vec![
            Header {
                name: "Upgrade".into(),
                value: "websocket".into(),
            },
            Header {
                name: "Proxy-Connection".into(),
                value: "keep-alive".into(),
            },
        ];
        let hs = String::from_utf8(build_handshake("GET", "/ws", "api.test:80", &headers)).unwrap();
        assert!(hs.starts_with("GET /ws HTTP/1.1\r\n"));
        assert!(hs.contains("Upgrade: websocket\r\n"));
        assert!(!hs.contains("Proxy-Connection"));
        assert!(hs.contains("Host: api.test:80\r\n"));
        assert!(hs.ends_with("\r\n\r\n"));
    }

    #[test]
    fn find_subsequence() {
        assert_eq!(find(b"abc\r\n\r\ndef", b"\r\n\r\n"), Some(3));
        assert_eq!(find(b"noterm", b"\r\n\r\n"), None);
    }
}

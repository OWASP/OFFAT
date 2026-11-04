//! The captured HTTP exchange ("flow"), its redaction policy, and body caps.
//!
//! A flow is the unit the proxy records and the MCP surface exposes. Secrets are
//! redacted by default so exported Bundles never carry live credentials, and
//! bodies are capped so one large download can't exhaust memory.

use crate::util::{next_id, now_ms};
use serde::{Deserialize, Serialize};

/// Default cap on a stored body before truncation (1 MiB).
pub const DEFAULT_BODY_CAP: usize = 1024 * 1024;

/// Header names whose values are replaced with a placeholder when redaction is on.
/// Matched case-insensitively.
pub const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-amz-security-token",
    "x-csrf-token",
];

pub const REDACTED: &str = "<redacted>";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub method: String,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub http_version: String,
    pub headers: Vec<Header>,
    pub body: String,
    #[serde(default)]
    pub body_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub status: u16,
    pub http_version: String,
    pub content_type: String,
    pub headers: Vec<Header>,
    pub body: String,
    #[serde(default)]
    pub body_truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flow {
    pub id: String,
    /// Epoch ms when the request was received.
    pub at_ms: u64,
    pub client: String,
    /// Whether the host is in the active-use scope (bodies kept, test surface).
    pub in_scope: bool,
    /// True once MITM decrypted this exchange (vs. plain HTTP or tunnel metadata).
    pub intercepted: bool,
    pub request: Request,
    pub response: Option<Response>,
    pub latency_ms: Option<u64>,
    /// Populated when the exchange failed before a response (DNS, connect, TLS).
    pub error: Option<String>,
    /// Labels applied by rules (`tag "..."`) - highlights/annotations.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Flow {
    pub fn new(client: String, request: Request, in_scope: bool, intercepted: bool) -> Self {
        Self {
            id: next_id("flow"),
            at_ms: now_ms(),
            client,
            in_scope,
            intercepted,
            request,
            response: None,
            latency_ms: None,
            error: None,
            tags: Vec::new(),
        }
    }

    /// Build a redacted copy for persistence / export. Out-of-scope flows also
    /// have bodies dropped (metadata only) to avoid hoarding third-party data.
    pub fn sanitized(&self, redact: bool) -> Flow {
        let mut f = self.clone();
        if redact {
            redact_headers(&mut f.request.headers);
            if let Some(r) = f.response.as_mut() {
                redact_headers(&mut r.headers);
            }
        }
        if !f.in_scope {
            f.request.body = String::new();
            f.request.body_truncated = false;
            if let Some(r) = f.response.as_mut() {
                r.body = String::new();
                r.body_truncated = false;
            }
        }
        f
    }

    pub fn url(&self) -> String {
        format!(
            "{}://{}{}",
            self.request.scheme, self.request.host, self.request.path
        )
    }
}

fn redact_headers(headers: &mut [Header]) {
    for h in headers.iter_mut() {
        if SENSITIVE_HEADERS
            .iter()
            .any(|s| s.eq_ignore_ascii_case(&h.name))
        {
            h.value = REDACTED.to_string();
        }
    }
}

/// Cap a body to `cap` bytes, decoding as UTF-8 lossily. Returns (text, truncated).
pub fn cap_body(bytes: &[u8], cap: usize) -> (String, bool) {
    if bytes.len() <= cap {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    } else {
        (String::from_utf8_lossy(&bytes[..cap]).into_owned(), true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Flow {
        let req = Request {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.example.test".into(),
            path: "/users/1".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![
                Header {
                    name: "Authorization".into(),
                    value: "Bearer secret".into(),
                },
                Header {
                    name: "Accept".into(),
                    value: "application/json".into(),
                },
            ],
            body: "{\"pw\":\"x\"}".into(),
            body_truncated: false,
        };
        let mut f = Flow::new("127.0.0.1:1".into(), req, true, true);
        f.response = Some(Response {
            status: 200,
            http_version: "HTTP/1.1".into(),
            content_type: "application/json".into(),
            headers: vec![Header {
                name: "Set-Cookie".into(),
                value: "sid=abc".into(),
            }],
            body: "{}".into(),
            body_truncated: false,
        });
        f
    }

    #[test]
    fn redaction_hides_credentials_keeps_other_headers() {
        let s = sample().sanitized(true);
        let auth = s
            .request
            .headers
            .iter()
            .find(|h| h.name == "Authorization")
            .unwrap();
        assert_eq!(auth.value, REDACTED);
        let accept = s
            .request
            .headers
            .iter()
            .find(|h| h.name == "Accept")
            .unwrap();
        assert_eq!(accept.value, "application/json");
        let cookie = s.response.unwrap().headers[0].value.clone();
        assert_eq!(cookie, REDACTED);
    }

    #[test]
    fn out_of_scope_drops_bodies() {
        let mut f = sample();
        f.in_scope = false;
        let s = f.sanitized(true);
        assert!(s.request.body.is_empty());
        assert!(s.response.unwrap().body.is_empty());
    }

    #[test]
    fn body_cap_truncates() {
        let (t, trunc) = cap_body(&[b'a'; 10], 4);
        assert_eq!(t, "aaaa");
        assert!(trunc);
        let (t2, trunc2) = cap_body(b"hi", 4);
        assert_eq!(t2, "hi");
        assert!(!trunc2);
    }
}

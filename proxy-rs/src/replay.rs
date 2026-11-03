//! Replay / "repeater": re-send a captured flow, optionally mutated.
//!
//! This is an *active* action - it sends a real request - so the target host must
//! be in the active-use scope. Fuzzing (iterating payloads over an insertion
//! point, Burp "Intruder"-style) is built on top of this and shares the same
//! scope gate; it is deliberately rate-limited and bounded.

use crate::flow::{cap_body, Flow, Header, Request as FlowRequest, Response as FlowResponse};
use crate::scope::Scope;
use anyhow::{bail, Result};
use serde::Deserialize;
use std::time::Instant;

/// Overrides applied to a base flow before replaying. Any `None` keeps the
/// original value.
#[derive(Debug, Default, Deserialize)]
pub struct Overrides {
    pub method: Option<String>,
    pub path: Option<String>,
    /// Replace the whole body.
    pub body: Option<String>,
    /// Add or replace these headers (by case-insensitive name).
    #[serde(default)]
    pub set_headers: Vec<Header>,
    /// Remove these header names (case-insensitive).
    #[serde(default)]
    pub remove_headers: Vec<String>,
}

/// Build the effective request from a base flow and overrides (pure; unit-tested).
pub fn apply_overrides(base: &FlowRequest, ov: &Overrides) -> FlowRequest {
    let mut req = base.clone();
    if let Some(m) = &ov.method {
        req.method = m.clone();
    }
    if let Some(p) = &ov.path {
        req.path = p.clone();
    }
    if let Some(b) = &ov.body {
        req.body = b.clone();
        req.body_truncated = false;
    }
    for name in &ov.remove_headers {
        req.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }
    for set in &ov.set_headers {
        req.headers
            .retain(|h| !h.name.eq_ignore_ascii_case(&set.name));
        req.headers.push(set.clone());
    }
    req
}

/// Replay a flow through the given client, returning the new captured flow.
pub async fn replay(
    client: &reqwest::Client,
    base: &Flow,
    ov: &Overrides,
    scope: &Scope,
    body_cap: usize,
) -> Result<Flow> {
    let req = apply_overrides(&base.request, ov);
    if !scope.allows(&req.host) {
        bail!(
            "host '{}' is not in active scope; add it with set_scope before replaying",
            req.host
        );
    }
    let url = format!("{}://{}{}", req.scheme, req.host, req.path);
    let method = reqwest::Method::from_bytes(req.method.as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut rb = client.request(method, &url);
    for h in &req.headers {
        // Skip framing headers reqwest manages itself.
        if h.name.eq_ignore_ascii_case("content-length")
            || h.name.eq_ignore_ascii_case("host")
            || h.name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        rb = rb.header(&h.name, &h.value);
    }
    if !req.body.is_empty() {
        rb = rb.body(req.body.clone().into_bytes());
    }

    let mut flow = Flow::new("replay".into(), req, true, true);
    let started = Instant::now();
    match rb.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let http_version = format!("{:?}", resp.version());
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let headers: Vec<Header> = resp
                .headers()
                .iter()
                .map(|(k, v)| Header {
                    name: k.as_str().to_string(),
                    value: v.to_str().unwrap_or("").to_string(),
                })
                .collect();
            let bytes = resp.bytes().await.unwrap_or_default();
            let (body, truncated) = cap_body(&bytes, body_cap);
            flow.latency_ms = Some(started.elapsed().as_millis() as u64);
            flow.response = Some(FlowResponse {
                status,
                http_version,
                content_type,
                headers,
                body,
                body_truncated: truncated,
            });
        }
        Err(e) => {
            flow.latency_ms = Some(started.elapsed().as_millis() as u64);
            flow.error = Some(e.to_string());
        }
    }
    Ok(flow)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FlowRequest {
        FlowRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "api.example.test".into(),
            path: "/a".into(),
            http_version: "HTTP/1.1".into(),
            headers: vec![
                Header {
                    name: "Accept".into(),
                    value: "*/*".into(),
                },
                Header {
                    name: "X-Token".into(),
                    value: "old".into(),
                },
            ],
            body: String::new(),
            body_truncated: false,
        }
    }

    #[test]
    fn overrides_method_path_body() {
        let ov = Overrides {
            method: Some("POST".into()),
            path: Some("/b".into()),
            body: Some("{}".into()),
            ..Default::default()
        };
        let r = apply_overrides(&base(), &ov);
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/b");
        assert_eq!(r.body, "{}");
    }

    #[test]
    fn set_and_remove_headers_case_insensitive() {
        let ov = Overrides {
            set_headers: vec![Header {
                name: "x-token".into(),
                value: "new".into(),
            }],
            remove_headers: vec!["accept".into()],
            ..Default::default()
        };
        let r = apply_overrides(&base(), &ov);
        assert!(r
            .headers
            .iter()
            .all(|h| !h.name.eq_ignore_ascii_case("accept")));
        let tok = r
            .headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case("x-token"))
            .unwrap();
        assert_eq!(tok.value, "new");
        // only one x-token remains
        assert_eq!(
            r.headers
                .iter()
                .filter(|h| h.name.eq_ignore_ascii_case("x-token"))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn replay_refused_out_of_scope() {
        let client = reqwest::Client::new();
        let mut f = Flow::new("c".into(), base(), true, true);
        f.response = None;
        let scope = Scope::default(); // empty -> denies
        let err = replay(&client, &f, &Overrides::default(), &scope, 1024)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not in active scope"));
    }
}

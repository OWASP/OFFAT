//! Request building and execution. HTTP/1.1 and HTTP/2 are implemented (reqwest
//! negotiates H2 over TLS automatically); other protocols are recognized and
//! recorded as skipped until their drivers land (gRPC, WebSocket, HTTP/3/QUIC).

use std::collections::HashMap;
use std::time::Instant;

use reqwest::Client;
use serde_json::{json, Map, Value};

/// Minimal endpoint view resolved from the bundle's `asm`.
#[derive(Clone)]
pub struct EndpointInfo {
    pub method: String,
    pub path: String,
    pub params: Vec<ParamInfo>,
}

#[derive(Clone)]
pub struct ParamInfo {
    pub name: String,
    pub location: String,
}

/// Index endpoints by their id.
pub fn index_endpoints(bundle: &Value) -> HashMap<String, EndpointInfo> {
    let mut out = HashMap::new();
    let eps = bundle
        .get("asm")
        .and_then(|a| a.get("endpoints"))
        .and_then(|e| e.as_array());
    if let Some(eps) = eps {
        for ep in eps {
            let id = ep
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            let params = ep
                .get("params")
                .and_then(Value::as_array)
                .map(|ps| {
                    ps.iter()
                        .map(|p| ParamInfo {
                            name: p
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_string(),
                            location: p
                                .get("location")
                                .and_then(Value::as_str)
                                .unwrap_or("query")
                                .to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.insert(
                id,
                EndpointInfo {
                    method: ep
                        .get("method")
                        .and_then(Value::as_str)
                        .unwrap_or("GET")
                        .to_string(),
                    path: ep
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("/")
                        .to_string(),
                    params,
                },
            );
        }
    }
    out
}

fn param_location<'a>(ep: &'a EndpointInfo, name: &str) -> Option<&'a str> {
    ep.params
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.location.as_str())
}

/// Substitute path placeholders `{x}`, `:x`, `<x>`; the targeted path param gets
/// the payload, others get a benign "1".
fn build_path(path: &str, target: &str, payload: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c == '{' {
            if let Some(end) = path[i..].find('}') {
                let name = &path[i + 1..i + end];
                out.push_str(if name == target { payload } else { "1" });
                i += end + 1;
                continue;
            }
        } else if c == ':' {
            let rest = &path[i + 1..];
            let end = rest.find('/').unwrap_or(rest.len());
            let name = &rest[..end];
            out.push_str(if name == target { payload } else { "1" });
            i += 1 + end;
            continue;
        } else if c == '<' {
            if let Some(end) = path[i..].find('>') {
                let inner = &path[i + 1..i + end];
                let name = inner.rsplit(':').next().unwrap_or(inner);
                out.push_str(if name == target { payload } else { "1" });
                i += end + 1;
                continue;
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

fn protocol_of(case: &Value) -> String {
    case.get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("http")
        .to_lowercase()
}

/// Execute a single test case. Returns an execution object for `results`.
pub async fn execute(
    client: &Client,
    base_url: &str,
    endpoints: &HashMap<String, EndpointInfo>,
    case: &Value,
    extra_headers: &[(String, String)],
    identities: &HashMap<String, Vec<(String, String)>>,
) -> Value {
    let case_id = case
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let proto = protocol_of(case);

    // Only HTTP variants are wired today; others are recorded as skipped.
    if !(proto == "http"
        || proto == "https"
        || proto == "http/1.1"
        || proto == "http/2"
        || proto.is_empty())
    {
        return json!({
            "id": format!("ex-{}", short(&case_id)),
            "case_id": case_id, "protocol": proto,
            "response": {"skipped": format!("protocol '{}' not yet supported by the engine", proto)},
        });
    }

    let ep_id = case.get("endpoint").and_then(Value::as_str).unwrap_or("");
    let ep = match endpoints.get(ep_id) {
        Some(e) => e.clone(),
        None => {
            return json!({
                "id": format!("ex-{}", short(&case_id)),
                "case_id": case_id, "protocol": "http",
                "response": {"error": format!("unknown endpoint {}", ep_id)},
            })
        }
    };

    let payload = case
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let target_param = case
        .get("param")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let location = case
        .get("location")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .or_else(|| param_location(&ep, &target_param).map(|s| s.to_string()))
        .unwrap_or_else(|| "query".to_string());

    let path = build_path(&ep.path, &target_param, &payload);
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let method = reqwest::Method::from_bytes(ep.method.to_uppercase().as_bytes())
        .unwrap_or(reqwest::Method::GET);

    // The principal this request acts as (its auth headers), merged over globals.
    let id_name = case.get("identity").and_then(Value::as_str).unwrap_or("");
    let mut primary_headers: Vec<(String, String)> = extra_headers.to_vec();
    if !id_name.is_empty() {
        if let Some(h) = identities.get(id_name) {
            primary_headers.extend(h.iter().cloned());
        }
    }
    let response = send_once(
        client,
        &method,
        &url,
        &primary_headers,
        &target_param,
        &location,
        &payload,
    )
    .await;

    // Differential baseline (resource owner / privileged identity) for authz tests.
    let base_name = case
        .get("baseline_identity")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut baseline = json!({});
    if !base_name.is_empty() {
        let mut bh: Vec<(String, String)> = extra_headers.to_vec();
        if let Some(h) = identities.get(base_name) {
            bh.extend(h.iter().cloned());
        }
        baseline = send_once(
            client,
            &method,
            &url,
            &bh,
            &target_param,
            &location,
            &payload,
        )
        .await;
    }

    json!({
        "id": format!("ex-{}", short(&case_id)),
        "case_id": case_id, "protocol": "http",
        "request": {"method": ep.method, "url": url, "param": target_param, "location": location,
                    "payload": payload, "identity": id_name, "baseline_identity": base_name},
        "response": response,
        "baseline": baseline,
    })
}

async fn send_once(
    client: &Client,
    method: &reqwest::Method,
    url: &str,
    headers: &[(String, String)],
    target_param: &str,
    location: &str,
    payload: &str,
) -> Value {
    let mut req = client.request(method.clone(), url);
    for (k, v) in headers {
        req = req.header(k.as_str(), v.as_str());
    }
    if !target_param.is_empty() {
        match location {
            "query" => req = req.query(&[(target_param, payload)]),
            "header" => req = req.header(target_param, payload),
            "cookie" => req = req.header("cookie", format!("{}={}", target_param, payload)),
            "body" | "form" => {
                let mut m = Map::new();
                m.insert(target_param.to_string(), Value::String(payload.to_string()));
                req = req.json(&Value::Object(m));
            }
            _ => {}
        }
    }
    let started = Instant::now();
    let result = req.send().await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let version = format!("{:?}", resp.version());
            let ctype = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let location_hdr = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = resp.text().await.unwrap_or_default();
            let snippet: String = body.chars().take(2048).collect();
            json!({"status": status, "http_version": version, "content_type": ctype,
                   "location": location_hdr, "body_snippet": snippet, "latency_ms": latency_ms})
        }
        Err(e) => json!({"error": e.to_string()}),
    }
}

fn short(s: &str) -> String {
    let n = s.chars().count();
    s.chars().skip(n.saturating_sub(12)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_substitution() {
        assert_eq!(build_path("/users/{id}", "id", "x"), "/users/x");
        assert_eq!(build_path("/users/{id}", "other", "x"), "/users/1");
        assert_eq!(build_path("/a/:id/b", "id", "9"), "/a/9/b");
        assert_eq!(build_path("/a/<int:id>", "id", "9"), "/a/9");
        assert_eq!(build_path("/static", "id", "9"), "/static");
    }

    #[test]
    fn protocol_detection() {
        assert_eq!(protocol_of(&json!({"protocol": "HTTP/2"})), "http/2");
        assert_eq!(protocol_of(&json!({})), "http");
    }

    #[test]
    fn short_suffix() {
        assert_eq!(short("tc-abcdef012345"), "abcdef012345");
        assert_eq!(short("x"), "x");
    }
}

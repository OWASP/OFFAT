//! Turn captured flows into an OFFAT Bundle.
//!
//! This is the integration point: observed live traffic becomes `asm.endpoints`
//! (deduplicated, with variable path segments templated to `{id}`) and
//! `results.executions` captures whose shape matches the Rust engine's output,
//! so every downstream stage (test-gen, triage, reporter, viz) consumes it
//! unchanged. The emitted document validates against
//! `bundle/offat_bundle/schema/offat-bundle-v1.schema.json`.

use crate::flow::Flow;
use crate::util::{next_id, now_ms, rfc3339};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1.0";

/// Build a Bundle (as JSON) from a set of flows. `only_scope` keeps in-scope
/// flows only - the usual choice, since those are the authorized test surface.
pub fn flows_to_bundle(flows: &[Flow], base_url: &str, only_scope: bool) -> Value {
    let ts = rfc3339(now_ms());
    let selected: Vec<&Flow> = flows.iter().filter(|f| !only_scope || f.in_scope).collect();

    // --- asm.endpoints: dedup by (method, templated path) ---
    let mut endpoints: BTreeMap<(String, String), Value> = BTreeMap::new();
    for f in &selected {
        let method = f.request.method.to_uppercase();
        let (path, _q) = split_path(&f.request.path);
        let templated = template_path(&path);
        let key = (method.clone(), templated.clone());
        let entry = endpoints.entry(key).or_insert_with(|| {
            json!({
                "id": endpoint_id(&method, &templated),
                "method": method,
                "path": templated,
                "protocol": "http",
                "params": [],
                "source": {"origin": "proxy-capture", "host": f.request.host},
            })
        });
        merge_params(entry, f);
    }

    let asm_endpoints: Vec<Value> = endpoints.into_values().collect();

    // --- results.executions: one capture per flow ---
    let executions: Vec<Value> = selected.iter().map(|f| capture(f)).collect();

    json!({
        "schema_version": SCHEMA_VERSION,
        "meta": {
            "tool": "offat-proxy",
            "version": env!("CARGO_PKG_VERSION"),
            "run_id": next_id("proxy-run"),
            "generated_at": ts,
            "target": {"base_url": base_url},
            "stages": [
                {"name": "map", "tool": "offat-proxy", "version": env!("CARGO_PKG_VERSION"), "at": ts}
            ],
        },
        "asm": {"endpoints": asm_endpoints},
        "results": {"executions": executions},
    })
}

fn capture(f: &Flow) -> Value {
    let mut ex = Map::new();
    ex.insert("id".into(), json!(next_id("ex")));
    ex.insert("protocol".into(), json!("http"));
    ex.insert("at".into(), json!(rfc3339(f.at_ms)));
    ex.insert(
        "request".into(),
        json!({
            "method": f.request.method,
            "url": f.url(),
            "headers": headers_map(&f.request.headers),
            "body": f.request.body,
        }),
    );
    if let Some(r) = &f.response {
        let location = header_value(&r.headers, "location");
        ex.insert(
            "response".into(),
            json!({
                "status": r.status,
                "http_version": r.http_version,
                "content_type": r.content_type,
                "location": location,
                "body_snippet": snippet(&r.body, 2048),
                "latency_ms": f.latency_ms.unwrap_or(0),
            }),
        );
    } else if let Some(e) = &f.error {
        ex.insert("response".into(), json!({"error": e}));
    }
    Value::Object(ex)
}

fn merge_params(endpoint: &mut Value, f: &Flow) {
    let (_, query) = split_path(&f.request.path);
    let mut existing: std::collections::BTreeSet<String> = endpoint
        .get("params")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| {
                    let n = p.get("name").and_then(Value::as_str)?;
                    let l = p.get("location").and_then(Value::as_str)?;
                    Some(format!("{l}:{n}"))
                })
                .collect()
        })
        .unwrap_or_default();
    let params = endpoint
        .get_mut("params")
        .and_then(Value::as_array_mut)
        .expect("params is always an array");

    // path params from {id} segments
    let (path, _) = split_path(&f.request.path);
    for seg in template_path(&path).split('/') {
        if seg == "{id}" {
            let key = "path:id".to_string();
            if existing.insert(key) {
                params.push(json!({"name": "id", "location": "path", "type": "string"}));
            }
        }
    }
    // query params
    for (k, _v) in parse_query(&query) {
        let key = format!("query:{k}");
        if existing.insert(key) {
            params.push(json!({"name": k, "location": "query", "type": "string"}));
        }
    }
}

/// Split "/a/b?x=1" into ("/a/b", "x=1").
fn split_path(p: &str) -> (String, String) {
    match p.split_once('?') {
        Some((path, q)) => (path.to_string(), q.to_string()),
        None => (p.to_string(), String::new()),
    }
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    if q.is_empty() {
        return vec![];
    }
    q.split('&')
        .filter(|s| !s.is_empty())
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (kv.to_string(), String::new()),
        })
        .collect()
}

/// Replace variable-looking path segments with `{id}` so `/users/1` and
/// `/users/2` collapse to one endpoint `/users/{id}`.
pub fn template_path(path: &str) -> String {
    let parts: Vec<String> = path
        .split('/')
        .map(|seg| {
            if is_variable_segment(seg) {
                "{id}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();
    let joined = parts.join("/");
    if joined.is_empty() {
        "/".to_string()
    } else {
        joined
    }
}

fn is_variable_segment(seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    // all digits
    if seg.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // uuid-ish: 32+ hex with dashes
    let hexish = seg.chars().filter(|c| c.is_ascii_hexdigit()).count();
    if seg.len() >= 32 && hexish >= 32 {
        return true;
    }
    // long opaque hex token (ids, hashes)
    if seg.len() >= 16 && seg.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    false
}

fn endpoint_id(method: &str, path: &str) -> String {
    let slug: String = path
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("ep-{}-{}", method.to_lowercase(), slug.trim_matches('_'))
}

fn headers_map(headers: &[crate::flow::Header]) -> Value {
    let mut m = Map::new();
    for h in headers {
        m.insert(h.name.clone(), json!(h.value));
    }
    Value::Object(m)
}

fn header_value(headers: &[crate::flow::Header], name: &str) -> String {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.clone())
        .unwrap_or_default()
}

fn snippet(body: &str, n: usize) -> String {
    body.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Header, Request, Response};

    fn mkflow(method: &str, path: &str, in_scope: bool) -> Flow {
        let mut f = Flow::new(
            "127.0.0.1:1".into(),
            Request {
                method: method.into(),
                scheme: "https".into(),
                host: "api.example.test".into(),
                path: path.into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![Header {
                    name: "Accept".into(),
                    value: "*/*".into(),
                }],
                body: String::new(),
                body_truncated: false,
            },
            in_scope,
            true,
        );
        f.response = Some(Response {
            status: 200,
            http_version: "HTTP/1.1".into(),
            content_type: "application/json".into(),
            headers: vec![],
            body: "{}".into(),
            body_truncated: false,
        });
        f.latency_ms = Some(5);
        f
    }

    #[test]
    fn templating() {
        assert_eq!(template_path("/users/1"), "/users/{id}");
        assert_eq!(template_path("/users/1/posts/2"), "/users/{id}/posts/{id}");
        assert_eq!(template_path("/users/alice"), "/users/alice");
        assert_eq!(
            template_path("/o/550e8400-e29b-41d4-a716-446655440000"),
            "/o/{id}"
        );
        assert_eq!(template_path("/"), "/");
    }

    #[test]
    fn dedup_and_params() {
        let flows = vec![
            mkflow("GET", "/users/1?page=2", true),
            mkflow("GET", "/users/2?page=3", true),
        ];
        let b = flows_to_bundle(&flows, "https://api.example.test", true);
        let eps = b["asm"]["endpoints"].as_array().unwrap();
        assert_eq!(eps.len(), 1, "two /users/{{id}} collapse to one endpoint");
        let ep = &eps[0];
        assert_eq!(ep["path"], "/users/{id}");
        let params = ep["params"].as_array().unwrap();
        // should contain path:id and query:page, once each
        let names: Vec<String> = params
            .iter()
            .map(|p| {
                format!(
                    "{}:{}",
                    p["location"].as_str().unwrap(),
                    p["name"].as_str().unwrap()
                )
            })
            .collect();
        assert!(names.contains(&"path:id".to_string()));
        assert!(names.contains(&"query:page".to_string()));
        assert_eq!(names.iter().filter(|n| *n == "query:page").count(), 1);
        // two captures recorded
        assert_eq!(b["results"]["executions"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn only_scope_filters() {
        let flows = vec![mkflow("GET", "/a", true), mkflow("GET", "/b", false)];
        let b = flows_to_bundle(&flows, "https://api.example.test", true);
        assert_eq!(b["asm"]["endpoints"].as_array().unwrap().len(), 1);
        let b_all = flows_to_bundle(&flows, "https://api.example.test", false);
        assert_eq!(b_all["asm"]["endpoints"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn schema_version_and_meta_present() {
        let b = flows_to_bundle(&[mkflow("GET", "/a", true)], "https://x.test", true);
        assert_eq!(b["schema_version"], "1.0");
        assert!(b["meta"]["run_id"].is_string());
        assert!(b["meta"]["generated_at"].is_string());
    }
}

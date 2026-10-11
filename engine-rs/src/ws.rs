//! WebSocket driver (ws:// and wss://).
//!
//! Opens the handshake as the case's identity (auth headers on the upgrade
//! request), sends the payload as a single message - wrapped as JSON when the
//! case names a param - and captures the handshake status plus the first few
//! response frames. A `no-auth` case records whether the handshake succeeded
//! with no credentials, which the consolidation stage reads as a missing-auth
//! signal.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Map, Value};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

use crate::exec::{short, EndpointInfo};

/// Turn an http(s) base URL into a ws(s) one and append the endpoint path.
fn ws_url(base_url: &str, path: &str) -> String {
    let base = base_url.trim_end_matches('/');
    let base = if let Some(rest) = base.strip_prefix("https://") {
        format!("wss://{}", rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        format!("ws://{}", rest)
    } else if base.starts_with("ws://") || base.starts_with("wss://") {
        base.to_string()
    } else {
        format!("ws://{}", base)
    };
    format!("{}/{}", base, path.trim_start_matches('/'))
}

/// The message body to send: a JSON object when the case names a param, else the
/// raw payload (or a benign ping string when there is nothing to send).
fn ws_message(param: &str, payload: &str) -> String {
    if !param.is_empty() {
        let mut m = Map::new();
        m.insert(param.to_string(), Value::String(payload.to_string()));
        Value::Object(m).to_string()
    } else if !payload.is_empty() {
        payload.to_string()
    } else {
        "{\"offat\":\"probe\"}".to_string()
    }
}

/// Execute one WebSocket case.
pub async fn execute(
    base_url: &str,
    endpoints: &HashMap<String, EndpointInfo>,
    case: &Value,
    extra_headers: &[(String, String)],
    identities: &HashMap<String, Vec<(String, String)>>,
) -> Value {
    let case_id = case.get("id").and_then(Value::as_str).unwrap_or("");
    let proto = case
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("ws")
        .to_lowercase();
    let ep_id = case.get("endpoint").and_then(Value::as_str).unwrap_or("");
    let ep = match endpoints.get(ep_id) {
        Some(e) => e.clone(),
        None => {
            return json!({
                "id": format!("ex-{}", short(case_id)),
                "case_id": case_id, "protocol": proto,
                "response": {"error": format!("unknown endpoint {}", ep_id)},
            })
        }
    };

    let payload = case.get("payload").and_then(Value::as_str).unwrap_or("");
    let param = case.get("param").and_then(Value::as_str).unwrap_or("");
    let id_name = case.get("identity").and_then(Value::as_str).unwrap_or("");

    let mut headers: Vec<(String, String)> = extra_headers.to_vec();
    if !id_name.is_empty() {
        if let Some(h) = identities.get(id_name) {
            headers.extend(h.iter().cloned());
        }
    }

    let url = ws_url(base_url, &ep.path);
    let response = connect_and_probe(&url, &headers, param, payload).await;

    json!({
        "id": format!("ex-{}", short(case_id)),
        "case_id": case_id, "protocol": proto,
        "request": {"url": url, "param": param, "payload": payload, "identity": id_name},
        "response": response,
        "baseline": {},
    })
}

async fn connect_and_probe(
    url: &str,
    headers: &[(String, String)],
    param: &str,
    payload: &str,
) -> Value {
    let mut request = match url.into_client_request() {
        Ok(r) => r,
        Err(e) => return json!({"error": format!("bad ws url: {}", e)}),
    };
    for (k, v) in headers {
        if let Ok(val) = HeaderValue::from_str(v) {
            if let Ok(name) =
                tokio_tungstenite::tungstenite::http::header::HeaderName::from_bytes(k.as_bytes())
            {
                request.headers_mut().insert(name, val);
            }
        }
    }

    let started = Instant::now();
    let connect = tokio::time::timeout(
        Duration::from_secs(15),
        tokio_tungstenite::connect_async(request),
    )
    .await;
    let (mut stream, http_resp) = match connect {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            // A handshake rejection is the expected, healthy outcome for a
            // protected socket reached without credentials.
            return json!({
                "connected": false,
                "handshake_status": handshake_status(&e),
                "error": e.to_string(),
                "latency_ms": started.elapsed().as_millis() as u64,
            });
        }
        Err(_) => return json!({"error": "ws connect timed out", "connected": false}),
    };
    let handshake = http_resp.status().as_u16();

    // Send the probe message, then read a few frames with a short budget.
    let _ = stream.send(Message::Text(ws_message(param, payload))).await;

    let mut frames: Vec<String> = Vec::new();
    let deadline = Duration::from_secs(3);
    let read_started = Instant::now();
    while read_started.elapsed() < deadline && frames.len() < 5 {
        match tokio::time::timeout(Duration::from_millis(800), stream.next()).await {
            Ok(Some(Ok(msg))) => match msg {
                Message::Text(t) => frames.push(t.chars().take(1024).collect()),
                Message::Binary(b) => frames.push(format!("<binary {} bytes>", b.len())),
                Message::Close(_) => break,
                _ => {}
            },
            Ok(Some(Err(_))) | Ok(None) => break,
            Err(_) => break, // read budget elapsed
        }
    }
    let _ = stream.close(None).await;

    let first_text = frames.first().cloned().unwrap_or_default();
    json!({
        "connected": true,
        "handshake_status": handshake,
        "frames": frames,
        "first_text": first_text,
        "latency_ms": started.elapsed().as_millis() as u64,
    })
}

/// Best-effort HTTP status for a rejected handshake.
fn handshake_status(e: &tokio_tungstenite::tungstenite::Error) -> u16 {
    if let tokio_tungstenite::tungstenite::Error::Http(resp) = e {
        resp.status().as_u16()
    } else {
        0
    }
}

//! Shared, UI-agnostic view helpers used by both the terminal UI and the desktop
//! GUI. Keeping this logic here (not in a feature-gated module) means it is always
//! compiled and unit-tested, regardless of which front-ends are built.

use crate::flow::Flow;
use crate::rule::ParsedExpr;

/// Indices of flows that pass the optional filter, in chronological order.
pub fn visible_indices(flows: &[Flow], filter: &Option<ParsedExpr>) -> Vec<usize> {
    flows
        .iter()
        .enumerate()
        .filter(|(_, f)| filter.as_ref().map(|e| e.matches(f)).unwrap_or(true))
        .map(|(i, _)| i)
        .collect()
}

/// A short status label for a flow (HTTP status, "ERR", or "-").
pub fn status_label(f: &Flow) -> String {
    match f.response.as_ref().map(|r| r.status) {
        Some(s) if s > 0 => s.to_string(),
        _ if f.error.is_some() => "ERR".to_string(),
        _ => "-".to_string(),
    }
}

/// Status-class bucket for colouring: "blocked", "error", "5xx", "4xx", "2xx", "other".
pub fn status_class(f: &Flow) -> &'static str {
    let code = f.response.as_ref().map(|r| r.status).unwrap_or(0);
    if f.tags.iter().any(|t| t == "blocked" || t == "dropped") {
        "blocked"
    } else if f.error.is_some() {
        "error"
    } else if code >= 500 {
        "5xx"
    } else if code >= 400 {
        "4xx"
    } else if (200..300).contains(&code) {
        "2xx"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{Header, Request, Response};
    use crate::rule::parse_expr;

    fn flow(path: &str, status: u16) -> Flow {
        let mut f = Flow::new(
            "c".into(),
            Request {
                method: "GET".into(),
                scheme: "https".into(),
                host: "api.test".into(),
                path: path.into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![Header {
                    name: "Accept".into(),
                    value: "*/*".into(),
                }],
                body: String::new(),
                body_truncated: false,
            },
            true,
            true,
        );
        if status > 0 {
            f.response = Some(Response {
                status,
                http_version: "HTTP/1.1".into(),
                content_type: "application/json".into(),
                headers: vec![],
                body: String::new(),
                body_truncated: false,
            });
        }
        f
    }

    #[test]
    fn filter_selects_matching() {
        let flows = vec![flow("/a", 200), flow("/b", 500), flow("/c", 404)];
        let f = Some(parse_expr("status >= 400").unwrap());
        assert_eq!(visible_indices(&flows, &f), vec![1, 2]);
        assert_eq!(visible_indices(&flows, &None), vec![0, 1, 2]);
    }

    #[test]
    fn labels_and_classes() {
        assert_eq!(status_label(&flow("/a", 200)), "200");
        assert_eq!(status_label(&flow("/a", 0)), "-");
        assert_eq!(status_class(&flow("/a", 200)), "2xx");
        assert_eq!(status_class(&flow("/a", 503)), "5xx");
        assert_eq!(status_class(&flow("/a", 404)), "4xx");
        let mut blocked = flow("/a", 403);
        blocked.tags.push("blocked".into());
        assert_eq!(status_class(&blocked), "blocked");
    }
}

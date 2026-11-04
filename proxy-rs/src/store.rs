//! Shared, bounded flow store. A ring buffer keeps memory flat under sustained
//! traffic; optional JSONL spill persists sanitized flows with 0600 perms.

use crate::config::Config;
use crate::flow::Flow;
use crate::scope::Scope;
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex, RwLock};

/// Process-wide state shared by the proxy loop and the MCP/control surface.
pub struct AppState {
    pub config: Config,
    pub scope: RwLock<Scope>,
    rules: RwLock<crate::rule::RuleSet>,
    flows: Mutex<VecDeque<Flow>>,
    spill: Mutex<Option<std::fs::File>>,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    pub fn new(config: Config, scope: Scope) -> std::io::Result<SharedState> {
        let spill = if config.persist {
            Some(open_spill(&config)?)
        } else {
            None
        };
        Ok(Arc::new(AppState {
            config,
            scope: RwLock::new(scope),
            rules: RwLock::new(crate::rule::RuleSet::default()),
            flows: Mutex::new(VecDeque::new()),
            spill: Mutex::new(spill),
        }))
    }

    pub fn set_rules(&self, rules: crate::rule::RuleSet) {
        *self.rules.write().expect("rules lock poisoned") = rules;
    }

    pub fn rules_snapshot(&self) -> crate::rule::RuleSet {
        self.rules.read().expect("rules lock poisoned").clone()
    }

    /// Record a completed flow. Applies redaction/scope on the persisted copy and
    /// evicts the oldest entry once the ring is full.
    pub fn record(&self, flow: Flow) {
        let sanitized = flow.sanitized(self.config.redact);
        if let Ok(mut guard) = self.spill.lock() {
            if let Some(file) = guard.as_mut() {
                if let Ok(line) = serde_json::to_string(&sanitized) {
                    let _ = writeln!(file, "{line}");
                }
            }
        }
        let mut flows = self.flows.lock().expect("flows mutex poisoned");
        if flows.len() >= self.config.max_flows {
            flows.pop_front();
        }
        flows.push_back(sanitized);
    }

    pub fn get(&self, id: &str) -> Option<Flow> {
        let flows = self.flows.lock().expect("flows mutex poisoned");
        flows.iter().find(|f| f.id == id).cloned()
    }

    pub fn all(&self) -> Vec<Flow> {
        let flows = self.flows.lock().expect("flows mutex poisoned");
        flows.iter().cloned().collect()
    }

    pub fn count(&self) -> usize {
        self.flows.lock().expect("flows mutex poisoned").len()
    }

    pub fn set_scope(&self, scope: Scope) {
        *self.scope.write().expect("scope lock poisoned") = scope;
    }

    pub fn scope_snapshot(&self) -> Scope {
        self.scope.read().expect("scope lock poisoned").clone()
    }
}

fn open_spill(config: &Config) -> std::io::Result<std::fs::File> {
    std::fs::create_dir_all(&config.state_dir)?;
    restrict_dir(&config.state_dir);
    let path = config.state_dir.join("flows.jsonl");
    let file = open_private(&path)?;
    Ok(file)
}

/// Open a file for append with owner-only perms (0600) on Unix.
pub fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(unix)]
fn restrict_dir(dir: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &std::path::Path) {}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::flow::{Header, Request};

    fn flow(host: &str) -> Flow {
        Flow::new(
            "127.0.0.1:1".into(),
            Request {
                method: "GET".into(),
                scheme: "http".into(),
                host: host.into(),
                path: "/".into(),
                http_version: "HTTP/1.1".into(),
                headers: vec![Header {
                    name: "X".into(),
                    value: "y".into(),
                }],
                body: String::new(),
                body_truncated: false,
            },
            true,
            false,
        )
    }

    #[test]
    fn ring_buffer_evicts_oldest() {
        let mut cfg = Config::default();
        cfg.max_flows = 2;
        let st = AppState::new(cfg, Scope::default()).unwrap();
        st.record(flow("a"));
        st.record(flow("b"));
        st.record(flow("c"));
        assert_eq!(st.count(), 2);
        let hosts: Vec<_> = st.all().iter().map(|f| f.request.host.clone()).collect();
        assert_eq!(hosts, vec!["b", "c"]);
    }

    #[test]
    fn all_returns_in_order() {
        let st = AppState::new(Config::default(), Scope::default()).unwrap();
        st.record(flow("api.example.test"));
        st.record(flow("cdn.other.test"));
        let hosts: Vec<_> = st.all().iter().map(|f| f.request.host.clone()).collect();
        assert_eq!(hosts, vec!["api.example.test", "cdn.other.test"]);
    }
}

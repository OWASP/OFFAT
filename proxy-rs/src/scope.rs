//! Scope rules. Passive capture records every connection, but only in-scope
//! hosts keep bodies and become test surface; active behaviour (replay, fuzz,
//! MITM) is refused outside scope. Default is "capture everything, trust
//! nothing": an empty allowlist means nothing is in scope for active use.

use crate::util::wildcard_match;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scope {
    /// Host globs that are in scope, e.g. `api.example.test`, `*.example.test`.
    pub include: Vec<String>,
    /// Host globs explicitly excluded; checked first and always wins.
    pub exclude: Vec<String>,
}

impl Scope {
    pub fn new(include: Vec<String>, exclude: Vec<String>) -> Self {
        Self { include, exclude }
    }

    /// Normalize a host: strip any port and lowercase.
    fn host_only(host: &str) -> &str {
        // IPv6 literals arrive bracketed ([::1]:443); leave the bracket form,
        // just drop a trailing :port after the last ']' or for plain hosts.
        if let Some(idx) = host.rfind(']') {
            return &host[..=idx];
        }
        match host.split_once(':') {
            Some((h, _)) => h,
            None => host,
        }
    }

    /// Is this host permitted for active actions (replay/fuzz/MITM)?
    pub fn allows(&self, host: &str) -> bool {
        let h = Self::host_only(host);
        if self.exclude.iter().any(|p| wildcard_match(p, h)) {
            return false;
        }
        self.include.iter().any(|p| wildcard_match(p, h))
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_exclude() {
        let s = Scope::new(
            vec!["*.example.test".into()],
            vec!["admin.example.test".into()],
        );
        assert!(s.allows("api.example.test"));
        assert!(s.allows("api.example.test:8443"));
        assert!(!s.allows("admin.example.test")); // excluded
        assert!(!s.allows("evil.test")); // not included
    }

    #[test]
    fn empty_scope_denies_active() {
        let s = Scope::default();
        assert!(!s.allows("api.example.test"));
        assert!(s.is_empty());
    }

    #[test]
    fn ipv6_literal_kept() {
        let s = Scope::new(vec!["[::1]".into()], vec![]);
        assert!(s.allows("[::1]:8443"));
    }
}

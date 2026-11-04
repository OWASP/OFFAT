//! Runtime configuration and its safe defaults.
//!
//! Defaults are chosen so an accidental run is harmless: loopback only, no TLS
//! interception, redaction on, bounded memory, empty active scope.

use crate::flow::DEFAULT_BODY_CAP;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    /// Allow binding a non-loopback address (refused otherwise, to avoid an open relay).
    pub allow_public: bool,
    /// Require this Basic `Proxy-Authorization` (user, pass) from clients.
    pub proxy_auth: Option<(String, String)>,
    /// Intercept TLS (MITM). Requires the `mitm` build feature and an installed CA.
    pub mitm: bool,
    /// Redact credentials in persisted/exported flows.
    pub redact: bool,
    /// Verify upstream TLS certificates. Disabling is opt-in and loud.
    pub verify_upstream_tls: bool,
    /// Cap on stored request/response bodies.
    pub body_cap: usize,
    /// Max flows kept in the ring buffer.
    pub max_flows: usize,
    /// Directory for CA material and flow spill. Created 0700.
    pub state_dir: PathBuf,
    /// Append sanitized flows to `state_dir/flows.jsonl`.
    pub persist: bool,
    /// Allowlist mode: block any request whose host is not in scope.
    pub block_out_of_scope: bool,
}

impl Default for Config {
    fn default() -> Self {
        let state_dir = default_state_dir();
        Self {
            listen: SocketAddr::from(([127, 0, 0, 1], 8080)),
            allow_public: false,
            proxy_auth: None,
            mitm: false,
            redact: true,
            verify_upstream_tls: true,
            body_cap: DEFAULT_BODY_CAP,
            max_flows: 5000,
            state_dir,
            persist: false,
            block_out_of_scope: false,
        }
    }
}

impl Config {
    /// Guard against turning the proxy into an open relay.
    pub fn validate(&self) -> Result<(), String> {
        let ip = self.listen.ip();
        let is_loopback = match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        };
        if !is_loopback && !self.allow_public {
            return Err(format!(
                "refusing to bind non-loopback address {} without --allow-public \
                 (an open proxy is a security risk); bind 127.0.0.1 or pass --allow-public with proxy auth",
                self.listen
            ));
        }
        if !is_loopback && self.proxy_auth.is_none() {
            return Err(
                "binding a public address requires --proxy-auth user:pass so the proxy is not open to the network"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub fn default_state_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("OFFAT_PROXY_HOME") {
        return PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".offat").join("proxy")
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    #[test]
    fn loopback_ok_without_flag() {
        let c = Config::default();
        assert!(c.validate().is_ok());
    }

    #[test]
    fn public_bind_refused_by_default() {
        let mut c = Config::default();
        c.listen = SocketAddr::from(([0, 0, 0, 0], 8080));
        assert!(c.validate().is_err());
    }

    #[test]
    fn public_bind_needs_auth() {
        let mut c = Config::default();
        c.listen = SocketAddr::from(([0, 0, 0, 0], 8080));
        c.allow_public = true;
        assert!(c.validate().is_err()); // no auth
        c.proxy_auth = Some(("u".into(), "p".into()));
        assert!(c.validate().is_ok());
    }
}

//! Small dependency-free helpers: RFC3339 timestamps, id generation, and a
//! minimal `*` wildcard matcher used by scope rules.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A short, monotonic, process-unique id. Not a UUID - we never need global
/// uniqueness, only stable local references between flows, cases and captures.
pub fn next_id(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{:x}-{:x}", now_ms(), n)
}

/// Format epoch milliseconds as an RFC3339 UTC timestamp (seconds precision),
/// e.g. `2026-11-03T12:34:56Z`. Hand-rolled to avoid a date dependency; matches
/// the format the rest of the pipeline emits.
pub fn rfc3339(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since 1970-01-01 -> (year, month, day). Howard Hinnant's civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Case-insensitive glob match supporting `*` (any run, including empty). Used for
/// host scope patterns like `*.example.test`. `?` and character classes are not
/// supported on purpose - scope rules should stay obvious.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_ascii_lowercase().chars().collect();
    let t: Vec<char> = text.to_ascii_lowercase().chars().collect();
    // Classic two-pointer backtracking matcher, O(n) amortized.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = ti;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_epoch() {
        // 2021-01-01T00:00:00Z == 1609459200s
        assert_eq!(rfc3339(1_609_459_200_000), "2021-01-01T00:00:00Z");
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn wildcard() {
        assert!(wildcard_match("*.example.test", "api.example.test"));
        assert!(wildcard_match("*.example.test", "a.b.example.test"));
        assert!(wildcard_match("api.example.test", "api.example.test"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("api.*", "api.example.test"));
        assert!(!wildcard_match("*.example.test", "example.test"));
        assert!(!wildcard_match("api.example.test", "evil.test"));
        // case-insensitive
        assert!(wildcard_match("*.Example.Test", "API.example.test"));
    }
}

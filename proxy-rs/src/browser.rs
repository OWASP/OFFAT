//! Launch a Chromium-family browser already wired to the proxy.
//!
//! The browser is started in a dedicated, throwaway profile (so the user's real
//! browser and its trust store are never touched) pointed at the proxy. When TLS
//! interception is on, it is given the CA's SPKI hash via
//! `--ignore-certificate-errors-spki-list`, so it trusts certificates minted by
//! *this* CA only - never a blanket "ignore all certificate errors". When
//! interception is off, HTTPS tunnels through untouched and the real certificate
//! is validated normally, so no trust flag is needed.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

/// Options for a browser launch.
pub struct LaunchOptions<'a> {
    pub proxy: SocketAddr,
    pub profile_dir: PathBuf,
    pub url: Option<String>,
    /// CA SPKI hash (base64) to pin-trust. `None` when MITM is off.
    pub spki: Option<String>,
    /// Pass `--headless=new` (for CI/containers without a display).
    pub headless: bool,
    /// Pass `--no-sandbox` (needed in some containers; avoid on real machines).
    pub no_sandbox: bool,
    /// Explicit browser name or path override.
    pub browser: Option<&'a str>,
}

/// Candidate Chromium-family executables, in preference order. Values are either
/// bare names (resolved on PATH) or absolute paths.
fn candidates() -> Vec<(&'static str, String)> {
    let mut v: Vec<(&'static str, String)> = vec![
        ("chrome", "google-chrome".into()),
        ("chrome", "google-chrome-stable".into()),
        ("chromium", "chromium".into()),
        ("chromium", "chromium-browser".into()),
        ("edge", "microsoft-edge".into()),
        ("brave", "brave-browser".into()),
        // macOS application bundles
        (
            "chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into(),
        ),
        (
            "chromium",
            "/Applications/Chromium.app/Contents/MacOS/Chromium".into(),
        ),
        (
            "brave",
            "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser".into(),
        ),
        (
            "edge",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge".into(),
        ),
    ];
    // Playwright's bundled Chromium, if present (common in CI/dev images).
    if let Some(p) = playwright_chromium() {
        v.insert(0, ("chromium", p));
    }
    v
}

fn playwright_chromium() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let base = Path::new(&home).join(".cache").join("ms-playwright");
    let entries = std::fs::read_dir(&base).ok()?;
    let mut hits: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("chromium"))
                .unwrap_or(false)
        })
        .collect();
    hits.sort();
    for dir in hits.into_iter().rev() {
        for sub in ["chrome-linux", "chrome-linux-arm64"] {
            let bin = dir.join(sub).join("chrome");
            if bin.is_file() {
                return Some(bin.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn on_path_or_abs(cmd: &str) -> Option<PathBuf> {
    let p = Path::new(cmd);
    if p.is_absolute() {
        return p.is_file().then(|| p.to_path_buf());
    }
    crate::pipeline::which(cmd)
}

/// Resolve the browser executable, honoring an explicit name/path override.
pub fn resolve(preferred: Option<&str>) -> Result<(String, PathBuf)> {
    if let Some(pref) = preferred {
        // Treat an override containing a path separator (or absolute) as a path.
        if pref.contains(std::path::MAIN_SEPARATOR) || Path::new(pref).is_absolute() {
            if let Some(p) = on_path_or_abs(pref) {
                return Ok(("custom".into(), p));
            }
            return Err(anyhow!("browser path not found: {pref}"));
        }
        // Otherwise match by family/name against candidates, then try PATH directly.
        for (fam, cmd) in candidates() {
            if fam == pref.to_ascii_lowercase() {
                if let Some(p) = on_path_or_abs(&cmd) {
                    return Ok((fam.to_string(), p));
                }
            }
        }
        if let Some(p) = on_path_or_abs(pref) {
            return Ok((pref.to_string(), p));
        }
        return Err(anyhow!("no '{pref}' browser found on this system"));
    }
    for (fam, cmd) in candidates() {
        if let Some(p) = on_path_or_abs(&cmd) {
            return Ok((fam.to_string(), p));
        }
    }
    Err(anyhow!(
        "no Chromium-family browser found. Install Chrome/Chromium or pass --browser-path"
    ))
}

/// Build the argv for a launch (pure, so it can be unit-tested).
pub fn build_args(opts: &LaunchOptions) -> Vec<String> {
    let mut args = vec![
        format!("--proxy-server=http://{}", opts.proxy),
        // Send even loopback targets through the proxy (useful for local test apps).
        "--proxy-bypass-list=<-loopback>".to_string(),
        format!("--user-data-dir={}", opts.profile_dir.display()),
        "--no-first-run".to_string(),
        "--no-default-browser-check".to_string(),
        "--no-service-autorun".to_string(),
        "--disable-background-networking".to_string(),
    ];
    if let Some(spki) = &opts.spki {
        // Trust leaves chaining to our CA's key only - not all certificate errors.
        args.push(format!("--ignore-certificate-errors-spki-list={spki}"));
    }
    if opts.headless {
        args.push("--headless=new".to_string());
    }
    if opts.no_sandbox {
        // Container-friendly flags: no sandbox, and don't rely on /dev/shm or a GPU.
        args.push("--no-sandbox".to_string());
        args.push("--disable-dev-shm-usage".to_string());
        args.push("--disable-gpu".to_string());
    }
    args.push(
        opts.url
            .clone()
            .unwrap_or_else(|| "about:blank".to_string()),
    );
    args
}

/// Resolve and spawn the browser. Returns the child and a human-readable summary.
pub fn launch(opts: &LaunchOptions) -> Result<(Child, String, Vec<String>)> {
    let (family, path) = resolve(opts.browser)?;
    std::fs::create_dir_all(&opts.profile_dir)?;
    let args = build_args(opts);
    let child = Command::new(&path)
        .args(&args)
        .spawn()
        .map_err(|e| anyhow!("launching {}: {e}", path.display()))?;
    let summary = format!(
        "launched {family} ({}) pid {} via proxy {}{}",
        path.display(),
        child.id(),
        opts.proxy,
        if opts.spki.is_some() {
            " [CA pin-trusted]"
        } else {
            ""
        }
    );
    Ok((child, summary, args))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(spki: Option<String>) -> LaunchOptions<'static> {
        LaunchOptions {
            proxy: "127.0.0.1:8080".parse().unwrap(),
            profile_dir: PathBuf::from("/tmp/offat-prof"),
            url: Some("https://api.example.test/".into()),
            spki,
            headless: true,
            no_sandbox: true,
            browser: None,
        }
    }

    #[test]
    fn args_include_proxy_profile_and_url() {
        let a = build_args(&opts(None));
        assert!(a
            .iter()
            .any(|x| x == "--proxy-server=http://127.0.0.1:8080"));
        assert!(a.iter().any(|x| x.starts_with("--user-data-dir=")));
        assert!(a.iter().any(|x| x == "--headless=new"));
        assert!(a.iter().any(|x| x == "--no-sandbox"));
        assert_eq!(a.last().unwrap(), "https://api.example.test/");
        // no trust flag when spki is absent
        assert!(!a.iter().any(|x| x.contains("spki-list")));
    }

    #[test]
    fn spki_pin_added_when_present() {
        let a = build_args(&opts(Some("ABC123==".into())));
        assert!(a
            .iter()
            .any(|x| x == "--ignore-certificate-errors-spki-list=ABC123=="));
    }

    #[test]
    fn resolve_rejects_missing_path() {
        let err = resolve(Some("/no/such/browser/here")).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }
}

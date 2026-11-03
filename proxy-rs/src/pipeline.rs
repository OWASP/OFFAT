//! Thin, shell-free wrappers around the existing OFFAT tools.
//!
//! The proxy never re-implements test-gen, triage or reporting and never calls a
//! model API directly - it shells out (argv arrays, never a shell string, so
//! captured target data can't be interpreted as a command) to `offat-platform`
//! and `offat-engine`, which route AI through `offat_triage` as the project
//! requires. Each tool is optional; if it isn't installed we say so instead of
//! failing opaquely.

use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;
use tokio::process::Command;

#[derive(Debug, Serialize)]
pub struct CmdResult {
    pub program: String,
    pub args: Vec<String>,
    pub found: bool,
    pub exit_code: Option<i32>,
    pub stdout_tail: String,
    pub stderr_tail: String,
}

/// Locate an executable on PATH without spawning a shell.
pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn tail(s: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(s);
    if text.len() <= max {
        return text.into_owned();
    }
    let start = text.len() - max;
    format!("...{}", &text[start..])
}

/// Run a program with an argv array, capturing bounded stdout/stderr.
pub async fn run(program: &str, args: &[String]) -> Result<CmdResult> {
    let found = which(program).is_some();
    if !found {
        return Ok(CmdResult {
            program: program.to_string(),
            args: args.to_vec(),
            found: false,
            exit_code: None,
            stdout_tail: String::new(),
            stderr_tail: format!(
                "`{program}` not found on PATH. Install the OFFAT tools (see OFFAT README) and retry."
            ),
        });
    }
    let output = Command::new(program).args(args).output().await?;
    Ok(CmdResult {
        program: program.to_string(),
        args: args.to_vec(),
        found: true,
        exit_code: output.status.code(),
        stdout_tail: tail(&output.stdout, 8192),
        stderr_tail: tail(&output.stderr, 8192),
    })
}

/// Execute a Bundle's test plan against an authorized target with `offat-engine`.
/// The caller must have already verified authorization (scope + confirm).
#[allow(clippy::too_many_arguments)]
pub async fn run_engine(
    bundle: &str,
    url: &str,
    out: &str,
    yes: bool,
    concurrency: u32,
    rate: f64,
    headers: &[String],
) -> Result<CmdResult> {
    if !yes {
        anyhow::bail!("run_engine requires confirm=true (authorized-use gate)");
    }
    let mut args = vec![
        "--bundle".into(),
        bundle.to_string(),
        "--url".into(),
        url.to_string(),
        "--out".into(),
        out.to_string(),
        "--concurrency".into(),
        concurrency.to_string(),
        "--rate".into(),
        rate.to_string(),
        "--yes".into(),
    ];
    for h in headers {
        args.push("-H".into());
        args.push(h.clone());
    }
    run("offat-engine", &args).await
}

/// Run the source-aware platform pipeline (`offat-platform run ...`).
pub async fn run_platform(args: &[String]) -> Result<CmdResult> {
    run("offat-platform", args).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_tool_reports_cleanly() {
        let r = run("definitely-not-a-real-binary-xyz", &[]).await.unwrap();
        assert!(!r.found);
        assert!(r.stderr_tail.contains("not found on PATH"));
    }

    #[tokio::test]
    async fn engine_requires_confirm() {
        let err = run_engine("b.json", "https://x.test", "o.json", false, 10, 25.0, &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("confirm=true"));
    }

    #[test]
    fn which_finds_sh() {
        // `sh` exists on any POSIX CI runner.
        assert!(which("sh").is_some());
    }
}

//! offat-proxy - an intercepting proxy for authorized OFFAT API security testing,
//! with an inbuilt MCP server.
//!
//! Subcommands:
//!   run       start the proxy (capture live traffic)
//!   mcp       start the proxy AND the MCP stdio server (drive the pipeline from an agent)
//!   ca        print the local CA certificate to install into a TEST trust store (mitm build)
//!   export    convert a persisted flows.jsonl into an OFFAT Bundle (offline)
//!
//! Authorized use only. Passive capture records traffic you route through it;
//! active actions (replay/fuzz, the engine, and TLS interception) are gated on an
//! explicit scope and confirmation, and credentials are redacted by default.

mod browser;
mod bundle;
#[cfg(feature = "mitm")]
mod ca;
mod config;
mod flow;
mod mcp;
mod pipeline;
mod proxy;
mod replay;
mod rule;
mod scope;
mod store;
mod tui;
mod util;
mod ws;

use anyhow::{Context, Result};
use config::Config;
use scope::Scope;
use std::net::SocketAddr;
use std::sync::Arc;

struct Cli {
    command: String,
    config: Config,
    scope: Scope,
    // browser launch (run/mcp)
    open_browser: bool,
    browser: Option<String>,
    browser_profile: Option<String>,
    browser_url: Option<String>,
    browser_headless: bool,
    browser_no_sandbox: bool,
    rules_file: Option<String>,
    inline_rules: Vec<String>,
    // export-only
    flows_in: String,
    out: String,
    only_scope: bool,
    base_url: String,
}

fn usage() -> ! {
    eprintln!(
        "offat-proxy - intercepting proxy + MCP for authorized OFFAT API testing\n\n\
Usage:\n  offat-proxy <run|tui|mcp|ca|export> [flags]\n\n\
Commands:\n  \
run       start the proxy and capture traffic you route through it\n  \
tui       start the proxy with a live terminal UI (flow viewer + filters)\n  \
mcp       start the proxy and an MCP server on stdio (for an AI agent)\n  \
ca        print the local CA cert to install into a TEST trust store\n  \
export    build an OFFAT Bundle from a persisted flows.jsonl\n\n\
Common flags:\n  \
--listen <addr>        bind address (default 127.0.0.1:8080)\n  \
--scope <host-glob>    add a host to the active-use scope (repeatable)\n  \
--exclude <host-glob>  exclude a host from scope (repeatable)\n  \
--mitm                 intercept TLS (needs a CA installed in a test store)\n  \
--no-redact            do NOT redact credentials in stored/exported flows\n  \
--insecure-upstream    do not verify upstream TLS certificates\n  \
--allow-public         permit binding a non-loopback address (needs --proxy-auth)\n  \
--proxy-auth <u:p>     require Basic proxy authentication\n  \
--state-dir <path>     CA + spill directory (default ~/.offat/proxy)\n  \
--persist              append sanitized flows to <state-dir>/flows.jsonl\n  \
--body-cap <bytes>     max stored body size (default 1048576)\n  \
--max-flows <n>        ring-buffer size (default 5000)\n\n\
Rules (live block / allow / tag / match-replace; see docs/proxy.md):\n  \
--rules <file>         load a rules file (one rule per line)\n  \
--rule '<rule>'        add one inline rule, e.g. 'block when host == \"evil.test\"' (repeatable)\n  \
--block-out-of-scope   allowlist mode: block any request whose host is not in scope\n\n\
Browser (run/mcp) - launch a browser wired to the proxy:\n  \
--open-browser         launch a Chromium-family browser pointed at the proxy\n  \
--browser <name|path>  chrome|chromium|edge|brave, or an explicit binary path\n  \
--browser-profile <d>  throwaway profile dir (default <state-dir>/browser-profile)\n  \
--browser-url <url>    initial URL to open (default: first scope host)\n  \
--browser-headless     run headless (for CI/containers)\n  \
--browser-no-sandbox   pass --no-sandbox (some containers; avoid on real machines)\n\n\
export flags:\n  \
--flows <file.jsonl>   input flows (default <state-dir>/flows.jsonl)\n  \
--out <file.json>      output Bundle (required)\n  \
--base-url <url>       meta.target.base_url\n  \
--all                  include out-of-scope flows (default: in-scope only)\n"
    );
    std::process::exit(2);
}

fn parse_cli() -> Cli {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    let command = args[0].clone();
    if command == "-h" || command == "--help" || command == "help" {
        usage();
    }

    let mut config = Config::default();
    let mut include = Vec::new();
    let mut exclude = Vec::new();
    let mut flows_in = String::new();
    let mut out = String::new();
    let mut base_url = String::new();
    let mut only_scope = true;
    let mut open_browser = false;
    let mut browser: Option<String> = None;
    let mut browser_profile: Option<String> = None;
    let mut browser_url: Option<String> = None;
    let mut browser_headless = false;
    let mut browser_no_sandbox = false;
    let mut rules_file: Option<String> = None;
    let mut inline_rules: Vec<String> = Vec::new();

    let mut i = 1;
    let val = |args: &[String], i: &mut usize| -> String {
        *i += 1;
        args.get(*i).cloned().unwrap_or_else(|| usage())
    };
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                let s = val(&args, &mut i);
                config.listen = s.parse::<SocketAddr>().unwrap_or_else(|_| {
                    eprintln!("invalid --listen address: {s}");
                    std::process::exit(2);
                });
            }
            "--scope" => include.push(val(&args, &mut i)),
            "--exclude" => exclude.push(val(&args, &mut i)),
            "--mitm" => config.mitm = true,
            "--no-redact" => config.redact = false,
            "--insecure-upstream" => config.verify_upstream_tls = false,
            "--allow-public" => config.allow_public = true,
            "--proxy-auth" => {
                let s = val(&args, &mut i);
                match s.split_once(':') {
                    Some((u, p)) => config.proxy_auth = Some((u.to_string(), p.to_string())),
                    None => {
                        eprintln!("--proxy-auth expects user:pass");
                        std::process::exit(2);
                    }
                }
            }
            "--state-dir" => config.state_dir = val(&args, &mut i).into(),
            "--persist" => config.persist = true,
            "--body-cap" => {
                config.body_cap = val(&args, &mut i).parse().unwrap_or(flow::DEFAULT_BODY_CAP)
            }
            "--max-flows" => config.max_flows = val(&args, &mut i).parse().unwrap_or(5000),
            "--rules" => rules_file = Some(val(&args, &mut i)),
            "--rule" => inline_rules.push(val(&args, &mut i)),
            "--block-out-of-scope" => config.block_out_of_scope = true,
            "--open-browser" => open_browser = true,
            "--browser" => browser = Some(val(&args, &mut i)),
            "--browser-profile" => browser_profile = Some(val(&args, &mut i)),
            "--browser-url" => browser_url = Some(val(&args, &mut i)),
            "--browser-headless" => browser_headless = true,
            "--browser-no-sandbox" => browser_no_sandbox = true,
            "--flows" => flows_in = val(&args, &mut i),
            "--out" => out = val(&args, &mut i),
            "--base-url" => base_url = val(&args, &mut i),
            "--all" => only_scope = false,
            other => {
                eprintln!("unknown flag: {other}");
                usage();
            }
        }
        i += 1;
    }

    Cli {
        command,
        config,
        scope: Scope::new(include, exclude),
        open_browser,
        browser,
        browser_profile,
        browser_url,
        browser_headless,
        browser_no_sandbox,
        rules_file,
        inline_rules,
        flows_in,
        out,
        only_scope,
        base_url,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = parse_cli();
    match cli.command.as_str() {
        "run" => cmd_serve(cli, false).await,
        "tui" => cmd_tui(cli).await,
        "mcp" => cmd_serve(cli, true).await,
        "ca" => cmd_ca(cli),
        "export" => cmd_export(cli),
        other => {
            eprintln!("unknown command: {other}");
            usage();
        }
    }
}

/// Validate config, build shared state + rules, start the proxy task, and
/// optionally launch a browser. Shared by `run`, `tui`, and `mcp`.
async fn start(cli: &Cli) -> Result<(Arc<proxy::ProxyRuntime>, tokio::task::JoinHandle<()>)> {
    cli.config.validate().map_err(|e| anyhow::anyhow!(e))?;
    print_safety_banner(&cli.config, &cli.scope);

    let state = store::AppState::new(cli.config.clone(), cli.scope.clone())
        .context("initializing flow store")?;

    // Load rules (file first, then inline rules appended) and fail fast on syntax.
    let mut rules_src = String::new();
    if let Some(path) = &cli.rules_file {
        rules_src.push_str(
            &std::fs::read_to_string(path).with_context(|| format!("reading rules file {path}"))?,
        );
        rules_src.push('\n');
    }
    for r in &cli.inline_rules {
        rules_src.push_str(r);
        rules_src.push('\n');
    }
    if !rules_src.trim().is_empty() {
        let rs =
            rule::RuleSet::parse(&rules_src).map_err(|e| anyhow::anyhow!("rule error: {e}"))?;
        eprintln!("  loaded {} rule(s)", rs.rules.len());
        state.set_rules(rs);
    }
    if cli.config.block_out_of_scope {
        eprintln!("  allowlist mode ON: requests to out-of-scope hosts are blocked (403)");
    }

    let runtime = build_runtime(&cli.config, state)?;

    // The proxy always runs as a task so we can launch a browser once it's bound.
    let proxy_rt = runtime.clone();
    let proxy_task = tokio::spawn(async move {
        if let Err(e) = proxy::serve(proxy_rt).await {
            eprintln!("proxy error: {e}");
        }
    });

    if cli.open_browser {
        if wait_listen(cli.config.listen).await {
            if let Err(e) = launch_browser(cli, &runtime) {
                eprintln!("could not launch browser: {e}");
            }
        } else {
            eprintln!("proxy did not become ready in time; skipping browser launch");
        }
    }

    Ok((runtime, proxy_task))
}

async fn cmd_serve(cli: Cli, with_mcp: bool) -> Result<()> {
    let (runtime, proxy_task) = start(&cli).await?;
    if with_mcp {
        // MCP owns stdio in the foreground; the proxy keeps running behind it.
        mcp::serve(runtime).await
    } else {
        proxy_task.await.ok();
        Ok(())
    }
}

async fn cmd_tui(cli: Cli) -> Result<()> {
    let (runtime, _proxy_task) = start(&cli).await?;
    // The TUI event loop is blocking (crossterm); run it off the async runtime
    // while the proxy keeps serving on background tasks.
    tokio::task::spawn_blocking(move || tui::run(runtime)).await?
}

/// Poll the listen address until the proxy accepts connections (or we give up).
async fn wait_listen(addr: SocketAddr) -> bool {
    for _ in 0..30 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    false
}

fn launch_browser(cli: &Cli, runtime: &Arc<proxy::ProxyRuntime>) -> Result<()> {
    let profile_dir = cli
        .browser_profile
        .clone()
        .map(Into::into)
        .unwrap_or_else(|| cli.config.state_dir.join("browser-profile"));
    let url = cli
        .browser_url
        .clone()
        .or_else(|| default_browser_url(&cli.scope));
    let spki = runtime.ca_spki();
    if cli.config.mitm && spki.is_none() {
        eprintln!(
            "note: --mitm set but no CA available; HTTPS pages in the browser will show cert warnings"
        );
    }
    let opts = browser::LaunchOptions {
        proxy: cli.config.listen,
        profile_dir,
        url,
        spki,
        headless: cli.browser_headless,
        no_sandbox: cli.browser_no_sandbox,
        browser: cli.browser.as_deref(),
    };
    let (child, summary, _args) = browser::launch(&opts)?;
    eprintln!("{summary}");
    // Detach: the browser runs independently of the proxy process.
    std::mem::forget(child);
    Ok(())
}

/// Default landing URL: the first in-scope host (https when MITM-capable).
fn default_browser_url(scope: &Scope) -> Option<String> {
    scope.include.first().map(|h| {
        let host = h.trim_start_matches("*.");
        format!("https://{host}/")
    })
}

#[cfg(feature = "mitm")]
fn build_runtime(config: &Config, state: store::SharedState) -> Result<Arc<proxy::ProxyRuntime>> {
    if config.mitm {
        let authority = ca::CertAuthority::load_or_create(&config.state_dir)
            .context("loading TLS-interception CA")?;
        eprintln!(
            "TLS interception ON. Install the CA from `offat-proxy ca --state-dir {}` into a TEST trust store only.",
            config.state_dir.display()
        );
        proxy::ProxyRuntime::with_ca(state, Arc::new(authority))
    } else {
        proxy::ProxyRuntime::new(state)
    }
}

#[cfg(not(feature = "mitm"))]
fn build_runtime(config: &Config, state: store::SharedState) -> Result<Arc<proxy::ProxyRuntime>> {
    if config.mitm {
        eprintln!("warning: this build has no `mitm` feature; CONNECT tunnels stay opaque.");
    }
    proxy::ProxyRuntime::new(state)
}

fn cmd_ca(cli: Cli) -> Result<()> {
    #[cfg(feature = "mitm")]
    {
        let authority = ca::CertAuthority::load_or_create(&cli.config.state_dir)
            .context("loading/creating CA")?;
        // The CA *certificate* is public material (the whole point of this command
        // is to install it); the private key is never printed. Emit it as program
        // output on stdout rather than through a logging macro.
        use std::io::Write;
        let mut stdout = std::io::stdout();
        stdout.write_all(authority.ca_cert_pem().as_bytes())?;
        stdout.write_all(b"\n")?;
        eprintln!(
            "\nInstall the certificate above ONLY into a dedicated test trust store \
             (e.g. a throwaway browser profile) for targets you are authorized to test. \
             The private key lives at {}/ca_key.pem (owner-only) and never leaves this machine.",
            cli.config.state_dir.display()
        );
        Ok(())
    }
    #[cfg(not(feature = "mitm"))]
    {
        let _ = cli;
        anyhow::bail!("this build was compiled without the `mitm` feature");
    }
}

fn cmd_export(cli: Cli) -> Result<()> {
    let path = if cli.flows_in.is_empty() {
        cli.config.state_dir.join("flows.jsonl")
    } else {
        cli.flows_in.clone().into()
    };
    if cli.out.is_empty() {
        anyhow::bail!("export requires --out <file.json>");
    }
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading flows from {}", path.display()))?;
    let mut flows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<flow::Flow>(line) {
            Ok(f) => flows.push(f),
            Err(e) => eprintln!("skipping malformed flow line: {e}"),
        }
    }
    let base_url = if cli.base_url.is_empty() {
        flows
            .iter()
            .find(|f| (!cli.only_scope || f.in_scope) && !f.request.host.is_empty())
            .map(|f| format!("{}://{}", f.request.scheme, f.request.host))
            .unwrap_or_default()
    } else {
        cli.base_url.clone()
    };
    let b = bundle::flows_to_bundle(&flows, &base_url, cli.only_scope);
    std::fs::write(&cli.out, serde_json::to_string_pretty(&b)?)?;
    eprintln!(
        "wrote {} ({} endpoints, {} captures) from {} flows",
        cli.out,
        b["asm"]["endpoints"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        b["results"]["executions"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        flows.len()
    );
    Ok(())
}

fn print_safety_banner(config: &Config, scope: &Scope) {
    eprintln!("offat-proxy - authorized use only.");
    if scope.is_empty() {
        eprintln!(
            "  active scope is EMPTY: passive capture only. Set --scope <host> to allow replay/fuzz/engine."
        );
    } else {
        eprintln!(
            "  active scope: include={:?} exclude={:?}",
            scope.include, scope.exclude
        );
    }
    if !config.redact {
        eprintln!("  WARNING: --no-redact is set; stored/exported flows will contain credentials.");
    }
    if !config.verify_upstream_tls {
        eprintln!("  WARNING: upstream TLS verification is OFF (--insecure-upstream).");
    }
}

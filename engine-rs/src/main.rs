//! offat-engine - the OFFAT-AI execution engine.
//!
//! Reads an OFFAT Bundle, executes its `test_plan` cases against an authorized
//! target, captures each request/response, and writes the `results` section back
//! into the Bundle. HTTP/1.1 and HTTP/2 are implemented; gRPC, WebSocket and
//! HTTP/3/QUIC are the next protocol increments (recognized and recorded as
//! skipped until then).
//!
//! Authorized use only: this sends real attack traffic. Pass --yes to confirm you
//! own or are permitted to test the target.

mod exec;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use tokio::sync::{Mutex, Semaphore};

struct Opts {
    bundle: String,
    url: String,
    out: String,
    concurrency: usize,
    rate: f64,
    timeout: u64,
    insecure: bool,
    yes: bool,
    headers: Vec<(String, String)>,
    identities: String,
}

fn usage() -> ! {
    eprintln!(
        "offat-engine - OFFAT-AI execution engine (HTTP/1.1 + HTTP/2)\n\n\
Usage:\n  offat-engine --bundle in.offat.json --url https://target [flags]\n\n\
Flags:\n  --bundle <path>     input Bundle (required)\n  --url <base>        target base URL (required)\n  \
--out <path>        output Bundle (default: overwrite input)\n  --concurrency <n>   concurrent requests (default 10)\n  \
--rate <n>          max requests/sec, 0 = unlimited (default 25)\n  --timeout <s>       per-request timeout (default 15)\n  \
-H 'Name: Value'    extra header (repeatable)\n  --insecure          skip TLS verification\n  \
--yes               confirm you are authorized to scan the target"
    );
    std::process::exit(2);
}

fn parse_args() -> Opts {
    let mut o = Opts {
        bundle: String::new(),
        url: String::new(),
        out: String::new(),
        concurrency: 10,
        rate: 25.0,
        timeout: 15,
        insecure: false,
        yes: false,
        headers: Vec::new(),
        identities: String::new(),
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].clone();
        let value = |idx: &mut usize| -> String {
            *idx += 1;
            args.get(*idx).cloned().unwrap_or_else(|| usage())
        };
        match a.as_str() {
            "--bundle" => o.bundle = value(&mut i),
            "--url" => o.url = value(&mut i),
            "--out" => o.out = value(&mut i),
            "--concurrency" => o.concurrency = value(&mut i).parse().unwrap_or(10),
            "--rate" => o.rate = value(&mut i).parse().unwrap_or(25.0),
            "--timeout" => o.timeout = value(&mut i).parse().unwrap_or(15),
            "-H" => {
                let h = value(&mut i);
                if let Some((k, v)) = h.split_once(':') {
                    o.headers.push((k.trim().to_string(), v.trim().to_string()));
                }
            }
            "--identities" => o.identities = value(&mut i),
            "--insecure" => o.insecure = true,
            "--yes" => o.yes = true,
            "-h" | "--help" => usage(),
            _ => {
                eprintln!("unknown argument: {}", a);
                usage();
            }
        }
        i += 1;
    }
    if o.bundle.is_empty() || o.url.is_empty() {
        usage();
    }
    if o.out.is_empty() {
        o.out = o.bundle.clone();
    }
    o
}

fn load_identities(path: &str) -> HashMap<String, Vec<(String, String)>> {
    let mut map = HashMap::new();
    if path.is_empty() {
        return map;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return map,
    };
    let data: Value = match serde_json::from_str(&text) {
        Ok(d) => d,
        Err(_) => return map,
    };
    if let Some(arr) = data.as_array() {
        for it in arr {
            let name = it.get("name").and_then(Value::as_str).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let mut hs = Vec::new();
            if let Some(h) = it.get("headers").and_then(Value::as_object) {
                for (k, v) in h {
                    if let Some(vs) = v.as_str() {
                        hs.push((k.clone(), vs.to_string()));
                    }
                }
            }
            map.insert(name.to_string(), hs);
        }
    }
    map
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = parse_args();

    let text = std::fs::read_to_string(&opts.bundle)
        .with_context(|| format!("reading {}", opts.bundle))?;
    let mut bundle: Value = serde_json::from_str(&text).context("parsing bundle JSON")?;

    let cases: Vec<Value> = bundle
        .get("test_plan")
        .and_then(|t| t.get("cases"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if cases.is_empty() {
        return Err(anyhow!(
            "bundle has no test_plan.cases - run `offat-platform test-gen` first"
        ));
    }

    if !opts.yes {
        eprintln!(
            "\nWARNING: this will send active attack traffic to {}",
            opts.url
        );
        eprintln!("Only scan systems you own or are explicitly authorized to test.");
        eprintln!("Re-run with --yes to confirm authorization and proceed.");
        std::process::exit(3);
    }

    let endpoints = Arc::new(exec::index_endpoints(&bundle));
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(opts.insecure)
        .timeout(Duration::from_secs(opts.timeout))
        .user_agent("offat-engine/0.1")
        .build()
        .context("building HTTP client")?;

    println!(
        "Executing {} case(s) against {} ({} workers, rate {}/s)...",
        cases.len(),
        opts.url,
        opts.concurrency,
        opts.rate
    );

    let identities = Arc::new(load_identities(&opts.identities));
    if !opts.identities.is_empty() {
        println!(
            "Loaded {} identities for access-control tests",
            identities.len()
        );
    }
    let sem = Arc::new(Semaphore::new(opts.concurrency.max(1)));
    let headers = Arc::new(opts.headers.clone());
    let min_gap = if opts.rate > 0.0 {
        Some(Duration::from_secs_f64(1.0 / opts.rate))
    } else {
        None
    };
    let next_slot = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let done = Arc::new(AtomicUsize::new(0));
    let total = cases.len();

    let mut set = tokio::task::JoinSet::new();
    for case in cases {
        let permit = sem.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let base = opts.url.clone();
        let endpoints = endpoints.clone();
        let headers = headers.clone();
        let identities = identities.clone();
        let next_slot = next_slot.clone();
        let done = done.clone();

        // Rate limit: reserve the next send slot.
        if let Some(gap) = min_gap {
            let mut slot = next_slot.lock().await;
            let now = tokio::time::Instant::now();
            let at = if *slot > now { *slot } else { now };
            *slot = at + gap;
            drop(slot);
            tokio::time::sleep_until(at).await;
        }

        set.spawn(async move {
            let _permit = permit;
            let ex = exec::execute(&client, &base, &endpoints, &case, &headers, &identities).await;
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            if n % 25 == 0 || n == total {
                eprintln!("  {}/{}", n, total);
            }
            ex
        });
    }

    let mut executions: Vec<Value> = Vec::with_capacity(total);
    while let Some(res) = set.join_next().await {
        if let Ok(ex) = res {
            executions.push(ex);
        }
    }

    // Write results back and record the stage.
    let results = bundle
        .as_object_mut()
        .unwrap()
        .entry("results")
        .or_insert_with(|| serde_json::json!({"executions": []}));
    results
        .as_object_mut()
        .unwrap()
        .insert("executions".to_string(), Value::Array(executions));

    if let Some(stages) = bundle
        .get_mut("meta")
        .and_then(|m| m.get_mut("stages"))
        .and_then(Value::as_array_mut)
    {
        stages.push(
            serde_json::json!({"name": "execute", "tool": "offat-engine", "version": "0.1.0"}),
        );
    }

    std::fs::write(&opts.out, serde_json::to_string_pretty(&bundle)?)
        .with_context(|| format!("writing {}", opts.out))?;
    println!("Wrote {} execution(s) to {}", total, opts.out);
    Ok(())
}

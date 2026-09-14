---
name: offat-whitebox
description: >
  Run the OFFAT-AI white-box (SAST) pipeline over a codebase — recon, hunt,
  chain, verify, report — following the security-harness workflow. Use when the
  user wants a static source-code security review, to "find vulnerabilities in
  this repo", scan for secrets/injection/insecure deserialization, or generate a
  security report from code they own.
---

# OFFAT-AI — White-box (SAST)

Drive the Python pipeline that reviews source code: detects the stack, hunts
vulnerabilities (built-in multi-language pattern hunter + semgrep when present),
chains co-located issues, triages them (AI or heuristic) and writes reports.

Scope is **owned or authorized code only** (no live testing of third parties).

## Steps

1. **Point at the codebase** (a local path). Deepen results by installing the
   optional scanners when available: `semgrep`, `syft`, `grype` (all optional —
   the pipeline runs without them and notes what was skipped).

2. **Run the pipeline:**
   ```bash
   python -m offat_wb <path-to-repo> --out offat-report/whitebox
   ```
   Run it from the repo root, or `pip install ./triager ./whitebox` first so
   `offat-whitebox` is on PATH.
   - AI triage engages when `OFFAT_AI_API_KEY` is set; else heuristic. `--no-ai`
     forces heuristic; `--no-semgrep` skips semgrep. No key? Use a local agent
     CLI with `--provider claude-code` or `--provider codex`.
   - Limit classes with `--classes sqli,secrets,command_injection`.

3. **Report.** Read `offat-report/whitebox/report.md`, then summarize by severity
   and verdict with `file:line`, the code snippet, and remediation. The run also
   emits `report.html`, `report.json`, `findings.jsonl` and `results.sarif`.

## Stages

| Stage | What it does |
|---|---|
| recon | language mix, dependency manifests, SBOM (syft), CVEs (grype/trivy/osv) |
| hunt | secrets, injection sinks, unsafe deserialization, weak crypto, TLS-off, XSS, SSRF, misconfig; + semgrep `--config auto` |
| chain | annotate co-located source/sink findings into attack paths |
| verify | AI/heuristic triager refutes then validates each finding |
| report | JSON, JSONL, SARIF, Markdown, HTML |

For a deeper, agentic multi-pass review, prefer the upstream
[security-harness](https://github.com/dmdhrumilmistry/security-harness) plugin;
this pipeline is the automation-friendly, CI-runnable counterpart.

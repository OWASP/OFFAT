---
name: offat-triage
description: >
  Re-triage an existing OFFAT-AI findings file (report.json / findings.jsonl, or
  any JSON/JSONL list of findings) with the shared AI/heuristic triager to add or
  refresh verdicts, CVSS and remediation. Use when the user wants to validate
  findings, cut false positives, or apply AI triage to results scanned earlier.
---

# OFFAT-AI — Triage

Apply the shared triager to findings that already exist, without rescanning.

## Steps

1. **Find the input** — a DAST or white-box `report.json`, a `findings.jsonl`,
   or any JSON array/object of findings.

2. **Run:**
   ```bash
   python -m offat_triage <findings-file> -o triaged.json
   ```
   - AI triage runs when `OFFAT_AI_API_KEY` (or `ANTHROPIC_API_KEY`) is set;
     otherwise it uses the deterministic heuristic. Force heuristic with
     `--no-ai`. Pick a backend with `--provider anthropic|claude-code|codex`
     (`claude-code`/`codex` use a signed-in local CLI, no API key needed).
   - Run from `triager/`, or `pip install ./triager` for the `offat-triage`
     command.

3. **Summarize** the verdict distribution (confirmed / likely / inconclusive /
   false_positive) and highlight anything downgraded to false_positive versus
   promoted to confirmed.

The triager adversarially verifies each finding (tries to refute it first) and
writes a `triage` block: `{verdict, confidence, cvss, severity, rationale,
remediation, source}`.

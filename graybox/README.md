# OFFAT-AI Gray-box (`offat-graybox`)

Gray-box = the white-box view (source, data-flow sinks) fused with a black-box
view (the HTTP endpoint attack surface, mapped from source with
[graft](https://github.com/NanoNets/Graft)) and analyzed together by AI. It
sends **no live traffic**: reachability comes from the structural call graph, and
AI tokens are spent only where they pay off.

```
recon -> map endpoints (graft) -> hunt (SAST) -> reachability -> analyze (AI) -> report
```

## Why gray-box

A SAST hit says "there is a dangerous sink at `file:line`". On its own that is
noisy. Gray-box asks the next question: **is that sink reachable from an exposed
endpoint?** It maps every route from source, links routes to sinks through the
call graph, and has the AI judge each finding with that reachability context -
so an unauthenticated-reachable sink is escalated and a dead-code sink is capped.

## Token discipline

The only token-spending stage is AI analysis, and it is kept cheap by design:

1. **Reachable-only.** Findings no endpoint reaches are triaged offline (0 tokens).
2. **Batched + tiered.** Reachable findings are screened in batches by a cheap
   model; only the confirmed/likely subset is re-checked by a strong model.
3. **Cached.** Verdicts are keyed on a content hash; re-runs pay only for new or
   changed findings.

Every AI path degrades to a deterministic heuristic, so a run never breaks and
never requires a key.

## Usage

```bash
pip install ./triager ./whitebox ./graybox
offat-graybox /path/to/your/repo               # AI if a provider is available
offat-graybox ./repo --no-ai                   # offline, heuristic only
offat-graybox ./repo --provider claude-code    # drive a local agent CLI
offat-graybox ./repo --fail-on high            # CI gate on reachable high+ findings
```

| Flag | Description |
|---|---|
| `--classes` | comma-separated vuln classes to hunt (default: all) |
| `-o, --out` | output directory (default `offat-report/graybox`) |
| `--no-ai` | heuristic triage only (no tokens) |
| `--provider` | `auto` (default), `anthropic`, `claude-code`, `codex`, `heuristic` |
| `--no-semgrep` | skip semgrep even if installed |
| `--no-graft` | map endpoints natively instead of via graft |
| `--no-cache` | do not read/write the AI-verdict cache |
| `--fail-on` | exit non-zero if an actionable finding is at/above this severity |

Model tiers are overridable: `OFFAT_GB_SCREEN_MODEL`, `OFFAT_GB_VERIFY_MODEL`,
`OFFAT_GB_BATCH_SIZE`.

## Output

`report.json`, `findings.jsonl`, `endpoints.json`, `results.sarif`, `report.md`,
`report.html`, `report.junit.xml`. Findings carry `reachable`, `reachable_from`
and `source_mode: graybox`.

## Credits

The multi-stage methodology mirrors the public
[security-harness](https://github.com/dmdhrumilmistry/security-harness) workflow
(recon -> hunt -> chain -> verify -> report).

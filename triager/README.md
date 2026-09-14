# offat-triage

The shared triager used by both halves of OFFAT-AI. It validates candidate
security findings and enriches each with a **verdict**, **CVSS**, and
**remediation**.

- **Heuristic triager** — deterministic, offline, no dependencies.
- **AI triager** — Anthropic Messages API; adversarially verifies each finding
  (tries to refute it first). Falls back to the heuristic on any error.

Pure standard library — no third-party packages.

## Use as a CLI

```bash
# Re-triage a DAST report (or any JSON/JSONL findings file)
python -m offat_triage offat-report/report.json -o triaged.json

# Heuristic only (no network)
python -m offat_triage findings.jsonl --no-ai
```

Enable AI triage by exporting a key:

```bash
export OFFAT_AI_API_KEY=sk-ant-...
export OFFAT_AI_MODEL=claude-sonnet-5   # optional; override to track latest
python -m offat_triage report.json
```

## Use as a library

```python
from offat_triage import triage_findings, heuristic_triage

source = triage_findings(findings, use_ai=True)   # mutates each finding in place
```

A *finding* is a dict; the triager writes a `triage` sub-dict:
`{verdict, confidence, cvss, severity, rationale, remediation, source}`.

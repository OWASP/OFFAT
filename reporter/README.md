# OFFAT-AI Reporter (`offat-report`)

Phase 6 of the platform: render an [OFFAT Bundle](../bundle/README.md) into
deliverables. Bundle in, reports out - a pure transform, so it works on any
Bundle produced by the pipeline.

```bash
pip install ./reporter            # add ./triager for OWASP API category names
offat-report app.offat.json -o reports --formats all
```

| Format | File | Notes |
|---|---|---|
| `sarif` | `results.sarif` | SARIF 2.1.0 (GitHub code scanning, etc.) |
| `md` | `report.md` | Markdown summary + findings |
| `html` | `report.html` | self-contained; renders the threat-model DFD (Mermaid) |
| `compliance` | `compliance.md` | OWASP API Top 10 (2023) coverage + ASVS notes |
| `pdf` | `report.pdf` | best-effort via wkhtmltopdf or headless Chrome; skipped with a note if neither is present |

`--formats` takes a comma-separated list (default `sarif,md,html,compliance`) or
`all`. The reporter reads `findings`, `summary`, `threat_model` and `meta` from the
Bundle; richer input (run the full pipeline first) yields richer reports.

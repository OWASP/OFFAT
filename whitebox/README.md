# offat-whitebox

The white-box (SAST) half of OFFAT-AI. A multi-stage source-code security
review modeled on the [security-harness](https://github.com/dmdhrumilmistry/security-harness)
workflow:

```
recon  ->  hunt  ->  chain  ->  verify (triage)  ->  report
```

- **recon** — detect the tech stack, inventory dependency manifests, generate an
  SBOM (syft) and CVE findings (grype / trivy / osv-scanner) when installed.
- **hunt** — a dependency-free, multi-language **built-in pattern hunter**
  (secrets, dangerous sinks, weak crypto, unsafe deserialization, TLS-off, XSS,
  SSRF, misconfig) plus **semgrep** (`--config auto`) when installed.
- **chain** — annotate co-located findings into simple attack paths.
- **verify** — the shared AI/heuristic triager refutes then validates each
  finding, assigning verdict / CVSS / remediation.
- **report** — JSON, JSONL, SARIF 2.1.0, Markdown and HTML.

Every external tool is optional; the pipeline runs end-to-end with none of them
installed and records what was skipped.

## Usage

```bash
python -m offat_wb /path/to/repo                 # from the repo (no install)
offat-whitebox /path/to/repo --no-ai -o out/     # if installed

# hunt only specific classes
python -m offat_wb . --classes sqli,secrets,command_injection
```

Enable AI triage with `OFFAT_AI_API_KEY` (see `../triager`).

## Tool integration

| Stage | Preferred | Alternatives | Fallback |
|---|---|---|---|
| SBOM | syft | — | manifest inventory |
| CVEs | grype | trivy, osv-scanner | skipped |
| Hunt | semgrep `--config auto` | — | built-in pattern hunter (always) |
| Map  | graft (`npx @nanonets/graft`) | — | language/manifest recon |

Install the scanners to deepen results, e.g. `brew install semgrep syft grype`.

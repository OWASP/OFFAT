# OFFAT-AI Platform (`offat-platform`)

Orchestrates the staged platform pipeline over a single
[Bundle](../bundle/README.md). See [`../docs/platform.md`](../docs/platform.md)
for the full design.

Implemented now (Phases 1-6):

- **`map`** - attack surface (endpoints with params + response fields), sink/
  source inventory, and the **parameter relation graph** (PRG), written into a
  Bundle. `--threat-model` also runs the next stage.
- **`threat-model`** - assets, trust boundaries, data flows, **STRIDE threats**
  mapped to the OWASP API Top 10 + CWE with a likelihood x impact risk, and a
  Mermaid data-flow diagram.
- **`test-gen`** - a **test plan**: injection vectors matched to each param by
  location and name hints, multi-step cases seeded from the PRG, and (with
  `--identities`) **BOLA / BFLA / RBAC / broken-auth / business-logic** cases.
  Optional `--ai` payload augmentation.
- **`triage`** - detect DAST findings from the engine's `results`, fold in SAST
  sinks, attach the OWASP/CWE threat mapping, triage (tiered/cached), and write
  `findings` + `summary` (with `--fail-on`).
- **`validate`** - check a Bundle against the schema and its cross-references.

```bash
pip install ./bundle ./triager ./whitebox ./graybox ./platform
offat-platform map /path/to/repo --threat-model -o out/app.offat.json
offat-platform test-gen out/app.offat.json --identities examples/identities.example.json
offat-engine --bundle out/app.offat.json --url https://target --yes   # execute (Rust)
offat-platform triage out/app.offat.json --fail-on high               # findings + summary
offat-platform validate out/app.offat.json
```

The `map` stage reuses the gray-box endpoint mapper (decorator routes **and**
OpenAPI/Swagger specs, carrying params and response fields) and the white-box
hunter (sinks). The PRG links an endpoint's **response fields** (producers) to
another endpoint's **request params** (consumers) when they refer to the same
value, so a later stage can seed Y's input from X's output (and replay foreign
identifiers for BOLA/IDOR).

The remaining phase adds the reporter (Bundle -> SARIF/HTML/MD/PDF/compliance) and
the visualizer, both consuming the same Bundle.

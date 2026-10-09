# OFFAT-AI Platform (`offat-platform`)

Orchestrates the staged platform pipeline over a single
[Bundle](../bundle/README.md). See [`../docs/platform.md`](../docs/platform.md)
for the full design.

Implemented now (Phase 1):

- **`map`** - attack surface (endpoints with params + response fields), sink/
  source inventory, and the **parameter relation graph** (PRG), written into a
  Bundle.
- **`validate`** - check a Bundle against the schema and its cross-references.

```bash
pip install ./bundle ./triager ./whitebox ./graybox ./platform
offat-platform map /path/to/repo -o out/app.offat.json
offat-platform validate out/app.offat.json
```

The `map` stage reuses the gray-box endpoint mapper (decorator routes **and**
OpenAPI/Swagger specs, carrying params and response fields) and the white-box
hunter (sinks). The PRG links an endpoint's **response fields** (producers) to
another endpoint's **request params** (consumers) when they refer to the same
value, so a later stage can seed Y's input from X's output (and replay foreign
identifiers for BOLA/IDOR).

Later phases add `threat-model`, `test-gen`, `execute` (the Rust engine),
`triage` and `report`, each reading and writing the same Bundle.

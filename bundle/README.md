# OFFAT Bundle (`offat-bundle`)

The canonical interchange document for the OFFAT-AI platform - one JSON file that
every pipeline stage reads and writes. It is the backbone described in
[`../docs/platform.md`](../docs/platform.md) and the import/export format for the
reporter and the visualizer.

## Sections

`schema_version` and `meta` are required; every other section is optional, so a
partial Bundle from an early stage is valid and later stages fill in their part.

| Section | Written by | Holds |
|---|---|---|
| `meta` | every stage | target, run id, tool/versions, `stages[]` |
| `asm` | map | endpoints (method, path, protocol, params, auth, responses, source) |
| `inventory` | map | sinks and sources (class, symbol, file:line, CWE) |
| `prg` | PRG | param nodes + producer->consumer edges |
| `threat_model` | threat modeling | assets, trust boundaries, data flows, threats, Mermaid DFD |
| `test_plan` | test-gen | test cases (endpoint/param, technique, payload, protocol, origin, chain) |
| `results` | engine | request/response captures |
| `findings` | triage | canonical findings + threat refs + triage |
| `summary` | any writer | rolled-up counts |

The authoritative contract is
[`offat_bundle/schema/offat-bundle-v1.schema.json`](offat_bundle/schema/offat-bundle-v1.schema.json).

## Use

```python
from offat_bundle import (new_bundle, endpoint, add_endpoint, sink, add_sink,
                          record_stage, validate_bundle, save, load, merge)

b = new_bundle(target={"source_path": "./repo"})
ep = add_endpoint(b, endpoint("GET", "/users/{id}", handler="get_user"))
add_sink(b, sink("sqli", symbol="get_user", file="views.py", line=8, cwe="CWE-89"))
record_stage(b, "map", tool="offat-graybox", version="1.0.0")

problems = validate_bundle(b)       # [] when valid
save(b, "run.offat.json")
```

Merge partial bundles from different stages (list sections union by id, later
wins; `meta.stages` concatenate):

```python
merged = merge(load("map.offat.json"), load("results.offat.json"))
```

## Validation

`validate_bundle(bundle)` returns a list of problems (empty = valid). It uses
`jsonschema` when installed (`pip install offat-bundle[validate]`) and otherwise
falls back to a dependency-free structural check. `cross_refs(bundle)` reports
dangling references between sections.

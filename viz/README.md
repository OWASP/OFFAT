# OFFAT-AI Visualizer

Phase 7: a dependency-free static web app that imports an
[OFFAT Bundle](../bundle/README.md) and visualizes it. No backend, no build step,
no external libraries - open `index.html` in a browser and import a
`*.offat.json` file (or drag it in).

## Views

- **Attack surface** - every endpoint with method, path, handler, params, source.
- **Parameter graph** - the PRG as an inline SVG: producers (response fields, left)
  linked to consumers (request params, right); hover an edge for its basis and
  confidence.
- **Threat model** - the data-flow diagram (Mermaid source) and the ranked STRIDE
  threats mapped to OWASP API Top 10 + CWE.
- **Findings** - filterable by severity and free text, with verdict and source.

Summary cards across the top; **Import** and **Export** in the header (export
re-downloads the current Bundle). `?url=<same-origin path>` auto-loads a Bundle.

## Use

```bash
# any static server works, or just open the file
python -m http.server -d viz 8080      # then http://localhost:8080
```

Produce a Bundle to load with the rest of the pipeline:

```bash
offat-platform map ./repo --threat-model -o app.offat.json
offat-platform test-gen app.offat.json
offat-engine --bundle app.offat.json --url https://target --yes
offat-platform triage app.offat.json
# open viz/index.html and import app.offat.json
```

## Tests

`tests/dom_smoke.js` runs the render logic under a minimal DOM shim in Node
(`node tests/dom_smoke.js`) to confirm each view populates. Full in-browser
rendering is exercised manually.

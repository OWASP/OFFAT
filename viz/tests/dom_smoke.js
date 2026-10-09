// Minimal DOM shim to exercise app.js render logic in Node (no browser).
// Not a full browser test - it verifies the render functions populate each view.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

function el() {
  const e = {
    _html: "", _text: "",
    hidden: false, disabled: false, value: "", style: {},
    children: [],
    classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
    addEventListener() {}, removeEventListener() {},
    closest() { return null; }, getAttribute() { return null; }, click() {},
    querySelector() { return el(); },
  };
  Object.defineProperty(e, "innerHTML", { get() { return e._html; }, set(v) { e._html = String(v); } });
  Object.defineProperty(e, "textContent", { get() { return e._text; }, set(v) { e._text = String(v); } });
  Object.defineProperty(e, "onchange", { get() { return e._oc; }, set(v) { e._oc = v; } });
  Object.defineProperty(e, "oninput", { get() { return e._oi; }, set(v) { e._oi = v; } });
  return e;
}

const registry = {};
const document = {
  getElementById(id) { return (registry[id] = registry[id] || el()); },
  createElement() { return el(); },
  addEventListener() {},
};
const sandbox = {
  document, window: {}, location: { search: "" }, console,
  URLSearchParams, Blob: function () {}, FileReader: function () {}, URL: { createObjectURL() { return ""; }, revokeObjectURL() {} },
  fetch: undefined, alert() {},
};
sandbox.window = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(path.join(__dirname, "..", "app.js"), "utf8"), sandbox);

const bundle = {
  schema_version: "1.0",
  meta: { run_id: "r1", generated_at: "2026-01-01T00:00:00Z", target: { source_path: "./repo" }, stages: [{ name: "map" }] },
  asm: { endpoints: [{ id: "ep-1", method: "GET", path: "/users/{id}", handler: "get_user", params: [{ name: "id", location: "path" }], source: { file: "v.py", line: 8 } }] },
  prg: { nodes: [{ id: "p1", kind: "producer", name: "id" }, { id: "c1", kind: "consumer", name: "id" }], edges: [{ from: "p1", to: "c1", basis: "exact-name", confidence: 0.9 }] },
  threat_model: { dfd_mermaid: "graph LR\n client --> ep_1", threats: [{ stride: "Tampering", title: "SQLi", owasp_api: "API8:2023", cwe: "CWE-89", risk: "high", mitigation: "parameterize" }] },
  findings: [{ id: "f1", class: "sqli", title: "SQLi on /users", severity: "high", endpoint: "ep-1", source_mode: "dast", threat: { owasp_api: "API8:2023", cwe: "CWE-89" }, triage: { verdict: "confirmed" } }],
  summary: { endpoints: 1, test_cases: 2, executions: 2, threats: 1, findings: 1, by_severity: { high: 1 } },
};

// The severity <select> defaults to "all" in a browser; seed it in the shim.
document.getElementById("fsev").value = "all";
sandbox.window.OFFAT.render(bundle);

function assert(cond, msg) { if (!cond) { console.error("FAIL:", msg); process.exit(1); } }
assert(/Endpoints/.test(registry.cards.innerHTML), "cards rendered");
assert(/\/users\/\{id\}/.test(registry["view-surface"].innerHTML), "surface rendered");
assert(/<svg/.test(registry["view-prg"].innerHTML), "prg svg rendered");
assert(/Threats|data-flow|graph LR/i.test(registry["view-threats"].innerHTML), "threats rendered");
// renderFindings writes the filters into view-findings and the table into #ftab.
assert(/Severity/.test(registry["view-findings"].innerHTML), "findings filters rendered");
assert(/SQLi on \/users/.test(registry.ftab.innerHTML), "findings table rendered");
assert(registry.app.hidden === false, "app shown");
console.log("viz dom smoke OK");

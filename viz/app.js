/* OFFAT-AI Visualizer - dependency-free. Imports an OFFAT Bundle and renders the
   attack surface, parameter relation graph, threat model and findings. Export
   downloads the current bundle. Everything runs in the browser; no backend. */
(function () {
  "use strict";
  var STATE = { bundle: null };
  var SEVS = ["critical", "high", "medium", "low", "info"];
  var esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };
  var $ = function (id) { return document.getElementById(id); };

  function render(bundle) {
    STATE.bundle = bundle;
    var meta = bundle.meta || {};
    var tgt = (meta.target || {}).source_path || (meta.target || {}).base_url || "";
    $("target").textContent = tgt ? ("target: " + tgt) : "";
    $("drop").hidden = true;
    $("app").hidden = false;
    $("export").disabled = false;
    renderCards(bundle);
    renderSurface(bundle);
    renderPRG(bundle);
    renderThreats(bundle);
    renderFindings(bundle);
  }

  function renderCards(b) {
    var s = b.summary || {};
    var asm = (b.asm || {}).endpoints || [];
    var cards = [
      ["Endpoints", s.endpoints != null ? s.endpoints : asm.length],
      ["Test cases", s.test_cases || ((b.test_plan || {}).cases || []).length],
      ["Executions", s.executions || ((b.results || {}).executions || []).length],
      ["Threats", s.threats || ((b.threat_model || {}).threats || []).length],
      ["Findings", s.findings != null ? s.findings : (b.findings || []).length],
    ];
    $("cards").innerHTML = cards.map(function (c) {
      return "<div class='card'><span class='n'>" + esc(c[1]) + "</span><span class='l'>" + esc(c[0]) + "</span></div>";
    }).join("");
  }

  function renderSurface(b) {
    var eps = (b.asm || {}).endpoints || [];
    if (!eps.length) { $("view-surface").innerHTML = "<p class='muted'>No endpoints.</p>"; return; }
    var rows = eps.map(function (e) {
      var params = (e.params || []).map(function (p) { return esc(p.name) + ":" + esc(p.location); }).join(", ");
      var src = (e.source || {});
      var loc = src.file ? (src.file + (src.line ? ":" + src.line : "")) : (e.framework || "");
      return "<tr><td><code>" + esc(e.method) + "</code></td><td><code>" + esc(e.path) +
        "</code></td><td>" + esc(e.handler || "") + "</td><td>" + esc(params) + "</td><td class='muted'>" + esc(loc) + "</td></tr>";
    }).join("");
    $("view-surface").innerHTML = "<table><thead><tr><th>Method</th><th>Path</th><th>Handler</th><th>Params</th><th>Source</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function renderPRG(b) {
    var prg = b.prg || {}, nodes = prg.nodes || [], edges = prg.edges || [];
    if (!nodes.length) { $("view-prg").innerHTML = "<p class='muted'>No parameter relation graph.</p>"; return; }
    var producers = nodes.filter(function (n) { return n.kind === "producer"; });
    var consumers = nodes.filter(function (n) { return n.kind === "consumer"; });
    var W = 1000, H = Math.max(360, Math.max(producers.length, consumers.length) * 26 + 40);
    var pos = {};
    var place = function (list, x) {
      list.forEach(function (n, i) { pos[n.id] = { x: x, y: 30 + i * ((H - 50) / Math.max(1, list.length - 1 || 1)) }; });
    };
    place(producers, 170); place(consumers, W - 170);
    var svg = ['<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="xMidYMid meet">'];
    edges.forEach(function (e) {
      var a = pos[e.from], c = pos[e.to];
      if (!a || !c) return;
      svg.push('<line class="edge" x1="' + a.x + '" y1="' + a.y + '" x2="' + c.x + '" y2="' + c.y +
        '"><title>' + esc(e.basis) + " (" + esc(e.confidence) + ")</title></line>");
    });
    var dot = function (n, cls, tx, anchor) {
      var p = pos[n.id];
      return '<circle r="4" cx="' + p.x + '" cy="' + p.y + '" class="' + cls + '"><title>' +
        esc(n.name) + "</title></circle>" +
        '<text x="' + tx + '" y="' + (p.y + 3) + '" text-anchor="' + anchor + '">' + esc(n.name) + "</text>";
    };
    producers.forEach(function (n) { svg.push(dot(n, "n-prod", pos[n.id].x - 8, "end")); });
    consumers.forEach(function (n) { svg.push(dot(n, "n-cons", pos[n.id].x + 8, "start")); });
    svg.push("</svg>");
    $("view-prg").innerHTML = "<p class='muted'>Producers (green, response fields) -> consumers (blue, request params). " +
      producers.length + " producers, " + consumers.length + " consumers, " + edges.length + " edges.</p>" + svg.join("");
  }

  function renderThreats(b) {
    var tm = b.threat_model || {}, threats = tm.threats || [];
    var html = "";
    if (tm.dfd_mermaid) {
      html += "<h3>Data-flow diagram</h3><pre>" + esc(tm.dfd_mermaid) + "</pre>";
    }
    if (threats.length) {
      var rows = threats.map(function (t) {
        return "<tr><td>" + esc(t.stride) + "</td><td>" + esc(t.title) + "</td><td>" + esc(t.owasp_api) +
          "</td><td>" + esc(t.cwe) + "</td><td><span class='pill sev-" + riskSev(t.risk) + "'>" + esc(t.risk) +
          "</span></td><td class='muted'>" + esc(t.mitigation) + "</td></tr>";
      }).join("");
      html += "<h3>Threats (" + threats.length + ")</h3><table><thead><tr><th>STRIDE</th><th>Title</th><th>OWASP API</th><th>CWE</th><th>Risk</th><th>Mitigation</th></tr></thead><tbody>" + rows + "</tbody></table>";
    }
    $("view-threats").innerHTML = html || "<p class='muted'>No threat model.</p>";
  }
  function riskSev(r) { return SEVS.indexOf(r) >= 0 ? r : "info"; }

  function renderFindings(b) {
    var all = b.findings || [];
    var wrap = $("view-findings");
    if (!all.length) { wrap.innerHTML = "<p class='muted'>No findings.</p>"; return; }
    var sevOpts = ["all"].concat(SEVS).map(function (s) { return "<option>" + s + "</option>"; }).join("");
    wrap.innerHTML = "<div class='filters'>Severity <select id='fsev'>" + sevOpts + "</select>" +
      "<input id='fq' placeholder='filter text' style='flex:1;min-width:160px;background:#20262f;color:inherit;border:1px solid var(--line);border-radius:8px;padding:6px 8px'></div><div id='ftab'></div>";
    var draw = function () {
      var sev = $("fsev").value, q = ($("fq").value || "").toLowerCase();
      var rows = all.filter(function (f) {
        if (sev !== "all" && f.severity !== sev) return false;
        if (q && JSON.stringify(f).toLowerCase().indexOf(q) < 0) return false;
        return true;
      }).map(function (f) {
        var t = f.triage || {}, th = f.threat || {};
        var loc = f.file ? (f.file + (f.line ? ":" + f.line : "")) : (f.endpoint || "");
        return "<tr><td><span class='pill sev-" + riskSev(f.severity) + "'>" + esc(f.severity) + "</span></td><td>" +
          esc(f.title) + "</td><td class='muted'>" + esc(loc) + "</td><td>" + esc(th.owasp_api) + "</td><td>" +
          esc(th.cwe) + "</td><td>" + esc(t.verdict || "") + "</td><td>" + esc(f.source_mode || "") + "</td></tr>";
      }).join("");
      $("ftab").innerHTML = "<table><thead><tr><th>Sev</th><th>Title</th><th>Location</th><th>OWASP API</th><th>CWE</th><th>Verdict</th><th>Source</th></tr></thead><tbody>" + rows + "</tbody></table>";
    };
    $("fsev").onchange = draw; $("fq").oninput = draw; draw();
  }

  // ---- import / export / tabs ----
  function loadText(text) {
    try { render(JSON.parse(text)); }
    catch (e) { alert("Not a valid Bundle JSON: " + e.message); }
  }
  $("file").addEventListener("change", function (e) {
    var f = e.target.files[0]; if (!f) return;
    var r = new FileReader(); r.onload = function () { loadText(r.result); }; r.readAsText(f);
  });
  var drop = $("drop");
  ["dragover", "dragenter"].forEach(function (ev) {
    document.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add("drag"); });
  });
  ["dragleave", "drop"].forEach(function (ev) {
    document.addEventListener(ev, function (e) { e.preventDefault(); if (ev === "dragleave") drop.classList.remove("drag"); });
  });
  document.addEventListener("drop", function (e) {
    e.preventDefault(); drop.classList.remove("drag");
    var f = e.dataTransfer.files[0]; if (!f) return;
    var r = new FileReader(); r.onload = function () { loadText(r.result); }; r.readAsText(f);
  });
  $("export").addEventListener("click", function () {
    if (!STATE.bundle) return;
    var blob = new Blob([JSON.stringify(STATE.bundle, null, 2)], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = (STATE.bundle.meta && STATE.bundle.meta.run_id || "bundle") + ".offat.json";
    a.click(); URL.revokeObjectURL(a.href);
  });
  $("tabs").addEventListener("click", function (e) {
    var b = e.target.closest("button[data-v]"); if (!b) return;
    [].forEach.call($("tabs").children, function (x) { x.classList.toggle("active", x === b); });
    ["surface", "prg", "threats", "findings"].forEach(function (v) {
      $("view-" + v).classList.toggle("active", v === b.getAttribute("data-v"));
    });
  });

  // Expose for programmatic use / tests.
  window.OFFAT = { render: render };

  // Allow ?url= to auto-load a bundle (same-origin).
  var u = new URLSearchParams(location.search).get("url");
  if (u) { fetch(u).then(function (r) { return r.text(); }).then(loadText).catch(function () {}); }
})();

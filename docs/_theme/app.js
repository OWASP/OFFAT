/* OWASP OFFAT docs: theme, navigation drawer, search, code blocks, TOC spy. */
(function () {
  "use strict";
  var root = document.documentElement;
  var body = document.body;

  /* ---------- theme ---------- */
  function effectiveTheme() {
    var t = root.getAttribute("data-theme");
    if (t) return t;
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.querySelectorAll("[data-toggle-theme]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var next = effectiveTheme() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      try { localStorage.setItem("offat-theme", next); } catch (e) { /* storage unavailable */ }
    });
  });

  /* ---------- navigation drawer (mobile) ---------- */
  var scrim = document.querySelector(".scrim");
  function setNav(open) {
    body.classList.toggle("nav-open", open);
    if (scrim) scrim.hidden = !open;
  }
  document.querySelectorAll("[data-open-nav]").forEach(function (el) {
    el.addEventListener("click", function () { setNav(true); });
  });
  document.querySelectorAll("[data-close-nav]").forEach(function (el) {
    el.addEventListener("click", function () { setNav(false); });
  });

  /* ---------- clipboard ---------- */
  function copyText(text, btn) {
    function done() {
      var old = btn.textContent;
      btn.textContent = "copied";
      setTimeout(function () { btn.textContent = old; }, 1400);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () {});
    } else {
      var ta = document.createElement("textarea");
      ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
      document.body.removeChild(ta);
    }
  }
  document.querySelectorAll(".cmd").forEach(function (box) {
    var btn = box.querySelector(".cmd-copy");
    if (btn) btn.addEventListener("click", function () { copyText(box.getAttribute("data-copy") || "", btn); });
  });

  /* ---------- code blocks: header with language + copy ---------- */
  document.querySelectorAll(".prose pre").forEach(function (pre) {
    var host = pre.parentElement && pre.parentElement.classList.contains("hl") ? pre.parentElement : pre;
    if (host.parentElement && host.parentElement.classList.contains("codeblock")) return;
    var code = pre.querySelector("code");
    var lang = host.getAttribute("data-lang") || "";
    if (!lang && code) {
      var m = (code.className || "").match(/language-([\w+-]+)/);
      if (m) lang = m[1];
    }
    var wrap = document.createElement("div");
    wrap.className = "codeblock";
    var head = document.createElement("div");
    head.className = "code-head";
    var label = document.createElement("span");
    var dots = document.createElement("span");
    dots.className = "dots";
    for (var d = 0; d < 3; d++) dots.appendChild(document.createElement("i"));
    label.appendChild(dots);
    label.appendChild(document.createTextNode(lang || "text"));
    head.appendChild(label);
    var btn = document.createElement("button");
    btn.type = "button"; btn.className = "code-copy"; btn.textContent = "copy";
    btn.addEventListener("click", function () { copyText((code || pre).innerText.replace(/\n$/, ""), btn); });
    head.appendChild(btn);
    host.parentNode.insertBefore(wrap, host);
    wrap.appendChild(head);
    wrap.appendChild(host);
  });

  /* ---------- table of contents scroll spy ---------- */
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a[href^='#']"));
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    tocLinks.forEach(function (a) { byId[decodeURIComponent(a.getAttribute("href").slice(1))] = a; });
    var visible = {};
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
      var heads = Object.keys(byId);
      var current = null;
      for (var i = 0; i < heads.length; i++) { if (visible[heads[i]]) { current = heads[i]; break; } }
      if (current) {
        tocLinks.forEach(function (a) { a.classList.remove("active"); });
        byId[current].classList.add("active");
      }
    }, { rootMargin: "-70px 0px -65% 0px" });
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) obs.observe(el);
    });
  }

  /* ---------- hero pulse: align with the pipeline rail ---------- */
  function placePulse() {
    var flow = document.querySelector(".flow");
    if (!flow) return;
    var steps = flow.querySelectorAll(".flow-steps li");
    var pulse = flow.querySelector(".flow-pulse");
    if (!steps.length || !pulse) return;
    var fr = flow.getBoundingClientRect();
    var first = steps[0].getBoundingClientRect();
    var last = steps[steps.length - 1].getBoundingClientRect();
    var top = first.top + first.height / 2 - fr.top - 3;
    var end = last.top + last.height / 2 - fr.top - 3;
    var rail = flow.querySelector(".flow-steps").getBoundingClientRect();
    pulse.style.top = top + "px";
    pulse.style.left = (rail.left - fr.left + 9) + "px";
    pulse.style.setProperty("--travel", (end - top) + "px");
  }
  placePulse();
  window.addEventListener("resize", placePulse);
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(placePulse);

  /* ---------- search ---------- */
  var modal = document.getElementById("search");
  var input = document.getElementById("search-input");
  var list = document.getElementById("search-results");
  var index = null;
  var sel = 0;

  function loadIndex() {
    if (index) return Promise.resolve(index);
    return fetch("search-index.json").then(function (r) { return r.json(); }).then(function (d) {
      index = d; return d;
    }).catch(function () { index = []; return index; });
  }
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
  function highlight(text, terms) {
    var out = esc(text);
    terms.forEach(function (t) {
      if (!t) return;
      var re = new RegExp("(" + t.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + ")", "ig");
      out = out.replace(re, "<mark>$1</mark>");
    });
    return out;
  }
  function snippet(text, term) {
    var i = text.toLowerCase().indexOf(term);
    if (i < 0) return text.slice(0, 140);
    var s = Math.max(0, i - 50);
    return (s > 0 ? "… " : "") + text.slice(s, s + 150) + "…";
  }
  function search(q) {
    var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    var results = [];
    index.forEach(function (p) {
      var title = p.t.toLowerCase(), text = (p.x || "").toLowerCase(), desc = (p.d || "").toLowerCase();
      var score = 0, all = true;
      terms.forEach(function (t) {
        var s = 0;
        if (title.indexOf(t) >= 0) s += 12;
        if (desc.indexOf(t) >= 0) s += 4;
        if (text.indexOf(t) >= 0) s += 1 + Math.min(4, text.split(t).length - 1) * 0.5;
        if (!s) all = false;
        score += s;
      });
      if (all && score) results.push({ url: p.u, title: p.t, meta: p.s, snip: snippet(p.x || p.d || "", terms[0]), score: score });
      (p.h || []).forEach(function (h) {
        var hn = h.n.toLowerCase();
        if (terms.every(function (t) { return hn.indexOf(t) >= 0; })) {
          results.push({ url: p.u + "#" + h.i, title: h.n, meta: p.t, snip: "", score: 10 + terms.length * 3 });
        }
      });
    });
    results.sort(function (a, b) { return b.score - a.score; });
    return results.slice(0, 12).map(function (r) { r.terms = terms; return r; });
  }
  function render(results, q) {
    sel = 0;
    if (!q) { list.innerHTML = '<li class="search-empty">Type to search every page and heading.</li>'; return; }
    if (!results.length) { list.innerHTML = '<li class="search-empty">No matches for “' + esc(q) + "”.</li>"; return; }
    list.innerHTML = results.map(function (r, i) {
      return '<li role="option"' + (i === 0 ? ' class="sel"' : "") + '><a href="' + esc(r.url) + '">' +
        '<span class="sr-title">' + highlight(r.title, r.terms) + '</span><span class="sr-meta">' + esc(r.meta) + "</span>" +
        (r.snip ? '<span class="sr-snip">' + highlight(r.snip, r.terms) + "</span>" : "") + "</a></li>";
    }).join("");
  }
  function moveSel(d) {
    var items = list.querySelectorAll("li[role='option']");
    if (!items.length) return;
    items[sel].classList.remove("sel");
    sel = (sel + d + items.length) % items.length;
    items[sel].classList.add("sel");
    items[sel].scrollIntoView({ block: "nearest" });
  }
  function openSearch() {
    if (!modal) return;
    setNav(false);
    modal.hidden = false;
    input.value = "";
    render([], "");
    loadIndex();
    setTimeout(function () { input.focus(); }, 10);
  }
  function closeSearch() { if (modal) modal.hidden = true; }

  document.querySelectorAll("[data-open-search]").forEach(function (b) { b.addEventListener("click", openSearch); });
  if (modal) {
    modal.addEventListener("click", function (e) { if (e.target === modal) closeSearch(); });
    input.addEventListener("input", function () {
      var q = input.value.trim();
      loadIndex().then(function () { render(search(q), q); });
    });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); moveSel(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); moveSel(-1); }
      else if (e.key === "Enter") {
        var a = list.querySelector("li.sel a");
        if (a) { window.location.href = a.getAttribute("href"); closeSearch(); }
      }
    });
    list.addEventListener("click", function (e) { if (e.target.closest("a")) closeSearch(); });
  }
  document.addEventListener("keydown", function (e) {
    var typing = /input|textarea|select/i.test((e.target && e.target.tagName) || "");
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); openSearch(); }
    else if (e.key === "/" && !typing && modal && modal.hidden) { e.preventDefault(); openSearch(); }
    else if (e.key === "Escape") { closeSearch(); setNav(false); }
  });
})();

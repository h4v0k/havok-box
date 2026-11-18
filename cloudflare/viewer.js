// Static viewer assets served by worker.js. Plain strings (no bundler plugin needed).
// Rule for the client code: every datum is untrusted; DOM is built with textContent only.

export const VIEWER_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>havok-box after-action snapshot</title>
<link rel="stylesheet" href="/app.css">
</head>
<body>
<header>
  <h1>havok-box</h1>
  <p class="ro">Read-only after-action snapshot</p>
</header>
<main id="app">
  <section id="auth" hidden>
    <label for="tok">View token</label>
    <input id="tok" type="password" autocomplete="off" autocapitalize="off" spellcheck="false">
    <button id="tok-go" type="button">Unlock</button>
  </section>
  <section id="picker" hidden>
    <label for="ver">Snapshot version</label>
    <select id="ver"></select>
    <button id="forget" type="button">Forget token</button>
  </section>
  <p id="msg" role="status"></p>
  <div id="out"></div>
</main>
<script src="/app.js"></script>
</body>
</html>
`;

export const VIEWER_CSS = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
html { font-size: 100%; }
body { margin: 0; background: #0d1117; color: #e6edf3; font: 1rem/1.5 system-ui, sans-serif; overflow-wrap: anywhere; }
header, main { max-width: 60rem; margin: 0 auto; padding: 0.75rem 1rem; }
h1 { font-size: 1.5rem; margin: 0; }
h2 { font-size: 1.25rem; margin: 1.5rem 0 0.5rem; border-bottom: 1px solid #30363d; padding-bottom: 0.25rem; }
h3 { font-size: 1.05rem; margin: 0.75rem 0 0.25rem; }
.ro { margin: 0; color: #8b949e; font-size: 0.9rem; }
label { display: block; margin: 0.5rem 0 0.25rem; }
input, select, button, summary { min-height: 3rem; font: inherit; color: inherit; }
input, select { width: 100%; background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; padding: 0.5rem 0.75rem; }
button { background: #21262d; border: 1px solid #30363d; border-radius: 0.5rem; padding: 0.5rem 1rem; margin-top: 0.5rem; }
details { background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; margin: 0.5rem 0; padding: 0 0.75rem; }
summary { display: flex; align-items: center; cursor: pointer; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 0.5rem; margin: 0.5rem 0; padding: 0.5rem 0.75rem; }
.step { margin: 0.5rem 0 0.5rem 0.75rem; padding-left: 0.75rem; border-left: 0.2rem solid #30363d; }
.step.executed { border-left-color: #3fb950; }
.step.pending { border-left-color: #d29922; }
.active { color: #ff7b72; font-weight: 700; }
.muted { color: #8b949e; font-size: 0.9rem; }
dl { margin: 0.25rem 0; } dt { color: #8b949e; font-size: 0.9rem; } dd { margin: 0 0 0.5rem 0.75rem; }
ul { margin: 0.25rem 0; padding-left: 1.25rem; }
#msg { color: #ff7b72; }
`;

export const VIEWER_JS = `
(function () {
  "use strict";
  var KEY = "havokbox_view_token";
  var ACTIVE = ["recon.active", "auth.attempt", "exploit.tool", "wifi.deauth", "wifi.inject", "rf.replay", "rf.transmit"];
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, text, cls) {
    var e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  }
  function add(parent) {
    for (var i = 1; i < arguments.length; i++) parent.appendChild(arguments[i]);
    return parent;
  }
  function fmtTime(t) {
    if (typeof t !== "number" || !isFinite(t)) return String(t);
    var d = new Date(t * 1000);
    return isNaN(d.getTime()) ? String(t) : d.toISOString().replace("T", " ").replace(".000Z", "Z");
  }
  function msg(t) { $("msg").textContent = t || ""; }

  function api(path) {
    var tok = localStorage.getItem(KEY);
    return fetch(path, { headers: { Authorization: "Bearer " + tok }, cache: "no-store", referrerPolicy: "no-referrer" })
      .then(function (r) {
        if (r.status === 401) {
          localStorage.removeItem(KEY);
          showAuth();
          throw new Error("Token rejected");
        }
        if (!r.ok) throw new Error("Request failed (" + r.status + ")");
        return r.json();
      });
  }

  // Generic renderer for arbitrary untrusted data.
  function renderValue(parent, v, depth) {
    if (depth > 6) { parent.appendChild(el("span", "...")); return; }
    if (Array.isArray(v)) {
      var ul = el("ul");
      v.forEach(function (x) { var li = el("li"); renderValue(li, x, depth + 1); ul.appendChild(li); });
      parent.appendChild(ul);
    } else if (v && typeof v === "object") {
      var dl = el("dl");
      Object.keys(v).forEach(function (k) {
        var dd = el("dd");
        renderValue(dd, v[k], depth + 1);
        add(dl, el("dt", k), dd);
      });
      parent.appendChild(dl);
    } else {
      parent.appendChild(el("span", v === null ? "null" : v));
    }
  }

  function modeMix(findings) {
    var m = {};
    findings.forEach(function (f) { var k = String(f.mode); m[k] = (m[k] || 0) + 1; });
    return Object.keys(m).sort().map(function (k) { return k + " " + m[k]; }).join(", ") || "none";
  }

  function section(title) { return el("h2", title); }

  function summary(out, s) {
    add(out, section("Summary"));
    var dl = el("dl");
    [["Box", s.box], ["Scope", s.scope_name], ["Version", s.version], ["Generated", s.generated],
     ["Mode mix", modeMix(s.findings || [])]].forEach(function (p) {
      add(dl, el("dt", p[0]), add(el("dd"), el("span", p[1])));
    });
    out.appendChild(dl);
  }

  function stepNode(st) {
    var d = el("div", null, "step " + (st.status === "executed" ? "executed" : "pending"));
    var head = el("div");
    add(head, el("strong", st.status === "executed" ? "Executed" : "Pending"), el("span", " " + st.tool + " "));
    var isActive = ACTIVE.indexOf(st.category) >= 0;
    add(head, el("span", st.category, isActive ? "active" : "muted"));
    if (isActive) add(head, el("span", " [ACTIVE]", "active"));
    d.appendChild(head);
    if (st.label) d.appendChild(el("div", st.label));
    d.appendChild(el("div", "mode: " + st.mode + " | " + fmtTime(st.created), "muted"));
    if (st.target && typeof st.target === "object" && Object.keys(st.target).length) {
      var t = el("div"); renderValue(t, st.target, 0); d.appendChild(t);
    }
    return d;
  }

  function attackPath(out, s) {
    add(out, section("Attack path"));
    var findings = (s.findings || []).slice().sort(function (a, b) { return a.created - b.created; });
    var steps = s.attack_path || [];
    if (!findings.length) out.appendChild(el("p", "No findings.", "muted"));
    var seen = {};
    findings.forEach(function (f) {
      seen[f.result_id] = true;
      var c = el("div", null, "card");
      add(c, el("strong", f.summary), el("div", f.space + " / " + f.kind + " | mode: " + f.mode + " | " + fmtTime(f.created), "muted"));
      steps.filter(function (st) { return st.result_id === f.result_id; })
        .sort(function (a, b) { return a.created - b.created; })
        .forEach(function (st) { c.appendChild(stepNode(st)); });
      out.appendChild(c);
    });
    var orphans = steps.filter(function (st) { return !seen[st.result_id]; });
    if (orphans.length) {
      var c2 = el("div", null, "card");
      c2.appendChild(el("strong", "Steps without a listed finding"));
      orphans.forEach(function (st) { c2.appendChild(stepNode(st)); });
      out.appendChild(c2);
    }
  }

  function findingsBySpace(out, s) {
    add(out, section("Findings by signal space"));
    var groups = {};
    (s.findings || []).forEach(function (f) { (groups[f.space] = groups[f.space] || []).push(f); });
    var spaces = Object.keys(groups).sort();
    if (!spaces.length) out.appendChild(el("p", "No findings.", "muted"));
    spaces.forEach(function (sp) {
      out.appendChild(el("h3", sp));
      groups[sp].forEach(function (f) {
        var d = el("details");
        d.appendChild(el("summary", f.kind + ": " + f.summary));
        d.appendChild(el("div", "mode: " + f.mode + " | " + fmtTime(f.created) + " | " + f.result_id, "muted"));
        var body = el("div"); renderValue(body, f.data === undefined ? {} : f.data, 0);
        d.appendChild(body);
        out.appendChild(d);
      });
    });
  }

  function evidence(out, s) {
    add(out, section("Evidence log"));
    var ev = (s.evidence || []).slice().sort(function (a, b) { return b.ts - a.ts; });
    if (!ev.length) out.appendChild(el("p", "No evidence entries.", "muted"));
    ev.forEach(function (e) {
      var c = el("div", null, "card");
      add(c, el("div", fmtTime(e.ts) + " | " + e.kind, "muted"), el("div", e.detail));
      out.appendChild(c);
    });
  }

  function render(s) {
    var out = $("out");
    out.textContent = "";
    summary(out, s); attackPath(out, s); findingsBySpace(out, s); evidence(out, s);
  }

  function load(v) {
    msg("Loading...");
    return api("/api/snapshot" + (v ? "?v=" + encodeURIComponent(v) : "")).then(function (s) { msg(""); render(s); })
      .catch(function (e) { msg(e.message); });
  }

  function showAuth() {
    $("auth").hidden = false; $("picker").hidden = true; $("out").textContent = "";
  }

  function start() {
    $("auth").hidden = true;
    api("/api/versions").then(function (list) {
      var sel = $("ver");
      sel.textContent = "";
      list.forEach(function (v) {
        var o = el("option", "v" + v.version + " | " + v.generated + " | " + String(v.sha256).slice(0, 8));
        o.value = String(v.version);
        sel.appendChild(o);
      });
      $("picker").hidden = false;
      if (list.length) load(list[0].version); else msg("No snapshots yet.");
    }).catch(function (e) { msg(e.message); });
  }

  $("tok-go").addEventListener("click", function () {
    var t = $("tok").value.trim();
    if (!t) return;
    localStorage.setItem(KEY, t);
    $("tok").value = "";
    msg("");
    start();
  });
  $("ver").addEventListener("change", function () { load($("ver").value); });
  $("forget").addEventListener("click", function () { localStorage.removeItem(KEY); showAuth(); });

  if (localStorage.getItem(KEY)) start(); else showAuth();
})();
`;

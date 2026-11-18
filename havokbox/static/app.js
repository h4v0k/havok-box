// havok-box dashboard. Everything from the box (SSIDs, hostnames, tool summaries) is attacker-
// influenceable radio/network data, so it is ONLY ever inserted with textContent — never innerHTML.
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const PHASES = ["recon", "enumerate", "test", "report"];
const POLL_MS = 3000;

let token = localStorage.getItem("hb_token") || "";
let state = null;
let lastJson = "";
let pending = null;          // proposal shown in the confirm sheet
const openDetails = new Set();

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) if (c !== null && c !== undefined) n.append(c instanceof Node ? c : String(c));
  return n;
}

async function call(method, path, body) {
  const r = await fetch(path, {
    method,
    headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) { lock("Token rejected."); throw new Error("unauthorized"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok && r.status !== 202) throw new Error(data.reason || data.status || ("HTTP " + r.status));
  return data;
}

// ---- auth -----------------------------------------------------------------
function lock(msg) {
  token = ""; localStorage.removeItem("hb_token");
  $("#app").hidden = true; $("#login").hidden = false;
  $("#login-err").textContent = msg || "";
  $("#token").focus();
}
$("#login-form").addEventListener("submit", (e) => {
  e.preventDefault();
  token = $("#token").value.trim();
  localStorage.setItem("hb_token", token);
  $("#token").value = "";
  start();
});

// ---- rendering ------------------------------------------------------------
function fmtTime(ts) { return new Date(ts * 1000).toLocaleString(); }
function fmtTarget(t) {
  const e = Object.entries(t || {});
  return e.length ? e.map(([k, v]) => `${k}: ${v}`).join(" · ") : "(listen only)";
}

function renderMode() {
  for (const b of $$(".mode button")) b.setAttribute("aria-checked", String(b.dataset.mode === state.mode));
}

// Recon cards come from the box: only signal spaces with a registered tool get a button.
function renderCards() {
  const busy = new Set(state.running.map((j) => j.lane));
  if (state.wardrive_running) for (const ln of ["wifi", "ble", "esp", "sdr", "subghz"]) busy.add(ln);
  $("#cards").replaceChildren(...state.cards.map((c) => el("article", { class: "card" },
    el("h3", { text: c.title }),
    el("p", { class: "sub", text: c.sub }),
    c.actions.map((a) => [
      el("button", { type: "button", class: "btn primary big scan", disabled: busy.has(c.space),
        onclick: (e) => startScan(e.currentTarget, c.space, a.action) }, a.label),
      el("p", { class: "hint", text: busy.has(c.space) ? (state.wardrive_running && c.space !== "wired" ? "In use by the drive." : "Running…") : a.hint }),
    ]))));
}

function renderPhase() {
  // Highlight where the attack path is; the tabs themselves are for navigation. No counts.
  const cur = PHASES.indexOf(state.phase);
  for (const b of $$(".phases button")) {
    const i = PHASES.indexOf(b.dataset.tab);
    b.classList.toggle("current", i === cur);
    b.classList.toggle("done", i >= 0 && i < cur);
    if (i === cur) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
  }
}

function renderStatus() {
  const s = $("#status");
  s.replaceChildren();
  if (state.running.length) s.append(el("span", { class: "run", text: "Running: " + state.running.map((j) => j.label).join(" · ") }));
  else {
    const last = (state.jobs || [])[0];
    if (last && last.finished) s.append(`Last: ${last.label} — ${last.status}${last.detail ? " · " + last.detail : ""}`);
  }
  if (state.commander_pending) s.append(el("div", { text: "Commander suggestions are queued and will fill in when the box is online." }));
}

function findingDetails(f) {
  const d = f.data || {};
  const items = [];
  if (f.kind === "hosts") for (const h of d.hosts || []) items.push(el("li", { text: h.ip + (h.mac ? `  (${h.mac})` : "") }));
  if (f.kind === "services") for (const s of d.services || [])
    items.push(el("li", { text: `${s.port}/${s.proto} ${s.service || "?"}${s.version ? " " + s.version : ""}` }));
  if (f.kind === "wifi_survey") {
    const twins = new Set((d.evil_twins || []).map((t) => t.bssid));
    for (const ap of d.aps || []) items.push(el("li", {
      class: twins.has(ap.bssid) ? "alert" : null,
      text: `${ap.ssid || "(hidden)"} — ${ap.bssid} ch ${ap.channel ?? "?"}${twins.has(ap.bssid) ? "  EVIL TWIN" : ""}`,
    }));
  }
  if (!items.length) items.push(...genericItems(d));
  if (!items.length) return null;
  const det = el("details", { open: openDetails.has(f.result_id) },
    el("summary", { text: "Details" }), el("ul", {}, items));
  det.addEventListener("toggle", () => det.open ? openDetails.add(f.result_id) : openDetails.delete(f.result_id));
  return det;
}

// Any tool's data: arrays become lists, anomalies first and flagged. Values shown as text only.
const ALERT_KEYS = new Set(["anomalies", "evil_twins", "findings"]);
function fmtItem(v) {
  if (v === null || typeof v !== "object") return String(v);
  return Object.entries(v).filter(([, x]) => x !== null && x !== "" && typeof x !== "object")
    .map(([k, x]) => `${k}: ${x}`).join(" · ").slice(0, 300);
}
function genericItems(d) {
  const out = [];
  const keys = Object.keys(d).sort((a, b) => ALERT_KEYS.has(b) - ALERT_KEYS.has(a));
  for (const k of keys) {
    const v = d[k];
    if (Array.isArray(v)) {
      for (const x of v.slice(0, 64)) out.push(el("li", { class: ALERT_KEYS.has(k) ? "alert" : null, text: `${k}: ${fmtItem(x)}` }));
    } else if (v !== null && typeof v !== "object" && v !== "") {
      out.push(el("li", { text: `${k}: ${v}` }));
    }
  }
  return out;
}

function stepButton(p) {
  return el("button", {
    type: "button", class: "btn step" + (p.suggested ? " suggested" : ""),
    onclick: () => (p.needs_approval ? openSheet(p) : runPassive(p)),
  }, p.label || p.tool,
     el("small", { text: p.approved ? `Approved · tap to run · ${p.category}` : !p.in_scope ? `Out of scope · ${p.category}`
       : !p.runnable ? `Tool not installed yet · ${p.category}`
       : `${p.needs_approval ? "Needs approval" : "Passive"} · ${p.category}${p.source === "commander" ? " · AI" : ""}` }));
}

function renderFindings() {
  const box = $("#findings");
  const fs = state.findings.slice().reverse();
  const known = new Set(state.findings.map((f) => f.result_id));
  const waiting = state.proposals.filter((p) => !known.has(p.result_id));
  const waitBox = waiting.length ? el("article", { class: "finding" },
    el("header", {}, el("span", { class: "sum", text: "Waiting for your approval" })),
    el("div", { class: "steps" }, waiting.map(stepButton))) : null;
  if (!fs.length && waitBox) { box.replaceChildren(waitBox); return; }
  if (!fs.length) { box.replaceChildren(el("p", { class: "empty", text: "No findings yet. Start with a recon card above." })); return; }
  const byResult = {};
  for (const p of state.proposals) (byResult[p.result_id] ||= []).push(p);
  box.replaceChildren(...(waitBox ? [waitBox] : []), ...fs.map((f) => {
    const twins = (f.data && f.data.evil_twins || []).length;
    const anomalies = (f.data && (f.data.anomalies || []).length) || 0;
    const vulns = f.kind === "vulns" && (f.data.findings || []).length;
    const steps = (byResult[f.result_id] || []).sort((a, b) => b.suggested - a.suggested);
    return el("article", { class: "finding" },
      el("header", {},
        el("span", { class: "sum", text: f.summary }),
        twins ? el("span", { class: "tag alert", text: "Evil twin" }) : null,
        anomalies ? el("span", { class: "tag alert", text: "Anomaly" }) : null,
        vulns ? el("span", { class: "tag alert", text: "Vulnerable" }) : null,
        f.kind === "capture" && f.data.handshake ? el("span", { class: "tag", text: "Handshake captured" }) : null,
        el("span", { class: "tag", text: f.space }),
        el("span", { class: "tag", text: f.mode })),
      el("time", { class: "hint", text: fmtTime(f.created) }),
      findingDetails(f),
      steps.length ? el("div", { class: "steps" }, steps.map(stepButton)) : null);
  }));
}

const ACTIVE = new Set(["wifi.deauth", "wifi.inject", "rf.replay", "rf.transmit", "auth.attempt", "exploit.tool"]);

function renderLists() {
  const steps = state.proposals.slice().sort((a, b) => b.suggested - a.suggested);
  const enumr = steps.filter((p) => p.category.startsWith("recon."));
  const test = steps.filter((p) => ACTIVE.has(p.category));
  $("#enumerate-list").replaceChildren(...(enumr.length ? enumr.map(stepButton)
    : [el("p", { class: "empty", text: "Nothing to enumerate yet. Run a recon scan first." })]));
  $("#test-list").replaceChildren(...(test.length ? test.map(stepButton)
    : [el("p", { class: "empty", text: state.wardrive_running ? "Test actions are off while a drive is running." : "No test actions proposed yet." })]));
}

function renderEvidence() {
  $("#timeline").replaceChildren(...state.findings.slice().reverse().map((f) =>
    el("li", {}, el("span", { class: "k", text: f.space }), f.summary, el("time", { text: `${fmtTime(f.created)} · ${f.mode}` }))));
  $("#evidence").replaceChildren(...state.evidence.map((e) =>
    el("li", {}, el("span", { class: "k " + e.kind, text: e.kind }), e.detail, el("time", { text: fmtTime(e.ts) }))));
}

function renderPublish() {
  const p = state.publish || { enabled: false };
  const btn = $("#publish-btn"), st = $("#publish-status"), link = $("#publish-link");
  btn.hidden = !p.enabled;
  link.hidden = !p.enabled;
  if (!p.enabled) {
    st.textContent = "Publishing is off. Set publish_url in config/box.json and HAVOKBOX_PUBLISH_TOKEN to enable it.";
    return;
  }
  link.href = p.viewer_url;
  const running = state.running.some((j) => j.lane === "publish");
  btn.disabled = running;
  const last = p.last_version ? `Last published v${p.last_version} · ${fmtTime(p.last_at)} · sha256 ${p.last_sha256}…` : "Not published yet.";
  st.textContent = running ? "Publishing…" : p.pending ? `${last} A publish is waiting and will go out when the box is online.` : last;
}

function renderDrift() {
  const d = state.drift || { learned: false, items: [] };
  const box = $("#drift");
  const learn = el("button", { type: "button", class: "btn" + (d.learned ? "" : " primary"), onclick: async () => {
    if (d.learned && !confirm("Replace the baseline with what the box sees now?")) return;
    await call("POST", "/api/baseline/learn"); refresh(); } }, d.learned ? "Re-learn baseline" : "Learn baseline from current findings");
  if (!d.learned) { box.replaceChildren(el("p", { class: "hint", text: "Scan the lab, then learn a baseline. New hosts, APs and devices will show up here." }), learn); return; }
  const sevRank = { high: 0, medium: 1, low: 2, info: 3 };
  const items = (d.items || []).slice().sort((a, b) => (sevRank[a.severity] ?? 4) - (sevRank[b.severity] ?? 4));
  box.replaceChildren(
    ...(items.length ? items.slice(0, 40).map((it) => el("div", { class: "finding" },
      el("header", {}, el("span", { class: "sum", text: it.label || it.key }),
        el("span", { class: "tag" + (it.severity === "high" ? " alert" : ""), text: it.kind.replace(/_/g, " ") })),
      it.detail ? el("p", { class: "hint", text: it.detail }) : null,
      it.kind.startsWith("new_") ? el("button", { type: "button", class: "btn", onclick: async () => { await call("POST", "/api/baseline/accept", { space: it.space, key: it.key }); refresh(); } }, "Accept as normal") : null))
      : [el("p", { class: "empty", text: "No changes since the baseline." })]),
    learn);
}

function render() {
  renderMode(); renderPhase(); renderStatus(); renderCards(); renderFindings(); renderLists(); renderEvidence(); renderPublish(); renderDrift();
  $("[data-tab=console]").hidden = !state.console_enabled;
}

async function refresh() {
  try {
    const s = await call("GET", "/api/state");
    const j = JSON.stringify(s);
    if (j !== lastJson) { lastJson = j; state = s; render(); }
  } catch (e) { if (e.message !== "unauthorized") $("#status").textContent = "Box unreachable: " + e.message; }
}

// ---- actions --------------------------------------------------------------
for (const b of $$(".mode button")) b.addEventListener("click", async () => {
  await call("POST", "/api/mode", { mode: b.dataset.mode }); refresh();
});
async function startScan(b, space, action) {
  b.disabled = true;
  try {
    const r = await call("POST", "/api/scan", { space, action, mode: state.mode });
    if (r.status === "needs_approval") {
      await refresh();
      const p = state.proposals.find((x) => x.task_id === r.task_id);
      if (p) openSheet(p);
      return;
    }
  } catch (e) { $("#status").textContent = "Scan failed: " + e.message; }
  refresh();
}

async function runPassive(p) {
  try { await call("POST", "/api/run", { task_id: p.task_id }); } catch (e) { $("#status").textContent = e.message; }
  refresh();
}

function openSheet(p) {
  pending = p;
  $("#sheet-title").textContent = p.label || p.tool;
  $("#sheet-target").textContent = fmtTarget(p.target);
  $("#sheet-cat").textContent = p.category;
  $("#sheet-mode").textContent = p.mode;
  $("#sheet-cmd").textContent = p.command || "Not available — this tool isn't installed on the box yet.";
  $("#sheet-note").textContent = p.in_scope ? "" : "Out of scope — the gate will refuse this: " + p.gate_reason;
  $("#sheet-run").disabled = !p.runnable;
  $("#sheet").hidden = false;
  $("#sheet-cancel").focus();
}
function closeSheet() { $("#sheet").hidden = true; pending = null; }
$("#sheet-cancel").addEventListener("click", closeSheet);
$("#sheet").addEventListener("click", (e) => { if (e.target.id === "sheet") closeSheet(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("#sheet").hidden) closeSheet(); });
$("#sheet-run").addEventListener("click", async () => {
  const p = pending; if (!p) return;
  $("#sheet-run").disabled = true;
  try {
    // Send the digest of the exact command this sheet displayed; the box refuses if it changed.
    if (!p.approved) await call("POST", "/api/approve", { task_id: p.task_id, digest: p.digest });
    await call("POST", "/api/run", { task_id: p.task_id });
    closeSheet();
  } catch (e) { $("#sheet-note").textContent = "Failed: " + e.message + ". Close and reopen to see the current command."; $("#sheet-run").disabled = false; }
  refresh();
});

$("#publish-btn").addEventListener("click", async () => {
  $("#publish-btn").disabled = true;
  try { await call("POST", "/api/publish"); } catch (e) { $("#publish-status").textContent = "Publish failed: " + e.message; }
  refresh();
});

// ---- tabs + console -------------------------------------------------------
for (const t of $$(".phases button")) t.addEventListener("click", () => {
  for (const o of $$(".phases button")) {
    o.setAttribute("aria-selected", String(o === t));
    $("#tab-" + o.dataset.tab).hidden = o !== t;
  }
});
$("#open-console").addEventListener("click", async () => {
  try { const r = await call("GET", "/api/console"); window.open(r.url, "_blank", "noopener"); $("#console-msg").textContent = ""; }
  catch (e) { $("#console-msg").textContent = "Console unavailable: " + e.message; }
});

// ---- boot -----------------------------------------------------------------
let timer = null;
function start() {
  $("#login").hidden = true; $("#app").hidden = false;
  refresh();
  clearInterval(timer); timer = setInterval(() => { if (token) refresh(); }, POLL_MS);
}
if (token) start(); else lock();

// ---- wardrive (Drive tab) --------------------------------------------------
let wd = null;
const SVGNS = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  return n;
}

function fixText(f) {
  if (!f || !f.mode || f.mode < 2 || f.lat == null) return "No GPS fix";
  return `${f.mode === 3 ? "3D" : "2D"} fix${f.used != null ? ` · ${f.used} sats` : ""}${f.degraded ? " · GNSS degraded" : ""}`;
}

function renderMap(d) {
  const box = $("#wd-map");
  const pts = (d.track || []).filter((p) => p.lat != null);
  const devs = (d.devices || []).filter((x) => x.lat != null);
  const alerts = (d.alerts || []).filter((a) => a.lat != null);
  const all = [...pts, ...devs, ...alerts];
  if (!all.length) { box.replaceChildren(el("p", { class: "hint", text: "No positions yet." })); return; }
  let [minLat, maxLat, minLon, maxLon] = [Infinity, -Infinity, Infinity, -Infinity];
  for (const p of all) { minLat = Math.min(minLat, p.lat); maxLat = Math.max(maxLat, p.lat); minLon = Math.min(minLon, p.lon); maxLon = Math.max(maxLon, p.lon); }
  const k = Math.cos(((minLat + maxLat) / 2) * Math.PI / 180);
  const W = 600, H = 420, pad = 20;
  const spanX = Math.max((maxLon - minLon) * k, 1e-4), spanY = Math.max(maxLat - minLat, 1e-4);
  const s = Math.min((W - 2 * pad) / spanX, (H - 2 * pad) / spanY);
  const X = (lon) => pad + (lon - minLon) * k * s, Y = (lat) => H - pad - (lat - minLat) * s;
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}` });
  for (const x of devs) {
    const tracker = x.kind && x.kind !== "ap" && x.kind !== "client";
    root.append(svg("circle", { cx: X(x.lon), cy: Y(x.lat), r: tracker ? 6 : 2.5, fill: tracker ? "#ff5c5c" : "#56636f" }));
  }
  if (pts.length > 1) root.append(svg("polyline", { points: pts.map((p) => `${X(p.lon)},${Y(p.lat)}`).join(" "), fill: "none", stroke: "#3fb6ff", "stroke-width": 3 }));
  for (const a of alerts) root.append(svg("rect", { x: X(a.lon) - 6, y: Y(a.lat) - 6, width: 12, height: 12, fill: "none", stroke: "#ff5c5c", "stroke-width": 3 }));
  if (pts.length) { const last = pts[pts.length - 1]; root.append(svg("circle", { cx: X(last.lon), cy: Y(last.lat), r: 7, fill: "#ffcf3f" })); }
  box.replaceChildren(root);
}

async function download(session, fmt) {
  const r = await fetch(`/api/wardrive/export?session=${encodeURIComponent(session)}&fmt=${fmt}`, { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) { const j = await r.json().catch(() => ({})); $("#wd-status").textContent = "Export failed: " + (j.reason || r.status); return; }
  const blob = await r.blob();
  const name = (r.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
  const a = el("a", { href: URL.createObjectURL(blob), download: name ? name[1] : `drive.${fmt}` });
  document.body.append(a); a.click(); a.remove();
}

function renderDrive(d) {
  wd = d;
  const btn = $("#wd-toggle");
  if (!d.enabled) { btn.disabled = true; $("#wd-status").textContent = "Wardrive isn't available on this box."; return; }
  btn.disabled = false;
  btn.textContent = d.running ? "Stop drive" : "Start drive";
  btn.className = "btn big " + (d.running ? "danger" : "primary");
  const radios = (d.summary || []).map((x) => `${x.radio === "wifi" ? "Wi-Fi" : "BLE"} ${x.devices} devices`).join(" · ");
  const cur = (d.sessions || []).find((x) => x.id === d.session);
  const km = cur ? ((d.running ? d.live_distance_m : cur.distance_m) / 1000).toFixed(1) + " km" : "";
  $("#wd-status").textContent = d.running ? [fixText(d.fix), km, radios].filter(Boolean).join(" · ")
    : cur ? `Last drive: ${cur.status} · ${km}${radios ? " · " + radios : ""}` : "No drives yet.";
  $("#wd-alerts").replaceChildren(...((d.alerts || []).length ? d.alerts.map((a) => el("li", { class: a.acked ? "acked" : null },
    el("span", { class: "k sev-" + a.severity, text: a.kind === "follow" ? "Following you" : a.kind }),
    a.detail, a.dev_plain ? el("div", { class: "hint", text: a.dev_plain }) : null,
    el("time", { text: fmtTime(a.ts) }),
    a.acked ? null : el("div", { class: "row" }, el("button", { type: "button", class: "btn", onclick: async () => { await call("POST", "/api/wardrive/ack", { alert_id: a.id }); refreshDrive(); } }, "Acknowledge"))))
    : [el("p", { class: "empty", text: "No alerts." })]));
  renderMap(d);
  const ray = d.rayhunter;
  $("#wd-ray").textContent = ray ? "Cell towers: " + ray.text : "";
  const ex = d.exposure;
  $("#wd-expo").replaceChildren(...(ex && ex.items && ex.items.length ? [
    ...ex.items.map((it) => el("article", { class: "finding" },
      el("header", {}, el("span", { class: "sum", text: it.name || it.id || it.class }),
        el("span", { class: "tag" + (it.identifier === "static" ? " alert" : ""), text: it.identifier === "static" ? "Fixed ID" : "Rotating" }),
        el("span", { class: "tag", text: it.radio.toUpperCase() })),
      el("p", { text: it.advice }),
      it.note ? el("p", { class: "hint", text: it.note }) : null)),
    ex.rotating_ble ? el("p", { class: "hint", text: `Plus ${ex.rotating_ble} Bluetooth device(s) using rotating addresses (harder to track).` }) : null]
    : [el("p", { class: "empty", text: "Shows after a drive of 5 km or more: what the car broadcasts that someone could use to follow it." })]));
  $("#wd-drones").replaceChildren(...((d.drones || []).length ? d.drones.map((dr) => el("li", {},
    el("span", { class: "k", text: "Drone" }), dr.ua_id || "unknown ID",
    el("div", { class: "hint", text: [dr.alt != null ? `${Math.round(dr.alt)} m up` : null, dr.speed != null ? `${Math.round(dr.speed)} m/s` : null, dr.operator_known ? "operator position broadcast" : null].filter(Boolean).join(" · ") })))
    : [el("p", { class: "empty", text: "No Remote ID broadcasts heard (BLE add-on modules only; most DJI drones use Wi-Fi)." })]));
  $("#wd-sessions").replaceChildren(...(d.sessions || []).filter((x) => x.status !== "running").map((x) => el("article", { class: "finding" },
    el("header", {}, el("span", { class: "sum", text: `${fmtTime(x.started)}${x.note ? " · " + x.note : ""}` }), el("span", { class: "tag", text: x.status })),
    el("p", { class: "hint", text: `${(x.distance_m / 1000).toFixed(1)} km` }),
    el("div", { class: "row" },
      el("button", { type: "button", class: "btn", onclick: () => download(x.id, "wigle") }, "WiGLE CSV"),
      el("button", { type: "button", class: "btn", onclick: () => download(x.id, "kml") }, "KML"),
      el("button", { type: "button", class: "btn", onclick: () => download(x.id, "ble") }, "BLE CSV"),
      el("button", { type: "button", class: "btn danger", onclick: async () => { await call("POST", "/api/wardrive/delete", { session: x.id }); refreshDrive(); } }, "Delete")))));
}

async function refreshDrive() {
  try { renderDrive(await call("GET", "/api/wardrive/state")); } catch (e) { /* box unreachable: main poll reports it */ }
}

$("#wd-toggle").addEventListener("click", async () => {
  $("#wd-toggle").disabled = true;
  try {
    if (wd && wd.running) await call("POST", "/api/wardrive/stop");
    else await call("POST", "/api/wardrive/start", { note: $("#wd-note").value.trim() });
  } catch (e) { $("#wd-status").textContent = e.message; }
  setTimeout(refreshDrive, 800);
});

setInterval(() => {
  if (token && (!$("#tab-drive").hidden || (state && state.wardrive_running))) refreshDrive();
}, POLL_MS);
for (const t of $$(".phases button")) t.addEventListener("click", () => { if (t.dataset.tab === "drive") refreshDrive(); });

// ---- Wi-Fi site survey (indoor grid-tap) ------------------------------------
let sv = null, svBssid = null, svBusy = false;
function rssiColor(v) {   // -40 strong (green) .. -85 weak (red); null = unmeasured
  if (v == null) return "";
  const t = Math.max(0, Math.min(1, (v + 85) / 45));
  return `hsl(${Math.round(t * 120)} 70% 38%)`;
}
function renderSurvey(d) {
  sv = d;
  const setup = $("#sv-setup"), grid = $("#sv-grid"), act = $("#sv-actions");
  if (!d.enabled) { $("#sv-card").hidden = true; return; }
  const running = (d.surveys || []).find((x) => x.status === "running");
  const heat = d.heatmap;
  act.replaceChildren();
  if (!running && !(d.view && heat)) {
    grid.hidden = true;
    setup.replaceChildren(
      ...(d.bssids.length ? d.bssids.map((b) => el("label", { class: "check" },
        el("input", { type: "checkbox", value: b, class: "sv-b" }), b))
        : [el("p", { class: "empty", text: "Add your AP BSSIDs to wifi.bssids in the scope file first." })]),
      el("label", { class: "sub", for: "sv-name", text: "Name" }),
      el("input", { id: "sv-name", class: "text", value: "Upstairs", maxlength: "60" }));
    act.append(el("button", { type: "button", class: "btn primary big", disabled: !d.bssids.length, onclick: async () => {
      const bssids = $$(".sv-b").filter((i) => i.checked).map((i) => i.value);
      try { await call("POST", "/api/survey/start", { name: $("#sv-name").value || "survey", bssids }); }
      catch (e) { $("#sv-msg").textContent = e.message; }
      refreshSurvey();
    } }, "Start survey"));
  } else {
    setup.replaceChildren();
    const bss = heat ? heat.bssids : JSON.parse((running && running.bssids) || "[]");
    if (!svBssid || !bss.includes(svBssid)) svBssid = bss[0];
    if (bss.length > 1) setup.append(el("div", { class: "row" }, bss.map((b) =>
      el("button", { type: "button", class: "btn" + (b === svBssid ? " primary" : ""), onclick: () => { svBssid = b; renderSurvey(sv); } }, b))));
    const [w, h] = heat ? heat.grid : [running.grid_w, running.grid_h];
    const readOnly = !running;
    const cells = {};
    for (const c of (heat ? heat.cells : [])) if (c.bssid === svBssid) cells[`${c.x},${c.y}`] = c.median_rssi;
    grid.style.gridTemplateColumns = `repeat(${w}, 1fr)`;
    grid.hidden = false;
    const btns = [];
    for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
      const v = cells[`${x},${y}`];
      const b = el("button", { type: "button", "aria-label": `cell ${x},${y}`, disabled: svBusy || readOnly,
        onclick: async (e) => {
          svBusy = true; e.currentTarget.classList.add("busy");
          $("#sv-msg").textContent = "Measuring — hold still about 15 seconds…";
          try { await call("POST", "/api/survey/measure", { x, y }); $("#sv-msg").textContent = "Saved. Move and tap the next spot."; }
          catch (err) { $("#sv-msg").textContent = err.message; }
          svBusy = false; refreshSurvey();
        } }, v == null ? "" : String(Math.round(v)));
      if (v != null) b.style.background = rssiColor(v);
      btns.push(b);
    }
    grid.replaceChildren(...btns);
    act.append(running
      ? el("button", { type: "button", class: "btn danger", onclick: async () => { await call("POST", "/api/survey/stop"); refreshSurvey(); } }, "Finish survey")
      : el("button", { type: "button", class: "btn", onclick: () => refreshSurvey() }, "Close"));
  }
  const weak = heat && heat.weak ? heat.weak.length : 0;
  $("#sv-past").replaceChildren(...(d.surveys || []).filter((x) => x.status !== "running").slice(0, 5).map((x) =>
    el("div", { class: "row" },
      el("span", { class: "sub", text: `${x.name} · ${x.status}` }),
      el("button", { type: "button", class: "btn", onclick: async () => {
        const r = await fetch(`/api/survey/csv?survey=${encodeURIComponent(x.id)}`, { headers: { Authorization: "Bearer " + token } });
        if (!r.ok) return;
        const a = el("a", { href: URL.createObjectURL(await r.blob()), download: `survey-${x.id}.csv` });
        document.body.append(a); a.click(); a.remove();
      } }, "CSV"),
      el("button", { type: "button", class: "btn", onclick: async () => renderSurvey({ ...(await call("GET", `/api/survey/state?survey=${encodeURIComponent(x.id)}`)), view: true }) }, "View"))));
  if (running && weak) $("#sv-msg").textContent ||= "Red cells are weak spots (below -70 dBm).";
}
async function refreshSurvey() {
  try { renderSurvey(await call("GET", "/api/survey/state")); } catch (e) { /* main poll reports */ }
}
for (const t of $$(".phases button")) t.addEventListener("click", () => { if (t.dataset.tab === "recon") refreshSurvey(); });
if (token) refreshSurvey();

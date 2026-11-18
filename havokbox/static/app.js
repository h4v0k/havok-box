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
  for (const c of kids.flat()) if (c !== null && c !== undefined) n.append(c instanceof Node ? c : String(c));
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
  const stealth = state.mode === "stealth";
  $("[data-hint=wired]").textContent = stealth
    ? "Stealth host discovery (passive listen) isn't built yet. Switch to Standard to sweep."
    : "Standard: nmap -sn sweep of in-scope networks (excluded hosts skipped).";
  $("[data-scan=wired]").dataset.stealthOff = stealth ? "1" : "";
}

function renderPhase() {
  const cur = PHASES.indexOf(state.phase);
  for (const li of $$(".phases li")) {
    const i = PHASES.indexOf(li.dataset.phase);
    li.classList.toggle("current", i === cur);
    li.classList.toggle("done", i < cur);
    if (i === cur) li.setAttribute("aria-current", "step"); else li.removeAttribute("aria-current");
  }
}

function renderStatus() {
  const s = $("#status");
  s.replaceChildren();
  if (state.running) s.append(el("span", { class: "run", text: "Running: " + state.running.label }));
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
  if (!items.length) return null;
  const det = el("details", { open: openDetails.has(f.result_id) },
    el("summary", { text: "Details" }), el("ul", {}, items));
  det.addEventListener("toggle", () => det.open ? openDetails.add(f.result_id) : openDetails.delete(f.result_id));
  return det;
}

function stepButton(p) {
  return el("button", {
    type: "button", class: "btn step" + (p.suggested ? " suggested" : ""),
    onclick: () => (p.needs_approval ? openSheet(p) : runPassive(p)),
  }, p.label || p.tool,
     el("small", { text: !p.in_scope ? `Out of scope · ${p.category}`
       : !p.runnable ? `Tool not installed yet · ${p.category}`
       : `${p.needs_approval ? "Needs approval" : "Passive"} · ${p.category}${p.source === "commander" ? " · AI" : ""}` }));
}

function renderFindings() {
  const box = $("#findings");
  const fs = state.findings.slice().reverse();
  const known = new Set(state.findings.map((f) => f.result_id));
  const waiting = state.proposals.filter((p) => !known.has(p.result_id));
  const waitBox = waiting.length ? el("article", { class: "finding" },
    el("header", {}, el("span", { class: "sum", text: "Scans waiting for approval" })),
    el("div", { class: "steps" }, waiting.map(stepButton))) : null;
  if (!fs.length && waitBox) { box.replaceChildren(waitBox); return; }
  if (!fs.length) { box.replaceChildren(el("p", { class: "empty", text: "No findings yet. Start with a recon card above." })); return; }
  const byResult = {};
  for (const p of state.proposals) (byResult[p.result_id] ||= []).push(p);
  box.replaceChildren(...(waitBox ? [waitBox] : []), ...fs.map((f) => {
    const twins = (f.data && f.data.evil_twins || []).length;
    const steps = (byResult[f.result_id] || []).sort((a, b) => b.suggested - a.suggested);
    return el("article", { class: "finding" },
      el("header", {},
        el("span", { class: "sum", text: f.summary }),
        twins ? el("span", { class: "tag alert", text: "Evil twin" }) : null,
        el("span", { class: "tag", text: f.space }),
        el("span", { class: "tag", text: f.mode })),
      el("time", { class: "hint", text: fmtTime(f.created) }),
      findingDetails(f),
      steps.length ? el("div", { class: "steps" }, steps.map(stepButton)) : null);
  }));
}

function renderEvidence() {
  $("#evidence").replaceChildren(...state.evidence.map((e) =>
    el("li", {}, el("span", { class: "k " + e.kind, text: e.kind }), e.detail, el("time", { text: fmtTime(e.ts) }))));
}

function render() {
  renderMode(); renderPhase(); renderStatus(); renderFindings(); renderEvidence();
  $("[data-tab=console]").hidden = !state.console_enabled;
  const busy = !!state.running;
  for (const b of $$("[data-scan]")) b.disabled = busy || b.dataset.stealthOff === "1";
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
for (const b of $$("[data-scan]")) b.addEventListener("click", async () => {
  b.disabled = true;
  try {
    const r = await call("POST", "/api/scan", { space: b.dataset.scan, mode: state.mode });
    if (r.status === "needs_approval") {
      await refresh();
      const p = state.proposals.find((x) => x.task_id === r.task_id);
      if (p) openSheet(p);
      return;
    }
  } catch (e) { $("#status").textContent = "Scan failed: " + e.message; }
  refresh();
});

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
  $("#sheet-why").textContent = p.in_scope ? (p.why || "") : "Out of scope — the gate will refuse this: " + p.gate_reason;
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
    await call("POST", "/api/approve", { task_id: p.task_id });
    await call("POST", "/api/run", { task_id: p.task_id });
    closeSheet();
  } catch (e) { $("#sheet-why").textContent = "Failed: " + e.message; $("#sheet-run").disabled = false; }
  refresh();
});

// ---- tabs + console -------------------------------------------------------
for (const t of $$(".tabs button")) t.addEventListener("click", () => {
  for (const o of $$(".tabs button")) {
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

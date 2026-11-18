// havok-box guard display. All box data is untrusted: DOM is built with textContent only.
"use strict";

const POLL_MS = 2000, FAIL_LIMIT = 3, SPEAK_GAP_MS = 20000, ALPR_SHOW_MS = 8000;
const $ = (s) => document.querySelector(s);

let token = localStorage.getItem("hb_guard_token") || "";
let started = false, timer = null, polling = false;
let state = null, fails = 0, linkLost = false, lostSpoken = false;
let lastId = null;            // highest alert id seen (null until first response)
let lastSpoke = 0, pendingHigh = null, mediumQueue = 0, wasStationary = false;
let alprId = null, alprShown = null, alprUntil = 0;
let notice = "", audioCtx = null, lastSig = "";

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(Infinity)) if (c !== null && c !== undefined) n.append(c instanceof Node ? c : String(c));
  return n;
}

// ---- network --------------------------------------------------------------
async function api(method, path, body) {
  // A box that loses power mid-request must not hang the poll: abort after 4 s (lost-link in ~6 s).
  const ctl = new AbortController();
  const timeout = setTimeout(() => ctl.abort(), 4000);
  let r;
  try {
    r = await fetch(path, {
      method, cache: "no-store", signal: ctl.signal,
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
  } finally { clearTimeout(timeout); }
  if (r.status === 401) { clearToken("Token rejected."); throw new Error("unauthorized"); }
  const data = await r.json().catch(() => ({}));
  if (r.status === 409) { const e = new Error(data.reason || "park first"); e.refused = true; throw e; }
  if (!r.ok) throw new Error("HTTP " + r.status);
  return data;
}

function clearToken(msg) {
  token = ""; localStorage.removeItem("hb_guard_token");
  clearInterval(timer); timer = null; started = false;
  show("token"); $("#token-err").textContent = msg || "";
}

// ---- views ----------------------------------------------------------------
function show(view) {
  $("#token-form").hidden = view !== "token";
  $("#start").hidden = view !== "start";
  $("#main").hidden = view !== "main";
  $("#root").dataset.view = view;
}

$("#token-form").addEventListener("submit", (e) => {
  e.preventDefault();
  token = $("#token").value.trim();
  if (!token) return;
  localStorage.setItem("hb_guard_token", token);
  $("#token").value = ""; $("#token-err").textContent = "";
  begin();
});

$("#start-btn").addEventListener("click", () => {
  if (!state || !state.can_touch) return;
  unlockAudio();
  started = true; requestWake();
  show("main"); lastSig = ""; render();
});

// ---- audio / speech -------------------------------------------------------
function unlockAudio() {
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC && !audioCtx) audioCtx = new AC();
    if (audioCtx && audioCtx.state === "suspended") audioCtx.resume();
  } catch (e) { /* best effort */ }
  try { if (window.speechSynthesis) { speechSynthesis.cancel(); speechSynthesis.speak(new SpeechSynthesisUtterance(" ")); } } catch (e) { /* ignore */ }
}

function chime() {            // two short tones, no audio files
  if (!audioCtx) return;
  try {
    const t0 = audioCtx.currentTime;
    [[880, 0], [660, 0.22]].forEach(([f, off]) => {
      const o = audioCtx.createOscillator(), g = audioCtx.createGain();
      o.type = "sine"; o.frequency.value = f;
      g.gain.setValueAtTime(0.0001, t0 + off);
      g.gain.exponentialRampToValueAtTime(0.5, t0 + off + 0.02);
      g.gain.exponentialRampToValueAtTime(0.0001, t0 + off + 0.18);
      o.connect(g); g.connect(audioCtx.destination);
      o.start(t0 + off); o.stop(t0 + off + 0.2);
    });
  } catch (e) { /* ignore */ }
}

function speak(text, force) {
  const now = Date.now();
  if (!started || !window.speechSynthesis || !text) return false;
  if (!force && now - lastSpoke < SPEAK_GAP_MS) return false;
  try { speechSynthesis.cancel(); speechSynthesis.speak(new SpeechSynthesisUtterance(String(text))); } catch (e) { return false; }
  lastSpoke = now;
  return true;
}

// ---- state handling -------------------------------------------------------
function handleAlerts(s) {
  const fresh = (s.alerts || []).filter((a) => lastId !== null && a.id > lastId);
  const maxId = Math.max(lastId === null ? 0 : lastId, ...(s.alerts || []).map((a) => a.id), 0);
  if (lastId !== null) {                       // first response is a baseline: never announce history
    const highs = fresh.filter((a) => a.severity === "high").sort((a, b) => b.id - a.id);
    if (highs.length) { chime(); pendingHigh = highs[0].phrase; }
    mediumQueue += fresh.filter((a) => a.severity === "medium").length;
  }
  lastId = maxId;
}

function handleSpeech(s) {
  if (pendingHigh && speak(pendingHigh, false)) pendingHigh = null;
  const still = !!s.stationary_60s;
  if (still && !wasStationary && mediumQueue > 0) {
    const n = mediumQueue;
    if (speak(n + (n === 1 ? " update" : " updates") + " while driving", false)) mediumQueue = 0;
  }
  if (!still) wasStationary = false; else if (mediumQueue === 0) wasStationary = true;
}

function handleAlpr(s) {
  const a = s.alpr_near;
  if (a && a.id !== alprId) { alprId = a.id; alprUntil = Date.now() + ALPR_SHOW_MS; chime(); }
  if (!a) alprId = null;
  if (a && Date.now() < alprUntil) alprShown = a.dist_m;
}

async function poll() {
  if (polling) return;
  polling = true;
  try {
    const since = lastId === null ? 0 : lastId;
    const s = await api("GET", "/api/guard/state?since=" + encodeURIComponent(since));
    fails = 0;
    if (linkLost) { linkLost = false; lostSpoken = false; }
    state = s;
    if (started) { handleAlerts(s); handleAlpr(s); handleSpeech(s); }
    else if (lastId === null) lastId = Math.max(0, ...(s.alerts || []).map((a) => a.id));
  } catch (e) {
    if (e.message === "unauthorized") { polling = false; return; }
    fails++;
    if (fails >= FAIL_LIMIT) {
      linkLost = true;
      if (!lostSpoken) lostSpoken = speak("Lost link to box") !== false;
    }
  }
  polling = false;
  render();
}

// ---- actions --------------------------------------------------------------
async function act(path, body) {
  notice = "";
  try { await api("POST", path, body); await poll(); }
  catch (e) { if (e.message !== "unauthorized") { notice = e.refused ? e.message : "Action failed"; render(); } }
}

// ---- rendering ------------------------------------------------------------
function fmtTime(ts) { return new Date(ts * 1000).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }); }

function statusWord() {
  if (linkLost) return ["NO LINK", "nolink"];
  const st = state && state.status;
  if (st === "alert") return ["ALERT", "alert"];
  if (st === "sentry") return ["SENTRY", "sentry"];
  return ["ALL CLEAR", "clear"];
}

function render() {
  if (!state) return;
  const can = !!state.can_touch;
  if (!started) {
    const b = $("#start-btn");
    b.disabled = !can; b.textContent = can ? "Start guard" : "Park to start";
    return;
  }
  const [word, cls] = statusWord();
  const alpr = Date.now() < alprUntil && alprId ? "Plate reader ahead · " + alprShown + " m" : "";
  const sig = JSON.stringify([word, state.fix, state.mode, can, state.recent, state.offers, alpr, notice]);
  if (sig === lastSig) return;
  lastSig = sig;

  $("#root").dataset.state = cls === "alert" ? "alert" : "";
  const st = $("#status"); st.textContent = word; st.className = "status " + cls;
  const fix = state.fix || {};
  const fixTxt = fix.mode >= 3 ? "3D" : fix.mode === 2 ? "2D" : "none";
  const mph = typeof fix.speed_mps === "number" ? Math.round(fix.speed_mps * 2.23694) : "--";
  const mode = { drive: "Drive", sentry: "Sentry", idle: "Idle" }[state.mode] || "Idle";
  $("#info").textContent = "GPS " + fixTxt + " · " + mph + " mph · " + mode;
  const ap = $("#alpr"); ap.hidden = !alpr; ap.textContent = alpr;
  $("#msg").textContent = notice;

  const list = $("#alerts"); list.replaceChildren();
  (state.recent || []).slice(0, 3).forEach((a) => {
    list.append(el("li", { class: a.severity + (a.acked ? " acked" : "") },
      el("span", { class: "phrase" }, a.phrase), el("span", { class: "time" }, fmtTime(a.ts)),
      can && !a.acked ? el("button", { class: "btn", type: "button", onclick: () => act("/api/guard/ack", { alert_id: a.id }) }, "Acknowledge") : null));
  });

  const ctl = $("#controls"); ctl.replaceChildren();
  if (can) {
    const armed = state.mode === "sentry";
    ctl.append(el("button", { class: "btn", type: "button", onclick: () => act("/api/guard/sentry", { arm: !armed }) }, armed ? "Disarm sentry" : "Arm sentry"));
    (state.offers || []).forEach((o) => ctl.append(el("button", { class: "btn", type: "button",
      onclick: () => act("/api/guard/mine", { radio: o.radio, dev_key: o.dev_key, label: o.label }) }, "Mark as mine: " + o.label)));
  }
  ctl.hidden = !can; $("#lock").hidden = can;
}

// Alert-memory ticks so the 8 s plate-reader banner expires even if the state is unchanged.
setInterval(() => { if (started) { lastSig = ""; render(); } }, 1000);

// ---- wake lock ------------------------------------------------------------
async function requestWake() {
  try { if (started && "wakeLock" in navigator && document.visibilityState === "visible") await navigator.wakeLock.request("screen"); }
  catch (e) { /* best effort */ }
}
document.addEventListener("visibilitychange", requestWake);

// ---- boot -----------------------------------------------------------------
function begin() {
  show("start");
  lastId = null; fails = 0; state = null;
  poll();
  clearInterval(timer); timer = setInterval(poll, POLL_MS);
}
if (token) begin(); else show("token");

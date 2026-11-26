"use strict";
const TOKEN = new URLSearchParams(location.search).get("t") || "";
const $ = (s) => document.querySelector(s);
function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === "text") e.textContent = v; else if (k === "class") e.className = v; else e.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null) e.append(k);
  return e;
}
async function api(path, body) {
  const r = await fetch(path + (path.includes("?") ? "&" : "?") + "t=" + encodeURIComponent(TOKEN), {
    method: body ? "POST" : "GET",
    headers: { "content-type": "application/json", "x-kit-token": TOKEN },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}

let DATA = null, CHOICES = {}, current = null, cat = null;
const CHAINS = "Chains (step-by-step)";

function tags(item) {
  const out = [];
  if (item.risk) out.push(el("span", { class: "tag " + item.risk, text: item.risk }));
  if (item.root) out.push(el("span", { class: "tag root", text: "needs sudo" }));
  if (item.est) out.push(el("span", { class: "tag", text: item.est }));
  return out;
}

function renderCats() {
  const names = [...DATA.categories, CHAINS];
  $("#cats").replaceChildren(...names.map((n) => {
    const b = el("button", { type: "button", class: "cat", "aria-pressed": String(n === cat), text: n });
    b.addEventListener("click", () => { cat = n; $("#q").value = ""; renderCats(); renderList(); });
    return b;
  }));
}

function items() {
  const q = $("#q").value.trim().toLowerCase();
  if (q) return [...DATA.recipes, ...DATA.chains.map((c) => ({ ...c, chain: true }))].filter((r) =>
    [r.id, r.name, r.what, r.category || "", r.cmd || "", r.notes || ""].join(" ").toLowerCase().includes(q));
  if (cat === CHAINS) return DATA.chains.map((c) => ({ ...c, chain: true }));
  return DATA.recipes.filter((r) => r.category === cat);
}

function renderList() {
  $("#detail").hidden = true; $("#list").hidden = false;
  const list = items();
  $("#list").replaceChildren(...(list.length ? list.map((r) => {
    const b = el("button", { type: "button", class: "card" },
      el("strong", { text: r.name }), el("span", { text: r.what }), el("div", {}, ...(r.chain ? [el("span", { class: "tag", text: r.steps.length + " steps" })] : tags(r))));
    b.addEventListener("click", () => openItem(r));
    return b;
  }) : [el("p", { class: "dim", text: "Nothing matches." })]));
}

function field(name, value) {
  const id = "f-" + name;
  const opts = CHOICES[name] || [];
  const inp = el("input", { id, name, value: value || "", list: opts.length ? id + "-l" : null, spellcheck: "false" });
  const lab = el("label", { for: id }, DATA.labels[name] || name, inp);
  if (opts.length) lab.append(el("datalist", { id: id + "-l" }, ...opts.map((o) => el("option", { value: o }))));
  return lab;
}

function openItem(r) {
  current = r;
  $("#list").hidden = true; $("#detail").hidden = false;
  $("#d-name").textContent = r.name;
  $("#d-meta").replaceChildren(...(r.chain ? [el("span", { class: "tag", text: "chain" })] : [el("span", { class: "tag", text: r.category }), ...tags(r)]));
  $("#d-what").textContent = r.what || "";
  $("#d-when").textContent = r.when ? "When: " + r.when : "";
  $("#d-steps").replaceChildren(...(r.chain ? [el("ol", { class: "steps" }, ...r.steps.map((s) => {
    const rec = DATA.recipes.find((x) => x.id === s); return el("li", { text: rec ? rec.name : s });
  }))] : []));
  const prefill = (n) => (["target", "tty"].includes(n) && CHOICES[n] && CHOICES[n][0]) || DATA.defaults[n] || "";
  $("#form").replaceChildren(...r.params.map((n) => field(n, prefill(n))));
  $("#d-notes").textContent = r.notes || "";
  $("#d-src").textContent = r.source ? "Source: " + r.source : "";
  $("#d-notes-wrap").hidden = !(r.notes || r.source);
  $("#cmd").hidden = true; msg("");
  const active = r.chain ? r.steps.some((s) => (DATA.recipes.find((x) => x.id === s) || {}).risk === "active") : r.risk === "active";
  $("#confirm-wrap").hidden = !active; $("#confirm").value = "";
  window.scrollTo(0, 0);
}

function values() {
  const v = {};
  for (const i of $("#form").querySelectorAll("input")) v[i.name] = i.value.trim();
  return v;
}
function msg(t, cls = "") { const m = $("#msg"); m.textContent = t; m.className = "msg " + cls; }

async function preview() {
  const r = await api("/api/preview", { id: current.id, values: values() });
  if (!r.ok) { msg(r.error, "err"); $("#cmd").hidden = true; return null; }
  $("#cmd").textContent = r.commands.join("\n\n") + (r.root ? "\n\n(runs with sudo)" : "") + "\n\nOutput: " + r.outdir;
  $("#cmd").hidden = false; msg("");
  return r;
}

$("#preview").addEventListener("click", () => preview().catch((e) => msg(e.message, "err")));
$("#copy").addEventListener("click", async () => {
  try {
    const r = await preview(); if (!r) return;
    await navigator.clipboard.writeText(r.commands.join("\n"));
    msg("Copied. Paste it into a terminal.", "ok");
  } catch (e) { msg("Couldn't copy: " + e.message, "err"); }
});
$("#run").addEventListener("click", async () => {
  try {
    const p = await preview(); if (!p) return;
    const r = await api("/api/run", { id: current.id, values: values(), confirm: $("#confirm").value });
    msg(r.ok ? "Running in a terminal window. Output: " + r.outdir : r.error, r.ok ? "ok" : "err");
  } catch (e) { msg(e.message, "err"); }
});
$("#back").addEventListener("click", renderList);
$("#q").addEventListener("input", renderList);

(async () => {
  try {
    [DATA, CHOICES] = await Promise.all([api("/api/recipes"), api("/api/choices")]);
  } catch (e) { document.body.replaceChildren(el("p", { class: "msg err", text: "Toolbox didn't load: " + e.message })); return; }
  const e = CHOICES.engagement;
  const box = $("#eng");
  if (e) { box.textContent = `Engagement "${e.name}": ${e.networks.join(", ")}`; box.className = "eng"; }
  else if ((CHOICES.target || []).length) { box.textContent = "In scope: " + CHOICES.target.join(", "); box.className = "eng"; }
  else { box.textContent = "No engagement: network recipes are refused until you pick the lab (hb engage)."; box.className = "eng none"; }
  cat = DATA.categories[0]; renderCats(); renderList();
})();

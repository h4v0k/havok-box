import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import worker from "../worker.js";

class FakeKV {
  constructor() { this.m = new Map(); this.failPutKey = null; this.putOrder = []; }
  async get(k) { return this.m.has(k) ? this.m.get(k).value : null; }
  async getWithMetadata(k) {
    const e = this.m.get(k);
    return e ? { value: e.value, metadata: e.metadata } : { value: null, metadata: null };
  }
  async put(k, value, opts = {}) {
    if (this.failPutKey === k) throw new Error("put failed");
    this.putOrder.push(k);
    this.m.set(k, { value, metadata: opts.metadata ?? null });
  }
  async delete(k) { this.m.delete(k); }
  async list({ prefix = "" } = {}) {
    const keys = [...this.m.keys()].filter((k) => k.startsWith(prefix)).sort()
      .map((name) => ({ name, metadata: this.m.get(name).metadata }));
    return { keys, list_complete: true };
  }
}

const P = "pub-token", V = "view-token";
const mkEnv = (over = {}) => ({ SNAPSHOTS: new FakeKV(), PUBLISH_TOKEN: P, VIEW_TOKEN: V, ...over });
const sha = (s) => createHash("sha256").update(s).digest("hex");
const snap = (version, extra = {}) =>
  JSON.stringify({ schema: 1, version, generated: "2026-11-18T03:00:00Z", box: "havok-box", findings: [], attack_path: [], evidence: [], ...extra });

function ingest(env, body, { version, token = P, hash, headers = {} } = {}) {
  const h = { "X-Snapshot-Version": String(version), "X-Snapshot-SHA256": hash ?? sha(body), ...headers };
  if (token) h.Authorization = "Bearer " + token;
  return worker.fetch(new Request("https://x/ingest", { method: "POST", headers: h, body }), env);
}
const get = (env, path, token) =>
  worker.fetch(new Request("https://x" + path, { headers: token ? { Authorization: "Bearer " + token } : {} }), env);

test("ingest happy path stores snapshot and latest", async () => {
  const env = mkEnv();
  const body = snap(1);
  const r = await ingest(env, body, { version: 1 });
  assert.equal(r.status, 201);
  assert.deepEqual(await r.json(), { version: 1 });
  assert.equal(r.headers.get("cache-control"), "no-store");
  assert.equal(r.headers.get("x-content-type-options"), "nosniff");
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  assert.equal(r.headers.get("referrer-policy"), "no-referrer");
  assert.equal(await env.SNAPSHOTS.get("latest"), "1");
  const e = env.SNAPSHOTS.m.get("snap:0000000001");
  assert.equal(e.value, body);
  assert.equal(e.metadata.sha256, sha(body));
  assert.equal(e.metadata.size, Buffer.byteLength(body));
});

test("ingest rejects bad token, missing token, and the view token", async () => {
  const env = mkEnv();
  for (const token of ["nope", V, null]) {
    const r = await ingest(env, snap(1), { version: 1, token });
    assert.equal(r.status, 401);
  }
  assert.equal(env.SNAPSHOTS.m.size, 0);
});

test("unset tokens fail closed with 503", async () => {
  assert.equal((await ingest(mkEnv({ PUBLISH_TOKEN: undefined }), snap(1), { version: 1 })).status, 503);
  assert.equal((await get(mkEnv({ VIEW_TOKEN: undefined }), "/api/versions", V)).status, 503);
  assert.equal((await get(mkEnv({ VIEW_TOKEN: undefined }), "/api/snapshot", V)).status, 503);
  // identical tokens would make them interchangeable: refuse
  assert.equal((await ingest(mkEnv({ VIEW_TOKEN: P }), snap(1), { version: 1 })).status, 503);
});

test("hash mismatch is 400", async () => {
  const env = mkEnv();
  const r = await ingest(env, snap(1), { version: 1, hash: sha("other") });
  assert.equal(r.status, 400);
  assert.equal(env.SNAPSHOTS.m.size, 0);
});

test("stale and equal versions are 409 and never overwrite", async () => {
  const env = mkEnv();
  const b5 = snap(5);
  assert.equal((await ingest(env, b5, { version: 5 })).status, 201);
  assert.equal((await ingest(env, snap(5, { box: "evil" }), { version: 5 })).status, 409);
  assert.equal((await ingest(env, snap(4), { version: 4 })).status, 409);
  assert.equal(env.SNAPSHOTS.m.get("snap:0000000005").value, b5);
  assert.equal(await env.SNAPSHOTS.get("latest"), "5");
});

test("schema and version mismatches are 400", async () => {
  const env = mkEnv();
  assert.equal((await ingest(env, JSON.stringify({ schema: 2, version: 1 }), { version: 1 })).status, 400);
  assert.equal((await ingest(env, snap(2), { version: 1 })).status, 400);
  assert.equal((await ingest(env, "not json", { version: 1 })).status, 400);
  assert.equal((await ingest(env, snap(1), { version: 0 })).status, 400);
  assert.equal((await ingest(env, snap(1), { version: "abc" })).status, 400);
});

test("oversize body is 413", async () => {
  const env = mkEnv();
  const body = snap(1, { pad: "a".repeat(5 * 1024 * 1024) });
  assert.equal((await ingest(env, body, { version: 1 })).status, 413);
  assert.equal(env.SNAPSHOTS.m.size, 0);
});

test("retention keeps newest 50", async () => {
  const env = mkEnv();
  for (let v = 1; v <= 55; v++) assert.equal((await ingest(env, snap(v), { version: v })).status, 201);
  const keys = [...env.SNAPSHOTS.m.keys()].filter((k) => k.startsWith("snap:")).sort();
  assert.equal(keys.length, 50);
  assert.equal(keys[0], "snap:0000000006");
  assert.equal(keys[49], "snap:0000000055");
  assert.equal(await env.SNAPSHOTS.get("latest"), "55");
});

test("versions and snapshot reads need VIEW_TOKEN, reject PUBLISH_TOKEN", async () => {
  const env = mkEnv();
  await ingest(env, snap(1), { version: 1 });
  await ingest(env, snap(2), { version: 2 });
  for (const p of ["/api/versions", "/api/snapshot", "/api/snapshot?v=1"]) {
    assert.equal((await get(env, p, null)).status, 401);
    assert.equal((await get(env, p, P)).status, 401);
    assert.equal((await get(env, p, "bad")).status, 401);
  }
  const vs = await (await get(env, "/api/versions", V)).json();
  assert.deepEqual(vs.map((x) => x.version), [2, 1]);
  assert.equal(vs[0].generated, "2026-11-18T03:00:00Z");
  assert.equal(vs[0].sha256, sha(snap(2)));
  const latest = await get(env, "/api/snapshot", V);
  assert.equal(latest.status, 200);
  assert.equal(await latest.text(), snap(2));
  assert.equal(latest.headers.get("x-snapshot-sha256"), sha(snap(2)));
  const old = await get(env, "/api/snapshot?v=1", V);
  assert.equal(old.headers.get("x-snapshot-sha256"), sha(snap(1)));
  assert.equal((await get(env, "/api/snapshot?v=99", V)).status, 404);
  assert.equal((await get(env, "/api/snapshot?v=abc", V)).status, 400);
});

test("latest is written last; failed second put leaves old latest", async () => {
  const env = mkEnv();
  await ingest(env, snap(1), { version: 1 });
  env.SNAPSHOTS.putOrder.length = 0;
  await ingest(env, snap(2), { version: 2 });
  assert.deepEqual(env.SNAPSHOTS.putOrder, ["snap:0000000002", "latest"]);

  env.SNAPSHOTS.failPutKey = "latest";
  await assert.rejects(() => ingest(env, snap(3), { version: 3 }));
  assert.equal(await env.SNAPSHOTS.get("latest"), "2");
  // retry of the same version succeeds once KV recovers
  env.SNAPSHOTS.failPutKey = null;
  assert.equal((await ingest(env, snap(3), { version: 3 })).status, 201);
  assert.equal(await env.SNAPSHOTS.get("latest"), "3");
});

test("GET / serves viewer with strict CSP, no token needed", async () => {
  const r = await get(mkEnv(), "/");
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type"), /text\/html/);
  const csp = r.headers.get("content-security-policy");
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe/);
  const html = await r.text();
  assert.match(html, /Read-only after-action snapshot/);
  assert.doesNotMatch(html, /\son[a-z]+=/i);
  assert.doesNotMatch(html, /<script>/);
  assert.equal(r.headers.get("x-frame-options"), "DENY");
  const js = await get(mkEnv(), "/app.js");
  assert.equal(js.status, 200);
  assert.doesNotMatch(await js.text(), /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
});

test("unknown path 404, wrong methods 405", async () => {
  const env = mkEnv();
  assert.equal((await get(env, "/nope")).status, 404);
  assert.equal((await get(env, "/ingest")).status, 405);
  for (const path of ["/", "/api/versions", "/api/snapshot"]) {
    const r = await worker.fetch(new Request("https://x" + path, { method: "POST", headers: { Authorization: "Bearer " + P }, body: "x" }), env);
    assert.equal(r.status, 405);
  }
  assert.equal(env.SNAPSHOTS.m.size, 0);
});

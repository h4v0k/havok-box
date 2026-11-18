// havok-box one-way read-only snapshot store. The box POSTs to /ingest; everything else is read-only.
import { VIEWER_HTML, VIEWER_JS, VIEWER_CSS } from "./viewer.js";

const MAX_BYTES = 5 * 1024 * 1024;
const KEEP = 50;
const PREFIX = "snap:";
const enc = new TextEncoder();

const BASE_HEADERS = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};
const CSP =
  "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function respond(body, status, type, extra) {
  return new Response(body, {
    status,
    headers: { ...BASE_HEADERS, "Content-Type": type, ...(extra || {}) },
  });
}
const json = (obj, status = 200, extra) =>
  respond(JSON.stringify(obj), status, "application/json; charset=utf-8", extra);
const err = (status, msg, extra) => json({ error: msg }, status, extra);

async function sha256Bytes(data) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}
function hex(u8) {
  return [...u8].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time compare: hash both sides to fixed length, then XOR-accumulate.
async function tokenOk(request, secret) {
  const h = request.headers.get("Authorization") || "";
  const m = /^Bearer (.+)$/.exec(h);
  const given = await sha256Bytes(enc.encode(m ? m[1] : ""));
  const want = await sha256Bytes(enc.encode(secret));
  let diff = m ? 0 : 1;
  for (let i = 0; i < want.length; i++) diff |= given[i] ^ want[i];
  return diff === 0;
}

// Returns a Response on failure, null on success.
async function authorize(request, env, name) {
  const secret = env[name];
  const other = env[name === "PUBLISH_TOKEN" ? "VIEW_TOKEN" : "PUBLISH_TOKEN"];
  if (!secret || (other && secret === other)) return err(503, "not configured");
  if (!(await tokenOk(request, secret))) {
    return err(401, "unauthorized", { "WWW-Authenticate": "Bearer" });
  }
  return null;
}

const pad = (n) => String(n).padStart(10, "0");

async function latestVersion(env) {
  const v = await env.SNAPSHOTS.get("latest");
  const n = v === null || v === undefined ? 0 : Number(v);
  return Number.isInteger(n) && n > 0 ? n : 0;
}

async function listSnaps(env) {
  const out = [];
  let cursor;
  for (;;) {
    const r = await env.SNAPSHOTS.list({ prefix: PREFIX, cursor });
    out.push(...r.keys);
    if (r.list_complete) break;
    cursor = r.cursor;
  }
  out.sort((a, b) => (a.name < b.name ? 1 : a.name > b.name ? -1 : 0)); // newest first
  return out;
}

async function ingest(request, env) {
  const denied = await authorize(request, env, "PUBLISH_TOKEN");
  if (denied) return denied;

  const vh = request.headers.get("X-Snapshot-Version") || "";
  if (!/^[1-9][0-9]{0,9}$/.test(vh)) return err(400, "bad X-Snapshot-Version");
  const version = Number(vh);
  const shaHdr = (request.headers.get("X-Snapshot-SHA256") || "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(shaHdr)) return err(400, "bad X-Snapshot-SHA256");

  const cl = request.headers.get("Content-Length");
  if (cl && Number(cl) > MAX_BYTES) return err(413, "too large");
  const buf = await request.arrayBuffer();
  if (buf.byteLength > MAX_BYTES) return err(413, "too large");

  const actual = hex(await sha256Bytes(buf));
  if (actual !== shaHdr) return err(400, "sha256 mismatch");

  let obj;
  const text = new TextDecoder("utf-8", { fatal: true });
  let body;
  try {
    body = text.decode(buf);
    obj = JSON.parse(body);
  } catch {
    return err(400, "invalid json");
  }
  if (!obj || typeof obj !== "object" || obj.schema !== 1) return err(400, "unsupported schema");
  if (obj.version !== version) return err(400, "version mismatch");

  if (version <= (await latestVersion(env))) return err(409, "stale version");

  const generated = typeof obj.generated === "string" ? obj.generated.slice(0, 64) : "";
  await env.SNAPSHOTS.put(PREFIX + pad(version), body, {
    metadata: { sha256: actual, generated, size: buf.byteLength },
  });
  await env.SNAPSHOTS.put("latest", String(version)); // written last

  try {
    const snaps = await listSnaps(env);
    for (const k of snaps.slice(KEEP)) await env.SNAPSHOTS.delete(k.name);
  } catch {
    // retention is best-effort; the next ingest retries it
  }
  return json({ version }, 201);
}

async function versions(request, env) {
  const denied = await authorize(request, env, "VIEW_TOKEN");
  if (denied) return denied;
  const snaps = await listSnaps(env);
  return json(
    snaps.map((k) => ({
      version: Number(k.name.slice(PREFIX.length)),
      generated: (k.metadata && k.metadata.generated) || "",
      sha256: (k.metadata && k.metadata.sha256) || "",
      size: (k.metadata && k.metadata.size) || 0,
    }))
  );
}

async function snapshot(request, env, url) {
  const denied = await authorize(request, env, "VIEW_TOKEN");
  if (denied) return denied;
  const q = url.searchParams.get("v");
  let v;
  if (q === null || q === "") v = await latestVersion(env);
  else if (/^[1-9][0-9]{0,9}$/.test(q)) v = Number(q);
  else return err(400, "bad v");
  if (!v) return err(404, "no snapshot");
  const r = await env.SNAPSHOTS.getWithMetadata(PREFIX + pad(v), "text");
  if (r.value === null || r.value === undefined) return err(404, "no such version");
  return respond(r.value, 200, "application/json; charset=utf-8", {
    "X-Snapshot-SHA256": (r.metadata && r.metadata.sha256) || "",
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path === "/ingest") {
      if (method !== "POST") return err(405, "method not allowed", { Allow: "POST" });
      return ingest(request, env);
    }
    const reads = ["/", "/app.js", "/app.css", "/api/versions", "/api/snapshot"];
    if (!reads.includes(path)) return err(404, "not found");
    if (method !== "GET" && method !== "HEAD") return err(405, "method not allowed", { Allow: "GET, HEAD" });

    if (path === "/") return respond(VIEWER_HTML, 200, "text/html; charset=utf-8", { "Content-Security-Policy": CSP });
    if (path === "/app.js") return respond(VIEWER_JS, 200, "text/javascript; charset=utf-8");
    if (path === "/app.css") return respond(VIEWER_CSS, 200, "text/css; charset=utf-8");
    if (path === "/api/versions") return versions(request, env);
    return snapshot(request, env, url);
  },
};

# havok-box snapshot (Cloudflare Worker)

One-way, read-only after-action snapshot. The box pushes to `/ingest`; the Worker stores in KV and
serves a viewer. Nothing is ever written back to the box and the box never reads from Cloudflare.

## Endpoints
- `POST /ingest` (PUBLISH_TOKEN): headers `X-Snapshot-Version`, `X-Snapshot-SHA256`; body = snapshot JSON (max 5 MB).
  Versions are monotonic; version <= latest returns 409. Newest 50 snapshots are kept.
- `GET /api/versions`, `GET /api/snapshot?v=<n>` (VIEW_TOKEN): read-only.
- `GET /` viewer page (static; data calls need the view token). `/app.js` and `/app.css` are its assets.

## Deploy
1. `cd cloudflare && wrangler kv namespace create SNAPSHOTS`, paste the id into `wrangler.toml`.
2. `wrangler secret put PUBLISH_TOKEN` and `wrangler secret put VIEW_TOKEN` (use two different long random values;
   if they are equal or either is unset the Worker answers 503).
3. `wrangler deploy`. Or connect the GitHub repo in the Cloudflare dashboard with root directory `cloudflare/`
   (add the KV binding and secrets there).

Findings are sensitive. Put **Cloudflare Access** in front of the viewer (and keep `/ingest` reachable by the box,
e.g. an Access bypass or service-token policy for `/ingest` only). The view token is a second layer, not a substitute.

## Box config
In the box config set `publish_url` to `https://<worker-host>/ingest` and export `HAVOKBOX_PUBLISH_TOKEN`
with the PUBLISH_TOKEN value. The box never holds the view token.

## Tests
`node --test cloudflare/test/` (Node 22, no installs).

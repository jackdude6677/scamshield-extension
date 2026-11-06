/**
 * ScamShield lookup proxy (Cloudflare Worker – free tier is enough).
 *
 * Why this exists: the Google Safe Browsing API needs an API key. A key inside
 * a browser extension can be extracted by anyone, so the key lives here, as a
 * Worker secret, and the extension never sees it.
 *
 * Privacy: the extension sends only 4-byte SHA-256 hash PREFIXES (8 hex chars),
 * never URLs. This Worker keeps no logs and no state beyond a short cache.
 *
 *   POST /v1/lookup   {"prefixes":["a1b2c3d4", ...]}      (1–30 prefixes)
 *   → 200 {"matches":[{"hash":"<64 hex>","threatTypes":["MALWARE"]}],"cacheSeconds":300}
 *   GET  /health      → 200 "OK"
 *
 * Secrets / vars (wrangler):
 *   SAFE_BROWSING_API_KEY   secret, required
 *   ALLOWED_ORIGINS         comma list, e.g. "chrome-extension://<your extension id>"
 */
const SB_URL = 'https://safebrowsing.googleapis.com/v5/hashes:search';
const MAX_PREFIXES = 30;
const MAX_BODY_BYTES = 4096;

const hexToBytes = (hex) => Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16)));
const bytesToHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
function b64ToBytes(b64) {
  const bin = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
function bytesToB64Url(bytes) {
  let s = '';
  bytes.forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function corsHeaders(origin, env) {
  const allowed = String(env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const h = { 'Vary': 'Origin', 'Cache-Control': 'no-store' };
  if (origin && allowed.includes(origin)) {
    h['Access-Control-Allow-Origin'] = origin;
    h['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
    h['Access-Control-Allow-Headers'] = 'Content-Type';
    h['Access-Control-Max-Age'] = '86400';
  }
  return h;
}
const json = (obj, status, headers) => new Response(JSON.stringify(obj), { status, headers: Object.assign({ 'Content-Type': 'application/json' }, headers) });

export async function handleRequest(request, env, fetchImpl = fetch) {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  const cors = corsHeaders(origin, env);

  if (url.pathname === '/health') return new Response('OK', { status: 200, headers: { 'Cache-Control': 'no-store' } });
  if (url.pathname !== '/v1/lookup') return json({ error: 'not_found' }, 404, cors);

  // Only the configured extension may call this.
  if (!cors['Access-Control-Allow-Origin']) return json({ error: 'forbidden' }, 403, cors);
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405, cors);
  if (!env.SAFE_BROWSING_API_KEY) return json({ error: 'not_configured' }, 503, cors);

  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) return json({ error: 'too_large' }, 413, cors);
  let body;
  try { body = JSON.parse(raw); } catch (e) { return json({ error: 'bad_json' }, 400, cors); }
  const prefixes = body && body.prefixes;
  if (!Array.isArray(prefixes) || prefixes.length < 1 || prefixes.length > MAX_PREFIXES ||
      !prefixes.every((p) => typeof p === 'string' && /^[0-9a-f]{8}$/.test(p))) {
    return json({ error: 'bad_prefixes' }, 400, cors);
  }

  const qs = Array.from(new Set(prefixes)).map((p) => 'hashPrefixes=' + bytesToB64Url(hexToBytes(p))).join('&');
  let sb;
  try {
    sb = await fetchImpl(`${SB_URL}?${qs}`, { headers: { 'x-goog-api-key': env.SAFE_BROWSING_API_KEY }, cf: { cacheTtl: 0 } });
  } catch (e) {
    return json({ error: 'upstream_unreachable' }, 502, cors);
  }
  if (!sb.ok) return json({ error: 'upstream_error' }, 502, cors);
  let data;
  try { data = await sb.json(); } catch (e) { return json({ error: 'upstream_bad_response' }, 502, cors); }

  const matches = (data.fullHashes || []).map((fh) => ({
    hash: bytesToHex(b64ToBytes(fh.fullHash)),
    threatTypes: Array.from(new Set((fh.fullHashDetails || []).map((d) => d.threatType).filter(Boolean))),
  }));
  const m = /^(\d+)s$/.exec(data.cacheDuration || '');
  return json({ matches, cacheSeconds: m ? Math.min(Number(m[1]), 3600) : 300 }, 200, cors);
}

export default { fetch: (request, env) => handleRequest(request, env) };

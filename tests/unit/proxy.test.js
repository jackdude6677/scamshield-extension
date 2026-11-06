const test = require('node:test');
const assert = require('node:assert/strict');
const T = require('../../extension/src/threatdb.js');

const ORIGIN = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
const env = { SAFE_BROWSING_API_KEY: 'SECRET-KEY-123', ALLOWED_ORIGINS: ORIGIN };
let handleRequest;
test.before(async () => { ({ handleRequest } = await import('../../proxy/worker.js')); });

const req = (body, o = {}) => new Request('https://proxy.example/v1/lookup', {
  method: o.method || 'POST', headers: Object.assign({ 'Content-Type': 'application/json', Origin: ORIGIN }, o.headers),
  body: o.method === 'GET' ? undefined : (typeof body === 'string' ? body : JSON.stringify(body)),
});

test('health check', async () => {
  const r = await handleRequest(new Request('https://proxy.example/health'), env);
  assert.equal(await r.text(), 'OK');
});

test('forwards prefixes upstream with the key in a header, never in the URL, and never returns the key', async () => {
  const full = await T.sha256Hex('evil.example/');
  const fullB64 = Buffer.from(full, 'hex').toString('base64');
  let seen;
  const upstream = async (url, init) => { seen = { url, init }; return new Response(JSON.stringify({ fullHashes: [{ fullHash: fullB64, fullHashDetails: [{ threatType: 'SOCIAL_ENGINEERING' }] }], cacheDuration: '120s' }), { status: 200 }); };
  const r = await handleRequest(req({ prefixes: [full.slice(0, 8)] }), env, upstream);
  const text = await r.text();
  assert.equal(r.status, 200);
  assert.equal(r.headers.get('access-control-allow-origin'), ORIGIN);
  const data = JSON.parse(text);
  assert.deepEqual(data.matches, [{ hash: full, threatTypes: ['SOCIAL_ENGINEERING'] }]);
  assert.equal(data.cacheSeconds, 120);
  assert.ok(!seen.url.includes('SECRET-KEY-123'));
  assert.equal(seen.init.headers['x-goog-api-key'], 'SECRET-KEY-123');
  assert.ok(!text.includes('SECRET-KEY-123'));
});

test('rejects other origins, bad methods and bad input', async () => {
  const up = async () => { throw new Error('should not be called'); };
  assert.equal((await handleRequest(req({ prefixes: ['aabbccdd'] }, { headers: { Origin: 'https://evil.example' } }), env, up)).status, 403);
  assert.equal((await handleRequest(new Request('https://proxy.example/v1/lookup', { method: 'POST', body: '{}' }), env, up)).status, 403);
  assert.equal((await handleRequest(req(null, { method: 'GET' }), env, up)).status, 405);
  assert.equal((await handleRequest(req('not json'), env, up)).status, 400);
  assert.equal((await handleRequest(req({ prefixes: [] }), env, up)).status, 400);
  assert.equal((await handleRequest(req({ prefixes: ['https://full.url/'] }), env, up)).status, 400);
  assert.equal((await handleRequest(req({ prefixes: Array(31).fill('aabbccdd') }), env, up)).status, 400);
  assert.equal((await handleRequest(req({ prefixes: ['aabbccdd'] }), { ALLOWED_ORIGINS: ORIGIN }, up)).status, 503);
});

test('handles CORS preflight and upstream failure', async () => {
  const pre = await handleRequest(new Request('https://proxy.example/v1/lookup', { method: 'OPTIONS', headers: { Origin: ORIGIN } }), env);
  assert.equal(pre.status, 204);
  const r = await handleRequest(req({ prefixes: ['aabbccdd'] }), env, async () => new Response('x', { status: 500 }));
  assert.equal(r.status, 502);
});

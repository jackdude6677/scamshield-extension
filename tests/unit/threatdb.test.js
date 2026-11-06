const test = require('node:test');
const assert = require('node:assert/strict');
const T = require('../../extension/src/threatdb.js');

test('expressions follow host-suffix × path-prefix rules', () => {
  const e = T.expressions('http://a.b.c.example.com/1/2.html?param=1#frag');
  assert.ok(e.includes('a.b.c.example.com/1/2.html?param=1'));
  assert.ok(e.includes('a.b.c.example.com/1/2.html'));
  assert.ok(e.includes('a.b.c.example.com/'));
  assert.ok(e.includes('a.b.c.example.com/1/'));
  assert.ok(e.includes('b.c.example.com/1/'));
  assert.ok(e.includes('example.com/'));
  assert.ok(!e.some((x) => x.startsWith('com/')));
  assert.ok(e.length <= 30);
});

test('IP hosts are only checked exactly; non-web URLs yield nothing', () => {
  assert.deepEqual(T.expressions('http://1.2.3.4/a/b').map((x) => x.split('/')[0]).filter((v, i, a) => a.indexOf(v) === i), ['1.2.3.4']);
  assert.deepEqual(T.expressions('chrome://settings'), []);
  assert.deepEqual(T.expressions('nonsense'), []);
});

test('sha256 matches a known vector', async () => {
  assert.equal(await T.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

function fakeProxy(listedExpr) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body, init });
    const wanted = await T.sha256Hex(listedExpr);
    const matches = body.prefixes.includes(wanted.slice(0, 8)) ? [{ hash: wanted, threatTypes: ['SOCIAL_ENGINEERING'] }] : [];
    return { ok: true, json: async () => ({ matches, cacheSeconds: 60 }) };
  };
  return { fetch, calls };
}

test('lookup finds a listed URL and sends only 8-hex-char prefixes', async () => {
  const p = fakeProxy('evil.example/phish/');
  const c = T.createClient({ endpoint: 'https://proxy.example', fetch: p.fetch });
  const r = await c.lookup('https://evil.example/phish/login.html?id=7');
  assert.equal(r.status, 'match');
  assert.deepEqual(r.threats, ['SOCIAL_ENGINEERING']);
  assert.equal(p.calls.length, 1);
  assert.ok(p.calls[0].body.prefixes.every((x) => /^[0-9a-f]{8}$/.test(x)));
  const sent = JSON.stringify(p.calls[0]);
  assert.ok(!sent.includes('evil.example') && !sent.includes('phish'), 'no URL text leaves the machine');
  assert.equal(p.calls[0].init.credentials, 'omit');
});

test('unlisted URL → no-match (not "safe"); results are cached', async () => {
  const p = fakeProxy('evil.example/phish/');
  const c = T.createClient({ endpoint: 'https://proxy.example', fetch: p.fetch });
  const r1 = await c.lookup('https://www.example.com/');
  assert.equal(r1.status, 'no-match');
  await c.lookup('https://www.example.com/');
  assert.equal(p.calls.length, 1);
});

test('a hash with a matching prefix but different full hash is not a match', async () => {
  const exprs = await T.hashExpressions('https://www.example.com/');
  const fake = exprs[0].slice(0, 8) + 'f'.repeat(56);
  const c = T.createClient({ endpoint: 'https://proxy.example', fetch: async () => ({ ok: true, json: async () => ({ matches: [{ hash: fake, threatTypes: ['MALWARE'] }] }) }) });
  assert.equal((await c.lookup('https://www.example.com/')).status, 'no-match');
});

test('failures and missing config fail open without throwing', async () => {
  assert.equal((await T.createClient({ endpoint: '' }).lookup('https://x.example/')).status, 'disabled');
  assert.equal((await T.createClient({ endpoint: 'http://remote.example', fetch: async () => { throw new Error('x'); } }).lookup('https://x.example/')).status, 'disabled');
  assert.equal((await T.createClient({ endpoint: 'https://p.example', fetch: async () => { throw new Error('offline'); } }).lookup('https://x.example/')).status, 'unavailable');
  assert.equal((await T.createClient({ endpoint: 'https://p.example', fetch: async () => ({ ok: false }) }).lookup('https://x.example/')).status, 'unavailable');
});

test('threat reasons use plain language', () => {
  const r = T.reasonsFromThreats(['MALWARE', 'SOCIAL_ENGINEERING']);
  assert.match(r[0].title, /scam|phishing/i);
  assert.equal(r.length, 2);
});

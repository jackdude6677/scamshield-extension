const test = require('node:test');
const assert = require('node:assert/strict');
const F = require('../../extension/src/feed.js');
const { build } = require('../../scripts/build-feed.js');

const memStore = () => { let v; return { get: async () => v, set: async (x) => { v = x; }, peek: () => v }; };
const mkFeed = async (lines, o = {}) => {
  const data = await build(lines, 'test');
  const calls = [];
  let t = 1000;
  const store = o.store || memStore();
  const feed = F.createFeed({
    getUrl: async () => o.url || 'https://feed.example/phishing.json', isEnabled: async () => o.enabled !== false, store, now: () => t,
    fetch: o.fetch || (async (url, init) => { calls.push({ url, init }); return { ok: true, text: async () => JSON.stringify(data) }; }),
  });
  return { feed, calls, store, tick: (ms) => { t += ms; }, data };
};

test('builder hashes host+path, skips junk, and protects well-known sites from whole-host listing', async () => {
  const d = await build(['# comment', 'https://evil.example/login.php?id=1', 'http://phish.test/', 'https://www.paypal.com/', 'https://docs.google.com/', 'not a url', ''], 'x');
  assert.equal(d.count, 2);
  assert.equal(d.skipped, 3);
  assert.ok(d.hashes.every((h) => /^[0-9a-f]{16}$/.test(h)));
  assert.ok(!JSON.stringify(d).includes('evil.example'), 'no readable URLs in the published file');
});

test('a listed page matches, regardless of query string; other pages on the same host do not', async () => {
  const { feed } = await mkFeed(['https://evil.example/bank/login.php?token=1', 'https://onlyhost.test/']);
  assert.equal((await feed.lookup('https://evil.example/bank/login.php?token=999')).status, 'match');
  assert.equal((await feed.lookup('https://evil.example/other.html')).status, 'no-match');
  assert.equal((await feed.lookup('https://onlyhost.test/anything/here')).status, 'match', 'a whole-host entry covers every path');
  assert.equal((await feed.lookup('https://onlyhost.test/')).status, 'match');
  assert.equal((await feed.lookup('https://www.example.com/')).status, 'no-match');
});

test('only one public file is downloaded; visited URLs never leave the machine', async () => {
  const { feed, calls } = await mkFeed(['https://evil.example/a']);
  await feed.lookup('https://secret-site.example/private?x=1');
  await feed.lookup('https://evil.example/a');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://feed.example/phishing.json');
  assert.ok(!JSON.stringify(calls).includes('secret-site'));
  assert.equal(calls[0].init.credentials, 'omit');
});

test('data is cached in storage, refreshed when stale, and older data is used if the refresh fails', async () => {
  const m = await mkFeed(['https://evil.example/a']);
  await m.feed.lookup('https://evil.example/a');
  assert.equal(m.calls.length, 1);
  assert.ok(m.store.peek().hashes.length === 1);
  m.tick(7 * 3600 * 1000);
  await m.feed.lookup('https://evil.example/a');
  assert.equal(m.calls.length, 2);
  // fresh feed object, same storage, network down: still protects from stored copy
  const f2 = F.createFeed({ getUrl: async () => '', isEnabled: async () => true, store: m.store, now: () => 1e12, fetch: async () => { throw new Error('offline'); } });
  assert.equal((await f2.lookup('https://evil.example/a')).status, 'match');
});

test('no data and no network → unavailable (not "safe"); disabled and bad URLs are respected', async () => {
  const down = await mkFeed([], { fetch: async () => { throw new Error('offline'); } });
  assert.equal((await down.feed.lookup('https://x.example/')).status, 'unavailable');
  assert.equal((await (await mkFeed(['https://evil.example/a'], { enabled: false })).feed.lookup('https://evil.example/a')).status, 'disabled');
  const bad = await mkFeed(['https://evil.example/a'], { url: 'http://remote.example/feed.json' });
  assert.equal((await bad.feed.lookup('https://evil.example/a')).status, 'unavailable');
  assert.equal(bad.calls.length, 0);
});

test('malformed or oversized feed files are rejected', async () => {
  for (const body of ['not json', '{"hashes":"x"}', JSON.stringify({ hashes: new Array(400001).fill('0123456789abcdef') })]) {
    const m = await mkFeed([], { fetch: async () => ({ ok: true, text: async () => body }) });
    assert.equal((await m.feed.refresh(true)).ok, false);
  }
  const m = await mkFeed([], { fetch: async () => ({ ok: true, text: async () => JSON.stringify({ hashes: ['zz', 5, '0123456789abcdef'] }) }) });
  await m.feed.refresh(true);
  assert.equal((await m.feed.status()).count, 1);
});

test('feed warning text is plain language', () => {
  assert.match(F.reasons()[0].title, /known phishing/);
});

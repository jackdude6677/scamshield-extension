/* ScamShield – free public phishing list, checked on this computer.
 * A GitHub Action rebuilds a list of 64-bit SHA-256 fragments from a public phishing feed every few hours.
 * The extension downloads that one public file and compares locally. The sites you visit are never sent anywhere.
 * "no-match" means "not on the list", never "safe". */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});
  const need = (n) => SS[n] || (typeof require === 'function' ? require('./' + n + '.js') : null);
  const T = need('threatdb');

  const DEFAULT_URL = 'https://raw.githubusercontent.com/jackdude6677/scamshield-extension/feed/phishing.json';
  const STALE_MS = 6 * 60 * 60 * 1000;
  const MAX_ENTRIES = 400000;
  const KEY_HEX = 16;

  function validUrl(u) {
    return /^https:\/\//i.test(u) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(u);
  }

  /** Same key the builder uses: sha256("host/path") first 16 hex chars. */
  async function keyFor(expr) { return (await T.sha256Hex(expr)).slice(0, KEY_HEX); }

  function createFeed(opts) {
    const doFetch = opts.fetch || ((...a) => g.fetch(...a));
    const now = opts.now || (() => Date.now());
    let set = null, meta = { at: 0, count: 0, generated: '' };
    let loading = null;

    async function load() {
      if (set) return;
      const saved = await opts.store.get();
      if (saved && Array.isArray(saved.hashes)) { set = new Set(saved.hashes); meta = { at: saved.at || 0, count: saved.hashes.length, generated: saved.generated || '' }; }
    }

    async function refresh(force) {
      const url = (await opts.getUrl()) || DEFAULT_URL;
      if (!validUrl(url)) return { ok: false, reason: 'bad-url' };
      await load();
      if (!force && set && now() - meta.at < STALE_MS) return { ok: true, cached: true };
      if (loading) return loading;
      loading = (async () => {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs || 15000);
        try {
          const res = await doFetch(url, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer', signal: ctrl.signal });
          if (!res.ok) return { ok: false, reason: 'http-' + res.status };
          const data = JSON.parse(await res.text());
          if (!data || !Array.isArray(data.hashes) || data.hashes.length > MAX_ENTRIES) return { ok: false, reason: 'bad-data' };
          const hashes = data.hashes.filter((h) => typeof h === 'string' && /^[0-9a-f]{16}$/.test(h));
          set = new Set(hashes);
          meta = { at: now(), count: hashes.length, generated: String(data.generated || '') };
          await opts.store.set({ at: meta.at, hashes, generated: meta.generated });
          return { ok: true };
        } catch (e) { return { ok: false, reason: 'network' }; } finally { clearTimeout(timer); loading = null; }
      })();
      return loading;
    }

    /** → { status: 'match' | 'no-match' | 'unavailable' | 'disabled' } */
    async function lookup(rawUrl) {
      if (opts.isEnabled && !(await opts.isEnabled())) return { status: 'disabled' };
      await load();
      if (!set || now() - meta.at >= STALE_MS) await refresh(false); // errors fall back to older data
      if (!set) return { status: 'unavailable' };
      for (const expr of T.expressions(rawUrl)) {
        if (set.has(await keyFor(expr))) return { status: 'match' };
      }
      return { status: 'no-match' };
    }

    async function status() { await load(); return { count: meta.count, at: meta.at, generated: meta.generated, loaded: !!set }; }
    return { lookup, refresh, status };
  }

  function reasons() {
    return [{
      code: 'THREAT_FEED_PHISHING', weight: 100, booster: false,
      title: 'This website is on a public list of known phishing sites',
      detail: 'This address appears on a free public list of scam ("phishing") websites that is updated several times a day. Sites like this try to steal passwords, card numbers or money.',
    }];
  }

  SS.feed = { createFeed, reasons, keyFor, DEFAULT_URL, STALE_MS, validUrl };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.feed;
})(typeof self !== 'undefined' ? self : globalThis);

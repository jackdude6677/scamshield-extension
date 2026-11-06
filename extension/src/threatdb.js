/* ScamShield – privacy-preserving threat-database lookups.
 *
 * The extension never sees an API key and never sends a full URL anywhere.
 * It sends only the first 4 bytes (8 hex chars) of SHA-256 hashes of URL
 * "expressions" to a small proxy you run (see /proxy). The proxy holds the
 * Google Safe Browsing key, asks Safe Browsing for the full hashes behind
 * those prefixes, and returns them. The extension then compares full hashes
 * locally. This follows the Safe Browsing hash-prefix model.
 */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});

  const MAX_PREFIXES = 30;
  const PREFIX_BYTES = 4;

  function hex(buf) {
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function sha256Hex(str) {
    const data = new TextEncoder().encode(str);
    return hex(await (g.crypto || require('node:crypto').webcrypto).subtle.digest('SHA-256', data));
  }

  /** Canonical host + path used for hashing (simplified Safe Browsing canonicalisation). */
  function canonicalize(rawUrl) {
    let u;
    try { u = new URL(String(rawUrl).replace(/[\t\r\n]/g, '')); } catch (e) { return null; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    let host = u.hostname.toLowerCase().replace(/^\.+|\.+$/g, '').replace(/\.{2,}/g, '.');
    if (!host) return null;
    // Resolve /./ and /../ and repeated slashes (URL() already resolves dots).
    let path = u.pathname.replace(/\/{2,}/g, '/') || '/';
    const query = u.search; // includes leading "?" or ""
    return { host, path, query };
  }

  /** Host-suffix and path-prefix combinations to check (max 30). */
  function expressions(rawUrl) {
    const c = canonicalize(rawUrl);
    if (!c) return [];
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(c.host) || c.host.startsWith('[');
    const labels = c.host.split('.');
    const hosts = [c.host];
    if (!isIP) {
      // up to 4 more, starting with the last 5 labels, down to the last 2
      const start = Math.max(1, labels.length - 5);
      for (let i = start; i <= labels.length - 2; i++) hosts.push(labels.slice(i).join('.'));
    }
    const paths = [];
    if (c.query) paths.push(c.path + c.query);
    paths.push(c.path);
    const parts = c.path.split('/').filter(Boolean);
    let acc = '/';
    paths.push('/');
    for (let i = 0; i < Math.min(parts.length - 1, 4); i++) {
      acc += parts[i] + '/';
      paths.push(acc);
    }
    const out = [];
    for (const h of Array.from(new Set(hosts))) for (const p of Array.from(new Set(paths))) out.push(h + p);
    return Array.from(new Set(out)).slice(0, MAX_PREFIXES);
  }

  async function hashExpressions(rawUrl) {
    const exprs = expressions(rawUrl);
    const hashes = await Promise.all(exprs.map(sha256Hex));
    return hashes;
  }

  const THREAT_COPY = {
    MALWARE: { title: 'This website is known to spread harmful software', detail: 'A security database lists this address as a source of malware. Visiting it can infect your computer.' },
    SOCIAL_ENGINEERING: { title: 'This website is a known scam or "phishing" site', detail: 'A security database lists this address as a site that tricks people into giving away passwords, bank details or money.' },
    UNWANTED_SOFTWARE: { title: 'This website is known to push unwanted software', detail: 'A security database lists this address as a source of software that changes your browser or computer without a clear choice.' },
    POTENTIALLY_HARMFUL_APPLICATION: { title: 'This website is known to offer harmful apps', detail: 'A security database lists this address as a source of apps that can harm your device.' },
  };

  /**
   * Look a URL up through the proxy.
   * Returns { status: 'match'|'no-match'|'unavailable'|'disabled', threats: [...] }
   * 'no-match' means only "not listed in the database right now" – never "safe".
   */
  function createClient(opts) {
    const cache = new Map(); // prefix -> { at, ttl, matches: [{hash, threatTypes}] }
    const doFetch = opts.fetch || ((...a) => g.fetch(...a));
    const now = opts.now || (() => Date.now());

    async function lookup(rawUrl) {
      const endpoint = (opts.getEndpoint ? await opts.getEndpoint() : opts.endpoint) || '';
      if (!endpoint) return { status: 'disabled', threats: [] };
      if (!/^https:\/\//i.test(endpoint) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(endpoint)) {
        return { status: 'disabled', threats: [] };
      }
      const fullHashes = await hashExpressions(rawUrl);
      if (!fullHashes.length) return { status: 'no-match', threats: [] };
      const prefixOf = (h) => h.slice(0, PREFIX_BYTES * 2);
      const prefixes = Array.from(new Set(fullHashes.map(prefixOf)));

      const t = now();
      const need = prefixes.filter((p) => { const c = cache.get(p); return !c || t - c.at > c.ttl; });
      if (need.length) {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs || 4000);
        try {
          const res = await doFetch(endpoint.replace(/\/+$/, '') + '/v1/lookup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ prefixes: need }),
            signal: ctrl.signal,
            credentials: 'omit',
            referrerPolicy: 'no-referrer',
            cache: 'no-store',
          });
          if (!res.ok) return { status: 'unavailable', threats: [] };
          const data = await res.json();
          const ttl = Math.min(Math.max(Number(data.cacheSeconds) || 300, 30), 3600) * 1000;
          const matches = Array.isArray(data.matches) ? data.matches : [];
          need.forEach((p) => cache.set(p, { at: t, ttl, matches: [] }));
          for (const m of matches) {
            if (!m || typeof m.hash !== 'string') continue;
            const c = cache.get(prefixOf(m.hash.toLowerCase()));
            if (c) c.matches.push({ hash: m.hash.toLowerCase(), threatTypes: Array.isArray(m.threatTypes) ? m.threatTypes.map(String) : [] });
          }
        } catch (e) {
          return { status: 'unavailable', threats: [] };
        } finally {
          clearTimeout(timer);
        }
      }

      const threats = new Set();
      for (const h of fullHashes) {
        const c = cache.get(prefixOf(h));
        if (!c) continue;
        c.matches.filter((m) => m.hash === h).forEach((m) => m.threatTypes.forEach((tt) => threats.add(tt)));
      }
      return threats.size ? { status: 'match', threats: Array.from(threats) } : { status: 'no-match', threats: [] };
    }
    return { lookup };
  }

  /** Convert a database match into the same "reasons" shape the other checks use. */
  function reasonsFromThreats(threats) {
    const known = threats.filter((t) => THREAT_COPY[t]);
    const order = ['SOCIAL_ENGINEERING', 'MALWARE', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];
    known.sort((a, b) => order.indexOf(a) - order.indexOf(b));
    const list = known.length ? known : ['SOCIAL_ENGINEERING'];
    return list.map((t) => ({ code: 'THREAT_DB_' + t, title: THREAT_COPY[t].title, detail: THREAT_COPY[t].detail, weight: 100, booster: false }));
  }

  SS.threatdb = { canonicalize, expressions, hashExpressions, sha256Hex, createClient, reasonsFromThreats, THREAT_COPY, MAX_PREFIXES };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.threatdb;
})(typeof self !== 'undefined' ? self : globalThis);

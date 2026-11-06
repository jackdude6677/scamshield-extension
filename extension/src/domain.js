/* ScamShield – hostname helpers (no network, no dependencies). */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});

  // Common two-part public suffixes. Not the full Public Suffix List; this is
  // enough for the brands we protect. Unknown suffixes fall back to the last
  // two labels.
  const MULTI_PART_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
    'co.nz', 'org.nz', 'govt.nz',
    'co.jp', 'or.jp', 'ne.jp', 'go.jp',
    'co.in', 'org.in', 'gov.in', 'net.in',
    'com.br', 'gov.br', 'org.br', 'net.br',
    'com.mx', 'gob.mx', 'org.mx',
    'co.za', 'org.za', 'gov.za',
    'com.cn', 'org.cn', 'gov.cn', 'net.cn',
    'com.sg', 'gov.sg', 'edu.sg',
    'com.hk', 'org.hk', 'gov.hk',
    'co.kr', 'or.kr', 'go.kr',
    'com.tr', 'gov.tr', 'org.tr',
    'com.ar', 'gob.ar', 'com.co', 'com.pe', 'com.ph', 'com.my', 'com.tw',
    'co.il', 'org.il', 'co.id', 'co.th', 'com.vn', 'com.ng', 'co.ke',
  ]);

  function isIPv4(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }
  function isIPv6(host) {
    return host.startsWith('[') && host.endsWith(']');
  }
  function isIPAddress(host) {
    return isIPv4(host) || isIPv6(host);
  }
  function isPrivateOrLocalHost(host) {
    if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') ||
        host.endsWith('.internal') || host.endsWith('.lan') || host.endsWith('.home.arpa')) return true;
    if (isIPv6(host)) return true; // conservative: never flag IPv6 literals as scams
    if (!isIPv4(host)) return false;
    const [a, b] = host.split('.').map(Number);
    return a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
  }

  /** Returns the registrable domain ("example.co.uk") of an ASCII hostname. */
  function registrableDomain(host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '');
    if (!host || isIPAddress(host)) return host;
    const labels = host.split('.');
    if (labels.length <= 2) return host;
    const lastTwo = labels.slice(-2).join('.');
    if (MULTI_PART_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join('.');
    return lastTwo;
  }

  /** Everything left of the registrable domain, as an array of labels. */
  function subdomainLabels(host) {
    host = String(host || '').toLowerCase().replace(/\.$/, '');
    const reg = registrableDomain(host);
    if (!reg || host === reg) return [];
    return host.slice(0, host.length - reg.length - 1).split('.');
  }

  /** The label that names the site: "paypal" for "www.paypal.co.uk". */
  function siteLabel(host) {
    const reg = registrableDomain(host);
    return reg.split('.')[0] || '';
  }

  function tld(host) {
    const labels = String(host || '').toLowerCase().split('.');
    return labels[labels.length - 1] || '';
  }

  /** True when host equals domain or is a subdomain of it. */
  function isSameOrSubdomain(host, domain) {
    host = String(host || '').toLowerCase();
    domain = String(domain || '').toLowerCase();
    return host === domain || host.endsWith('.' + domain);
  }

  // ---- Punycode (RFC 3492) decoder, so we can inspect IDN labels. ----
  function punycodeDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const output = [];
    let n = 128, i = 0, bias = 72;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 128) throw new Error('bad punycode');
      output.push(input.charCodeAt(j));
    }
    const adapt = (delta, numPoints, first) => {
      let k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (index >= input.length) throw new Error('bad punycode');
        const c = input.charCodeAt(index++);
        const digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) throw new Error('bad punycode');
        i += digit * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      const out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  /** Decode every xn-- label of a hostname to Unicode. Never throws. */
  function toUnicodeHost(host) {
    return String(host || '').split('.').map((label) => {
      if (label.startsWith('xn--')) {
        try { return punycodeDecode(label.slice(4)); } catch (e) { return label; }
      }
      return label;
    }).join('.');
  }

  // ---- Script detection for homograph checks ----
  function scriptOf(ch) {
    const c = ch.codePointAt(0);
    if (c < 0x80) return /[a-z0-9-]/i.test(ch) ? 'latin' : 'other';
    if ((c >= 0x00c0 && c <= 0x024f) || (c >= 0x1e00 && c <= 0x1eff)) return 'latin';
    if (c >= 0x0370 && c <= 0x03ff) return 'greek';
    if (c >= 0x0400 && c <= 0x052f) return 'cyrillic';
    if (c >= 0x0530 && c <= 0x058f) return 'armenian';
    if (c >= 0x0590 && c <= 0x06ff) return 'rtl';
    if (c >= 0x3040 && c <= 0x30ff) return 'cjk';
    if (c >= 0x4e00 && c <= 0x9fff) return 'cjk';
    if (c >= 0xac00 && c <= 0xd7af) return 'cjk';
    return 'other';
  }

  function scriptsInLabel(label) {
    const set = new Set();
    for (const ch of label) {
      if (ch === '-' || /\d/.test(ch)) continue;
      set.add(scriptOf(ch));
    }
    return set;
  }

  // Look-alike characters from other scripts → Latin.
  const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ѵ': 'v', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't',
    'в': 'b', 'ο': 'o', 'ν': 'v', 'α': 'a', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'i', 'ǀ': 'l', 'ı': 'i',
    'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'ç': 'c', 'è': 'e', 'é': 'e', 'ê': 'e',
    'ë': 'e', 'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i', 'ñ': 'n', 'ò': 'o', 'ó': 'o', 'ô': 'o', 'ö': 'o',
    'õ': 'o', 'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ý': 'y', 'ÿ': 'y',
  };

  /**
   * Reduce a label to a "skeleton" so look-alikes compare equal:
   * paypa1 / paypaI / раypal (Cyrillic) / paypal → "paypal"-like skeleton.
   */
  function skeleton(label) {
    let s = String(label || '').toLowerCase();
    s = Array.from(s).map((ch) => CONFUSABLES[ch] || ch).join('');
    s = s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl(?=[a-z])/g, 'd');
    s = s.replace(/[0]/g, 'o').replace(/[1il|]/g, 'l').replace(/5/g, 's').replace(/3/g, 'e').replace(/\$/g, 's');
    return s.replace(/-/g, '');
  }

  function editDistance(a, b, max) {
    if (Math.abs(a.length - b.length) > max) return max + 1;
    const prev = new Array(b.length + 1);
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      let diagPrev = prev[0];
      prev[0] = i;
      for (let j = 1; j <= b.length; j++) {
        const tmp = prev[j];
        prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diagPrev + (a[i - 1] === b[j - 1] ? 0 : 1));
        diagPrev = tmp;
      }
    }
    return prev[b.length];
  }

  SS.domain = {
    isIPAddress, isPrivateOrLocalHost, registrableDomain, subdomainLabels, siteLabel, tld,
    isSameOrSubdomain, punycodeDecode, toUnicodeHost, scriptsInLabel, skeleton, editDistance,
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.domain;
})(typeof self !== 'undefined' ? self : globalThis);

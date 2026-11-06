/* ScamShield – conservative URL / domain impersonation rules.
 * Pure functions: no network, no storage. A result of level "none" means
 * "no warning signs found by these rules". It NEVER means "safe". */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});
  const need = (n) => SS[n] || (typeof require === 'function' ? require('./' + n + '.js') : null);
  const D = need('domain');
  const { BRANDS, RISK_KEYWORDS } = need('brands');

  const WARNING_SCORE = 60; // show the full-page warning
  const CAUTION_SCORE = 35; // mention in popup only

  // Strong keywords make "brand + keyword" a credential-trap signal on their own.
  // Weak keywords only count together with another signal.
  const WEAK_KEYWORDS = new Set(['bank', 'banking', 'online', 'service', 'services', 'help', 'customer', 'care', 'official']);
  const STRONG_KEYWORDS = RISK_KEYWORDS.filter((k) => !WEAK_KEYWORDS.has(k));

  const SUSPICIOUS_TLDS = new Set(['top', 'xyz', 'click', 'icu', 'cfd', 'sbs', 'rest', 'gq', 'tk', 'ml', 'cf', 'ga', 'work',
    'support', 'monster', 'buzz', 'quest', 'zip', 'mov', 'cyou', 'bond', 'loan', 'country', 'kim', 'men', 'review']);

  // Sites where anyone can create "brand.example-host.com". Never judge these by subdomain.
  const SHARED_HOSTS = new Set(['github.io', 'gitlab.io', 'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com',
    'fandom.com', 'netlify.app', 'vercel.app', 'pages.dev', 'herokuapp.com', 'web.app', 'firebaseapp.com',
    'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'sharepoint.com', 'tumblr.com', 'medium.com',
    'substack.com', 'squarespace.com', 'myshopify.com', 'bubbleapps.io', 'glitch.me', 'repl.co', 'onrender.com']);

  // Real, unrelated sites whose names happen to sit one letter away from a protected brand.
  const KNOWN_NEIGHBOURS = new Set(['paypay.ne.jp', 'paypay.co.jp', 'paypay.com', 'googles.com', 'chaser.com']);

  const BRAND_KEYS = BRANDS.map((b) => {
    const keys = new Set([b.id]);
    b.aliases.forEach((a) => keys.add(a.replace(/[^a-z0-9]/g, '')));
    return { brand: b, keys: Array.from(keys), siteLabels: new Set(b.domains.map((d) => D.siteLabel(d))) };
  });

  function tokensOf(label) {
    return label.split(/[-_.]/).filter(Boolean);
  }

  function matchesBrandToken(token, key) {
    if (token === key) return true;
    if (key.length < 4) return false;
    for (const kw of STRONG_KEYWORDS.concat(Array.from(WEAK_KEYWORDS))) {
      const k = kw.replace(/-/g, '');
      if (token === key + k || token === k + key) return true;
    }
    return false;
  }

  function legitBrandsFor(host) {
    return BRANDS.filter((b) => b.domains.some((d) => D.isSameOrSubdomain(host, d)));
  }

  function R(code, title, detail, weight, booster) {
    return { code, title, detail, weight, booster: !!booster };
  }

  function levelFor(score) {
    return score >= WARNING_SCORE ? 'warning' : score >= CAUTION_SCORE ? 'caution' : 'none';
  }

  function combine(reasons) {
    const primary = reasons.filter((r) => !r.booster).sort((a, b) => b.weight - a.weight);
    const boosters = reasons.filter((r) => r.booster);
    let score = 0;
    if (primary.length) {
      score = primary[0].weight + primary.slice(1).reduce((s, r) => s + r.weight * 0.5, 0);
      if (primary[0].weight >= 30) score += boosters.reduce((s, r) => s + r.weight, 0);
    }
    score = Math.min(100, Math.round(score));
    const used = primary.concat(primary.length && primary[0].weight >= 30 ? boosters : []);
    return { score, level: levelFor(score), reasons: used };
  }

  /** Analyse one URL string. */
  function analyzeUrl(rawUrl) {
    let u;
    try { u = new URL(rawUrl); } catch (e) { return { level: 'none', score: 0, reasons: [], hostname: '', invalid: true }; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return { level: 'none', score: 0, reasons: [], hostname: u.hostname, skipped: true };

    const host = u.hostname.toLowerCase().replace(/\.$/, '');
    const reg = D.registrableDomain(host);
    const reasons = [];
    const unicodeHost = D.toUnicodeHost(host);

    if (D.isPrivateOrLocalHost(host)) return { level: 'none', score: 0, reasons: [], hostname: host, local: true };

    // 1. "https://chase.com@evil.example/" tricks
    if (u.username || u.password) {
      reasons.push(R('USERINFO_TRICK', 'The address hides the real website',
        `This link has an "@" sign in it. Everything before the "@" is ignored by the browser. The site you would actually visit is "${host}".`, 60));
    }

    // 2. Raw IP address
    if (D.isIPAddress(host)) {
      reasons.push(R('IP_ADDRESS', 'The address is just numbers',
        'Real companies almost never ask you to sign in at a numeric address like this. Scam sites often use them to avoid having a name.', 40));
    }

    const realBrands = legitBrandsFor(host);
    const isSharedHost = SHARED_HOSTS.has(reg);

    // 3. Mixed scripts in one label (e.g. Latin + Cyrillic): a classic look-alike trick
    unicodeHost.split('.').forEach((label) => {
      const scripts = D.scriptsInLabel(label);
      if (scripts.size > 1) {
        reasons.push(R('MIXED_SCRIPT', 'The address mixes letters from different alphabets',
          'Some letters in this web address come from a different alphabet (for example Russian or Greek letters that look like English ones). Scammers use this to copy real names.', 70));
      }
    });

    if (!realBrands.length && !isSharedHost && !D.isIPAddress(host)) {
      const siteLabelUni = D.siteLabel(unicodeHost);
      const siteTokens = tokensOf(siteLabelUni);
      const subs = D.subdomainLabels(host);
      const subTokens = subs.flatMap(tokensOf);
      const allTokens = siteTokens.concat(subTokens);
      const strongSet = new Set(STRONG_KEYWORDS.map((k) => k.replace(/-/g, '')));
      const hasStrongToken = allTokens.some((t) => strongSet.has(t));
      const hasWeakToken = allTokens.some((t) => WEAK_KEYWORDS.has(t));
      const concatKind = (t, key) => {
        if (key.length < 4) return null;
        for (const k of strongSet) if (t === key + k || t === k + key) return 'strong';
        for (const k of WEAK_KEYWORDS) if (t === key + k || t === k + key) return 'weak';
        return null;
      };

      for (const { brand, keys, siteLabels } of BRAND_KEYS) {
        const mainKey = keys[0];
        // 3a. real brand domain written in front: paypal.com.verify-account.net
        const subJoined = subs.join('.');
        const embedded = brand.domains.find((d) => ('.' + subJoined + '.').includes('.' + d + '.') || subJoined === d || subJoined.endsWith('.' + d));
        if (embedded && subs.length) {
          reasons.push(R('BRAND_DOMAIN_IN_SUBDOMAIN', `This address pretends to be ${brand.name}`,
            `The address starts with "${embedded}", but the website you would actually visit is "${reg}". ${brand.name}'s real website ends in ${brand.domains[0]}.`, 75));
          break;
        }
        // 3b. look-alike spelling of the site name
        const skeletons = siteTokens.concat([siteLabelUni]);
        const labelEquals = (t) => siteLabels.has(t);
        const lookalike = skeletons.find((t) => t.length >= 4 && !labelEquals(t) && keys.some((key) => key.length >= 4 && D.skeleton(t) === D.skeleton(key)));
        if (lookalike && !KNOWN_NEIGHBOURS.has(reg)) {
          reasons.push(R('LOOKALIKE_DOMAIN', `This address copies the name "${brand.name}"`,
            `"${reg}" is spelled to look like ${brand.name}, but it is not ${brand.name}'s website. ${brand.name}'s real website is ${brand.domains[0]}.`, 75));
          break;
        }
        // 3c. brand name + login-style word, on a domain the brand does not own
        const exact = allTokens.some((t) => keys.includes(t));
        const kinds = allTokens.flatMap((t) => keys.map((key) => concatKind(t, key))).filter(Boolean);
        const strong = (exact && hasStrongToken) || kinds.includes('strong');
        const weak = (exact && hasWeakToken) || kinds.includes('weak');
        if (strong) {
          reasons.push(R('BRAND_WITH_LOGIN_WORDS', `This address uses the name "${brand.name}"`,
            `The address "${host}" has the name ${brand.name} plus words like "login" or "secure", but it is not ${brand.name}'s website. Scam sites often do this. ${brand.name}'s real website is ${brand.domains[0]}.`, 65));
          break;
        }
        if (weak) {
          reasons.push(R('BRAND_NAME_USED', `This address uses the name "${brand.name}"`,
            `"${reg}" includes the name ${brand.name}, but it is not ${brand.name}'s website.`, 50));
          break;
        }
        // 3d. one-letter typo of a long brand name
        const typo = siteLabels.size && !siteLabels.has(D.siteLabel(host)) &&
          mainKey.length >= 6 && D.siteLabel(host).length >= 6 && D.editDistance(D.siteLabel(host), mainKey, 1) === 1 &&
          !KNOWN_NEIGHBOURS.has(reg);
        if (typo) {
          reasons.push(R('POSSIBLE_TYPO', `This address is very close to "${brand.name}"`,
            `"${reg}" differs from ${brand.name}'s name by only one letter. If you meant to visit ${brand.name}, the real website is ${brand.domains[0]}.`, 45));
          break;
        }
        // 3e. real brand name as a sub-label of a different site: paypal.secure-login.net
        if (subs.some((s) => keys.includes(s)) && (hasStrongToken || hasWeakToken)) {
          reasons.push(R('BRAND_AS_SUBDOMAIN', `This address pretends to be ${brand.name}`,
            `The name "${mainKey}" appears at the front of the address, but the website you would actually visit is "${reg}".`, 65));
          break;
        }
      }

      // Boosters: weak on their own, only used with a real signal above.
      if (SUSPICIOUS_TLDS.has(D.tld(host))) reasons.push(R('RISKY_ENDING', `The address ends in ".${D.tld(host)}"`, 'This ending is cheap and often used by short-lived scam sites.', 10, true));
      if ((siteLabelUni.match(/-/g) || []).length >= 3) reasons.push(R('MANY_HYPHENS', 'The address has many dashes', 'Long dashed names are common on scam sites.', 8, true));
      if (host.length > 45) reasons.push(R('LONG_ADDRESS', 'The address is unusually long', 'Very long addresses are often used to hide the real site.', 5, true));
      if (u.protocol === 'http:') reasons.push(R('NOT_ENCRYPTED', 'The connection is not encrypted', 'This site does not use HTTPS, so anything you type could be seen by others.', 10, true));
      const pathLower = decodeURIComponent((u.pathname || '').toLowerCase());
      BRAND_KEYS.forEach(({ brand, keys }) => {
        if (keys.some((key) => tokensOf(pathLower.replace(/\//g, '-')).includes(key)) && reasons.some((r) => !r.booster)) {
          reasons.push(R('BRAND_IN_PATH', `The page address mentions ${brand.name}`, `The part of the address after the site name mentions ${brand.name}, but the site itself is "${reg}".`, 8, true));
        }
      });
    }

    const out = combine(reasons);
    return Object.assign({ hostname: host, registrableDomain: reg }, out);
  }

  SS.urlcheck = { analyzeUrl, levelFor, combine, WARNING_SCORE, CAUTION_SCORE, R, legitBrandsFor };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.urlcheck;
})(typeof self !== 'undefined' ? self : globalThis);

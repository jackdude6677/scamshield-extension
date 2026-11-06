/* ScamShield – page content rules (fake bank logins, fake virus / tech-support alerts).
 * analyzePage() takes plain "features" so it can be unit-tested without a browser.
 * extractFeatures() turns a live Document into those features.
 * Level "none" means "no warning signs found". It never means "safe". */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});
  const need = (n) => SS[n] || (typeof require === 'function' ? require('./' + n + '.js') : null);
  const D = need('domain');
  const U = need('urlcheck');
  const { BRANDS, SECURITY_AND_SUPPORT_DOMAINS } = need('brands');

  const R = U.R;
  const MAX_TEXT = 6000;

  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  // ---------- Tech-support / fake virus alert phrases ----------
  const ALARM = [
    /\b(your|this)\s+(computer|pc|device|system|mac|browser|windows|phone|ip address)\b[^.!?\n]{0,40}\b(is|has been|have been|may be|might be|was|are)\b[^.!?\n]{0,25}\b(infected|hacked|compromised|blocked|locked|damaged|at risk)\b/i,
    /\b(\d+\s+)?(viruses|virus|trojans?|spyware|malware)\b[^.!?\n]{0,30}\b(detected|found|alert|warning|infection)\b/i,
    /\b(virus|malware|trojan|spyware)\s+(detected|alert|warning|found|infection)\b/i,
    /\b(windows|microsoft|apple|mac|system|security)\s+(defender\s+)?(security\s+)?(alert|warning|error|notice)\b/i,
    /\byour\s+(personal|banking|bank|credit card|financial|private)\s+(information|data|details|files|photos)\b[^.!?\n]{0,30}\b(stolen|at risk|exposed|in danger|compromised|being)\b/i,
    /\bsuspicious\s+activity\s+(was\s+)?(detected|found)\s+on\s+your\s+(computer|device|system|pc)\b/i,
  ];
  const CONTACT = [
    /\b(call|dial|contact|ring)\b[^.!?\n]{0,60}\b(now|immediately|right away|toll[- ]?free|support|technician|helpline|help line|hotline|helpdesk|help desk)\b/i,
    /\btoll[- ]?free\b/i,
    /\b(microsoft|apple|windows|norton|mcafee|geek squad)\s+(certified\s+)?(support|technician|helpline|help line|engineer|specialist)s?\b/i,
    /\b(?:\+?1[\s.-]?)?\(?8(?:00|33|44|55|66|77|88)\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/, // US toll-free numbers
  ];
  const PRESSURE = [
    /\bdo\s+not\s+(close|shut\s*down|restart|reboot|turn\s+off|ignore)\b/i,
    /\b(don'?t|do not)\s+(close|restart|shut|turn off|ignore)\b/i,
    /\b(immediately|right now|urgent(ly)?|within\s+\d+\s+(minutes?|seconds?|hours?))\b/i,
    /\b(data|files|photos|information|account)\b[^.!?\n]{0,30}\b(will be|may be|could be|are going to be)\s+(lost|deleted|erased|disabled|suspended|blocked)\b/i,
    /\b(failure|failing)\s+to\s+(call|respond|act|comply)\b/i,
    /\bcritical\s+(alert|error|warning)\b/i,
  ];

  // ---------- Fake bank / account login phrases ----------
  const SIGNIN_WORDS = /\b(sign\s*in|log\s*in|login|online\s+banking|account\s+access|enter\s+your\s+(password|passcode|pin)|member\s+login|secure\s+login|customer\s+login)\b/i;
  const URGENT_ACCOUNT = [
    /\b(verify|confirm|validate|re-?validate|update|restore|reactivate|unlock)\s+your\s+(account|identity|information|details|payment|billing|card|password|login|profile)\b/i,
    /\byour\s+account\s+(has been|have been|is|was|will be)\s+(suspended|locked|limited|restricted|disabled|closed|deactivated|compromised)\b/i,
    /\bunusual\s+(sign[- ]?in|login|activity)\b/i,
    /\bsecurity\s+(check|verification|update)\s+(required|needed)\b/i,
    /\bwithin\s+(24|48|72)\s+hours\b/i,
  ];
  const SENSITIVE_FIELD = /(ssn|social[-_ ]?security|card[-_ ]?number|cc-?num|cardnumber|cvv|cvc|security[-_ ]?code|pin\b|routing|account[-_ ]?number|mother|maiden)/i;

  function brandRegex(brand) {
    const names = Array.from(new Set(brand.aliases.concat([brand.name.toLowerCase()])));
    return new RegExp('(?:^|[^a-z0-9])(?:' + names.map(escapeRe).join('|') + ')(?:$|[^a-z0-9])', 'i');
  }
  const BRAND_RES = BRANDS.map((b) => ({ brand: b, re: brandRegex(b) }));

  function isTrustedForBrand(host, brand) {
    return brand.domains.some((d) => D.isSameOrSubdomain(host, d));
  }
  function isSecurityOrSupportSite(host) {
    return SECURITY_AND_SUPPORT_DOMAINS.some((d) => D.isSameOrSubdomain(host, d)) ||
      /\.(gov|edu|mil)(\.[a-z]{2})?$/.test(host);
  }
  function anyBrandOwns(host) {
    return BRANDS.some((b) => isTrustedForBrand(host, b));
  }

  function collect(patterns, text) {
    const hits = [];
    for (const re of patterns) {
      const m = text.match(re);
      if (m) hits.push(m[0].trim().slice(0, 80));
    }
    return hits;
  }

  /** Detect a fake virus / tech-support alert. */
  function techSupportScam(f, host) {
    const text = (f.title + ' \n ' + f.headings.join(' \n ') + ' \n ' + f.text).slice(0, MAX_TEXT);
    // Awareness articles and security vendors talk about these phrases legitimately.
    if (isSecurityOrSupportSite(host) || anyBrandOwns(host)) return null;
    if (/\bscams?\b|\bphishing\b|\bfraud\b|\bhow to (spot|avoid|recognize|report)\b/i.test(text)) return null;

    const alarm = collect(ALARM, text);
    const contact = collect(CONTACT, text);
    const pressure = collect(PRESSURE, text);
    const hasPhone = (f.phoneNumbers || []).length > 0 || CONTACT[3].test(text);

    // Conservative: need a false alarm AND a way to contact "support" AND urgency / lock-in behaviour.
    const lockIn = !!(f.usesBeforeUnload || f.fullscreenRequested || f.audioAutoplay);
    const strong = alarm.length >= 1 && (contact.length >= 1 || hasPhone) && (pressure.length >= 1 || lockIn || alarm.length >= 2);
    if (!strong) return null;

    let claimed = null;
    for (const { brand, re } of BRAND_RES) {
      if (['tech', 'security'].includes(brand.kind) && re.test(text)) { claimed = brand; break; }
    }
    return { alarm, contact, pressure, hasPhone, lockIn, claimed };
  }

  /** Detect a fake bank / payment / account login page. */
  function fakeLogin(f, host, urlResult) {
    if (!f.hasPasswordField) return null;
    if (anyBrandOwns(host)) {
      // On a brand's own domain, only warn if the page claims to be a *different* brand.
    }
    const head = (f.title + ' \n ' + f.headings.join(' \n ') + ' \n ' + f.text.slice(0, 600)).slice(0, 2000);
    const titleAndHeadings = f.title + ' \n ' + f.headings.join(' \n ');

    // Which brand does the page claim to be?
    let claimed = null;
    let inTitle = false;
    for (const { brand, re } of BRAND_RES) {
      if (isTrustedForBrand(host, brand)) continue; // genuine host for this brand
      if (['bank', 'payment', 'tech', 'shop', 'social', 'gov'].includes(brand.kind) && re.test(titleAndHeadings)) {
        claimed = brand; inTitle = true; break;
      }
    }
    if (!claimed) {
      // Brand in the first lines of body text plus sign-in wording is a weaker signal.
      for (const { brand, re } of BRAND_RES) {
        if (isTrustedForBrand(host, brand)) continue;
        if (['bank', 'payment'].includes(brand.kind) && re.test(head) && SIGNIN_WORDS.test(head)) { claimed = brand; break; }
      }
    }
    if (!claimed) return null;
    // A genuine host of ANY brand that merely mentions another brand (e.g. "Sign in with Google") is not a fake.
    if (anyBrandOwns(host)) return null;

    const reasons = [];
    const pageHost = host;
    reasons.push({ code: 'BRAND_CLAIM', weight: inTitle ? 30 : 20, brand: claimed });

    const signin = SIGNIN_WORDS.test(head) || SIGNIN_WORDS.test(f.text.slice(0, 1500));
    if (signin) reasons.push({ code: 'SIGNIN', weight: 10 });

    const foreign = (f.formActions || []).map((a) => { try { return new URL(a).hostname.toLowerCase(); } catch (e) { return ''; } })
      .filter((h) => h && D.registrableDomain(h) !== D.registrableDomain(pageHost));
    if (foreign.length) reasons.push({ code: 'FORM_ELSEWHERE', weight: 25, host: foreign[0] });

    if (f.protocol === 'http:') reasons.push({ code: 'HTTP_LOGIN', weight: 20 });

    const urgent = collect(URGENT_ACCOUNT, (f.text || '').slice(0, MAX_TEXT));
    if (urgent.length) reasons.push({ code: 'URGENT_ACCOUNT', weight: 20, phrase: urgent[0] });

    if ((f.inputHints || []).some((h) => SENSITIVE_FIELD.test(h))) reasons.push({ code: 'SENSITIVE_FIELDS', weight: 25 });

    // URL-level signals about this very host count too.
    if (urlResult && urlResult.score >= U.CAUTION_SCORE) reasons.push({ code: 'URL_SIGNALS', weight: Math.round(urlResult.score * 0.5) });

    return { claimed, reasons, signin };
  }

  /** Main entry: features → {level, score, reasons[]} */
  function analyzePage(f) {
    f = Object.assign({ title: '', headings: [], text: '', formActions: [], inputHints: [], phoneNumbers: [] }, f);
    let url;
    try { url = new URL(f.url); } catch (e) { return { level: 'none', score: 0, reasons: [] }; }
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return { level: 'none', score: 0, reasons: [] };
    const host = url.hostname.toLowerCase();
    if (D.isPrivateOrLocalHost(host)) return { level: 'none', score: 0, reasons: [] };
    f.protocol = url.protocol;

    const urlResult = U.analyzeUrl(f.url);
    const reasons = [];

    const ts = techSupportScam(f, host);
    if (ts) {
      const who = ts.claimed ? ts.claimed.name : 'a technology company';
      reasons.push(R('FAKE_VIRUS_ALERT', 'This page shows a fake virus or "tech support" alert',
        `The page says your computer has a problem and tells you to call a phone number. Real warnings from ${ts.claimed ? ts.claimed.name : 'Microsoft, Apple or your antivirus'} never appear as a web page with a phone number. This is a very common scam to get your money or remote access to your computer.`,
        ts.claimed || ts.lockIn ? 85 : 75));
      if (ts.claimed && !isTrustedForBrand(host, ts.claimed)) {
        reasons.push(R('FAKE_BRAND_SUPPORT', `This page pretends to be ${who}`, `The page uses the name ${who}, but the website is "${U.legitBrandsFor(host).length ? host : D.registrableDomain(host)}", not ${ts.claimed.domains[0]}.`, 20, true));
      }
      if (ts.lockIn) reasons.push(R('TRIES_TO_TRAP', 'The page tries to stop you from leaving', 'It uses pop-ups, full-screen or sound to make the alert feel real. You can safely close the tab.', 10, true));
    }

    const fl = fakeLogin(f, host, urlResult);
    if (fl) {
      const b = fl.claimed;
      const detail = [`The page asks for a password and says it is ${b.name}, but the website is "${D.registrableDomain(host)}". ${b.name}'s real website is ${b.domains[0]}.`];
      const extra = fl.reasons.find((r) => r.code === 'FORM_ELSEWHERE');
      if (extra) detail.push(`The form would send what you type to a different site ("${extra.host}").`);
      if (fl.reasons.some((r) => r.code === 'HTTP_LOGIN')) detail.push('The connection is not encrypted.');
      const urgent = fl.reasons.find((r) => r.code === 'URGENT_ACCOUNT');
      if (urgent) detail.push('It also pressures you to act fast ("' + urgent.phrase + '").');
      const weight = Math.min(95, fl.reasons.reduce((s, r) => s + r.weight, 0));
      reasons.push(R('FAKE_LOGIN_PAGE', `This looks like a fake ${b.name} sign-in page`, detail.join(' '), weight));
    }

    // Merge URL reasons (impersonating domain etc.)
    urlResult.reasons.forEach((r) => reasons.push(r));

    const out = U.combine(reasons);
    return Object.assign({ hostname: host }, out);
  }

  // ---------- Live DOM → features (content script) ----------
  function extractFeatures(doc, win) {
    const loc = (win || doc.defaultView).location;
    const body = doc.body;
    const text = body ? (body.innerText || body.textContent || '') : '';
    const forms = Array.from(doc.forms || []);
    const passwordInputs = Array.from(doc.querySelectorAll('input[type="password"]'))
      .filter((i) => !i.disabled && i.type === 'password');
    const formActions = [];
    passwordInputs.forEach((p) => {
      const form = p.form;
      if (form) {
        try { formActions.push(new URL(form.getAttribute('action') || loc.href, loc.href).href); } catch (e) { /* ignore */ }
      }
    });
    const inputHints = Array.from(doc.querySelectorAll('input, select, textarea')).map((i) =>
      [i.name, i.id, i.getAttribute('autocomplete'), i.getAttribute('placeholder'), i.getAttribute('aria-label')].filter(Boolean).join(' ')).slice(0, 80);
    const telLinks = Array.from(doc.querySelectorAll('a[href^="tel:"]')).map((a) => a.getAttribute('href')).slice(0, 10);
    const phoneRe = /(?:\+?1[\s.-]?)?\(?[2-9]\d{2}\)?[\s.-]\d{3}[\s.-]\d{4}/g;
    const phoneNumbers = telLinks.concat((text.slice(0, MAX_TEXT).match(phoneRe) || []).slice(0, 5));
    return {
      url: loc.href,
      title: doc.title || '',
      headings: Array.from(doc.querySelectorAll('h1, h2, h3')).slice(0, 8).map((h) => (h.innerText || h.textContent || '').trim()).filter(Boolean),
      text: text.slice(0, MAX_TEXT),
      hasPasswordField: passwordInputs.length > 0,
      passwordFieldCount: passwordInputs.length,
      formActions,
      formCount: forms.length,
      inputHints,
      phoneNumbers,
      usesBeforeUnload: false, // filled in by content script if it observes it
      fullscreenRequested: false,
      audioAutoplay: Array.from(doc.querySelectorAll('audio[autoplay], video[autoplay]')).some((a) => !a.muted),
    };
  }

  SS.pagecheck = { analyzePage, extractFeatures, techSupportScam, fakeLogin };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.pagecheck;
})(typeof self !== 'undefined' ? self : globalThis);

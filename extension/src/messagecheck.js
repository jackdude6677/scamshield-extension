/* ScamShield – analyse a pasted message or link WITHOUT opening anything.
 * Links are only parsed as text. "none" means "no warning signs found", never "safe". */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});
  const need = (n) => SS[n] || (typeof require === 'function' ? require('./' + n + '.js') : null);
  const U = need('urlcheck');
  const D = need('domain');

  const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'tiny.cc', 'rb.gy', 'lnkd.in', 'bl.ink', 'v.gd', 's.id', 'qr.ae']);

  // Each rule: id, title, why, weight, regex. Weights add up (with a cap), no single weak rule warns alone.
  const RULES = [
    { id: 'GIFT_CARDS', weight: 60, title: 'Asks for gift cards',
      why: 'Only scammers ask you to pay with gift cards. No bank, government office or company will.',
      re: /\b(gift\s*cards?|itunes\s+cards?|google\s+play\s+cards?|steam\s+cards?|amazon\s+cards?|ebay\s+cards?)\b/i, needs: /\b(buy|purchase|pay|send|scratch|read|code|numbers?|photo|picture|photograph)\b/i },
    { id: 'WIRE_CRYPTO', weight: 50, title: 'Asks for a wire transfer, cryptocurrency, or cash by mail',
      why: 'Money sent this way is almost impossible to get back, so scammers prefer it.',
      re: /\b(wire\s+(the\s+)?(money|transfer|funds)|western\s+union|moneygram|bitcoin|crypto(currency)?\s+(atm|wallet)|bitcoin\s+atm|cash\s+(by\s+mail|in\s+an?\s+envelope)|zelle\s+(me|it|the money))\b/i },
    { id: 'SECRECY', weight: 35, title: 'Tells you to keep it secret',
      why: 'Scammers tell victims not to talk to family, the bank or the police because those people would spot the scam.',
      re: /\b(don'?t|do not|keep\s+(this|it)|not)\b[^.!?\n]{0,25}\b(tell|told|share with|talk to|inform|mention|secret|between us|confidential)\b/i },
    { id: 'URGENT_PRESSURE', weight: 25, title: 'Pushes you to act right now',
      why: 'Scammers rush you so you do not stop to think or ask someone.',
      re: /\b(act\s+now|immediately|right\s+away|within\s+\d+\s+(hours?|minutes?|days?)|last\s+(chance|warning|notice)|final\s+notice|urgent|expires?\s+(today|soon|tonight)|asap|before\s+it'?s\s+too\s+late)\b/i },
    { id: 'ACCOUNT_THREAT', weight: 35, title: 'Says your account has a problem',
      why: 'Fake "problem with your account" messages are used to steal passwords and card numbers.',
      re: /\b(account|card|access)\b[^.!?\n]{0,30}\b(suspended|locked|frozen|limited|restricted|disabled|closed|compromised|on hold|deactivated)\b|\b(unusual|suspicious|unauthori[sz]ed)\s+(activity|sign[- ]?in|login|transaction|charge|access)\b/i },
    { id: 'VERIFY_DETAILS', weight: 30, title: 'Asks you to confirm personal or account details',
      why: 'Real companies do not ask you to "confirm" passwords, PINs, card numbers or Social Security numbers by message.',
      re: /\b(verify|confirm|validate|update|re-?enter)\b[^.!?\n]{0,25}\b(password|pin\b|card\s+number|social\s+security|ssn|bank\s+details?|account\s+details?|identity|billing|payment\s+(info|details|method))\b/i },
    { id: 'ONE_TIME_CODE', weight: 50, title: 'Asks you to read out a code',
      why: 'A code sent to your phone or email is a key to your account. Never read it out or reply with it.',
      re: /\b(read|tell|send|give|share|forward|reply with)\b[^.!?\n]{0,30}\b(code|otp|passcode|verification\s+code|6[- ]digit)\b/i },
    { id: 'REMOTE_ACCESS', weight: 55, title: 'Asks to control your computer',
      why: 'Giving someone remote access lets them steal from your accounts. Support staff never ask for this out of the blue.',
      re: /\b(anydesk|teamviewer|ultraviewer|logmein|remote\s+(access|desktop|support|session)|ammyy|supremo|quick\s+assist)\b/i },
    { id: 'TECH_SUPPORT_ALARM', weight: 45, title: 'Claims your computer is infected',
      why: 'Real companies do not contact you about viruses. This is a common way to get you to call a fake support line.',
      re: /\b(your\s+(computer|pc|device|mac|phone)\b[^.!?\n]{0,30}\b(infected|hacked|compromised)|virus(es)?\s+(detected|found)|malware\s+(detected|found))\b/i },
    { id: 'GOVERNMENT_THREAT', weight: 55, title: 'Threatens arrest, a lawsuit or lost benefits',
      why: 'The IRS, Social Security, Medicare and the police do not threaten people by text, email or phone, and never demand payment this way.',
      re: /\b(arrest(ed)?|warrant|lawsuit|legal\s+action|deport(ed|ation)?|jail|prison|suspend(ed)?\s+your\s+social\s+security|your\s+ssn\s+(has been|is)\s+(suspended|blocked|compromised)|irs\s+(agent|officer|case)|back\s+taxes|medicare\s+(card|number)\s+(expire|suspend))\b/i },
    { id: 'FAMILY_EMERGENCY', weight: 55, title: 'Looks like a "family member in trouble" scam',
      why: 'Scammers pretend to be a grandchild or relative in jail, in an accident or stranded, and ask for money fast. Call the person on a number you already know.',
      re: /\b(grand(son|daughter|ma|pa|mother|father|child)|it'?s\s+me|your\s+(son|daughter|nephew|niece))\b[^.!?\n]{0,80}\b(jail|accident|hospital|bail|lawyer|arrested|stranded|need\s+money|in\s+trouble|lost\s+my\s+(wallet|passport))\b/i },
    { id: 'PRIZE', weight: 50, title: 'Says you won a prize or are owed money',
      why: 'Real prizes do not ask you to pay fees or give bank details first. If you did not enter, you did not win.',
      re: /\b(you('| ha)?ve\s+won|congratulations[^.!?\n]{0,30}(won|winner|selected)|lottery|sweepstakes|claim\s+your\s+(prize|reward|refund|gift)|unclaimed\s+(funds|package|prize)|inheritance|you\s+are\s+owed\s+a\s+refund)\b/i },
    { id: 'DELIVERY_FEE', weight: 45, title: 'Asks for a small fee to deliver a package',
      why: 'Fake delivery messages ask for a "redelivery fee" to steal card details.',
      re: /\b(package|parcel|delivery|shipment)\b[^.!?\n]{0,50}\b(fee|unable to deliver|undeliverable|failed|on hold|address (is )?incomplete|reschedule|redelivery)\b/i },
    { id: 'ROMANCE_INVEST', weight: 35, title: 'Pushes an investment or sends you to a trading site',
      why: 'Scammers build trust, then show fake profits to get you to send more money.',
      re: /\b(guaranteed\s+(returns?|profit)|risk[- ]free\s+(investment|profit)|double\s+your\s+money|crypto\s+investment|trading\s+platform|insider\s+tip)\b/i },
    { id: 'CALL_NUMBER', weight: 20, title: 'Tells you to call a phone number from the message',
      why: 'Do not call numbers from unexpected messages. Look up the real number on the back of your card or the company\'s own website.',
      re: /\b(call|phone|dial|contact)\b[^.!?\n]{0,50}(\+?1?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})/i },
  ];

  // Defanged links: hxxp://, [.] , (dot)
  function refang(text) {
    return text.replace(/\bhxxps?:\/\//gi, (m) => m.replace(/xx/i, 'tt')).replace(/\[\.\]|\(\.\)|\s\(dot\)\s/gi, '.');
  }

  const TLDS = 'com|net|org|info|biz|co|us|uk|ca|au|de|io|me|xyz|top|click|link|online|site|shop|store|live|app|dev|support|help|club|cc|tk|ml|ga|cf|gq|ru|cn|in|ly|gl|to|sh|icu|work|vip|buzz|cfd|sbs|rest|bond|gov|edu';
  const URL_RE = new RegExp('(?:https?:\\/\\/[^\\s<>"\']+)|(?:\\bwww\\.[^\\s<>"\']+)|(?:\\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+(?:' + TLDS + ')\\b(?:\\/[^\\s<>"\']*)?)', 'gi');

  function extractLinks(text) {
    const found = [];
    const seen = new Set();
    let m;
    const t = refang(String(text || ''));
    while ((m = URL_RE.exec(t))) {
      let raw = m[0].replace(/[),.;:!?'"\]]+$/, '');
      if (/^[^@]*@[^/]*$/.test(raw) && !/^https?:\/\//i.test(raw)) continue; // email address, not a link
      // Skip the domain part of an email address.
      const before = t[m.index - 1];
      if (before === '@') continue;
      const normalized = /^https?:\/\//i.test(raw) ? raw : 'https://' + raw;
      let key;
      try { key = new URL(normalized).href; } catch (e) { continue; }
      if (seen.has(key)) continue;
      seen.add(key);
      found.push({ shown: raw, url: key });
    }
    return found.slice(0, 20);
  }

  function analyzeLink(link) {
    const res = U.analyzeUrl(link.url);
    const reasons = res.reasons.slice();
    const host = res.hostname || '';
    const reg = D.registrableDomain(host);
    if (SHORTENERS.has(reg)) {
      reasons.push(U.R('SHORT_LINK', 'This is a shortened link',
        'A shortened link hides where it really goes. Do not open it unless you trust whoever sent it and know what it is.', 30));
    }
    const combined = U.combine(reasons);
    return Object.assign({ shown: link.shown, url: link.url, hostname: host }, combined);
  }

  /** Text-only analysis. The caller may add threat-database results for the links afterwards. */
  function analyzeMessage(text) {
    text = String(text || '').trim();
    if (!text) return { empty: true, level: 'none', score: 0, reasons: [], links: [], advice: [] };
    const flat = text.replace(/\s+/g, ' ');
    const found = [];
    for (const rule of RULES) {
      if (rule.re.test(flat) && (!rule.needs || rule.needs.test(flat))) found.push({ code: rule.id, title: rule.title, detail: rule.why, weight: rule.weight });
    }
    const links = extractLinks(text).map(analyzeLink);

    const reasons = found.map((r) => Object.assign({ booster: false }, r));
    links.forEach((l) => l.reasons.filter((r) => r.weight >= 40).forEach((r) => reasons.push(Object.assign({}, r, { title: `Link "${l.shown.slice(0, 40)}": ${r.title}` }))));

    // Score: strongest + half of the rest. Several mild signals together can reach a warning.
    const sorted = reasons.slice().sort((a, b) => b.weight - a.weight);
    let score = sorted.length ? sorted[0].weight + sorted.slice(1).reduce((s, r) => s + r.weight * 0.5, 0) : 0;
    // A link in a message that also pressures you is the classic phishing shape.
    if (links.length && found.some((r) => ['URGENT_PRESSURE', 'ACCOUNT_THREAT', 'VERIFY_DETAILS', 'DELIVERY_FEE'].includes(r.code))) score += 10;
    score = Math.min(100, Math.round(score));
    const level = U.levelFor(score);

    const advice = [];
    if (level !== 'none') {
      advice.push('Do not click links, call numbers or reply.');
      advice.push('If it claims to be a company or bank, contact them using a phone number or website you already trust.');
      if (found.some((r) => ['GIFT_CARDS', 'WIRE_CRYPTO', 'ONE_TIME_CODE', 'REMOTE_ACCESS'].includes(r.code))) advice.push('Never send money, codes or computer access to someone who contacted you first.');
      advice.push('If you already shared a password or paid, call your bank right away and change the password.');
    }
    return { level, score, reasons: sorted, links, advice };
  }

  SS.messagecheck = { analyzeMessage, extractLinks, analyzeLink, RULES, SHORTENERS };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.messagecheck;
})(typeof self !== 'undefined' ? self : globalThis);

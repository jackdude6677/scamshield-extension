/* ScamShield – service worker.
 * Privacy: no analytics, no logging, no history stored. The only network call is an
 * optional hash-prefix lookup to the proxy the user configured. */
importScripts('src/domain.js', 'src/brands.js', 'src/urlcheck.js', 'src/threatdb.js', 'src/messagecheck.js', 'src/settings.js', 'src/feed.js');

const { analyzeUrl } = SS.urlcheck;
const ALLOW_MINUTES = 30;

const threatClient = SS.threatdb.createClient({
  getEndpoint: async () => {
    const s = await SS.settings.get();
    return s.dbEnabled ? s.proxyUrl : '';
  },
});

const feed = SS.feed.createFeed({
  getUrl: async () => (await SS.settings.get()).feedUrl,
  isEnabled: async () => (await SS.settings.get()).feedEnabled,
  store: {
    get: async () => (await chrome.storage.local.get('feed')).feed,
    set: (v) => chrome.storage.local.set({ feed: v }),
  },
});

/** Combine local rules and the threat database into one verdict. */
async function checkUrl(url) {
  const local = analyzeUrl(url);
  let db = { status: 'disabled', threats: [] };
  let fd = { status: 'disabled' };
  if (!local.invalid && !local.skipped && !local.local) [db, fd] = await Promise.all([threatClient.lookup(url), feed.lookup(url)]);
  if (db.status === 'match' || fd.status === 'match') {
    const reasons = (db.status === 'match' ? SS.threatdb.reasonsFromThreats(db.threats) : []).concat(fd.status === 'match' ? SS.feed.reasons() : []);
    return { level: 'threat', source: db.status === 'match' ? 'database' : 'feed', reasons: reasons.concat(local.reasons), db: db.status, feed: fd.status, hostname: local.hostname };
  }
  return { level: local.level, source: 'rules', reasons: local.reasons, db: db.status, feed: fd.status, hostname: local.hostname, score: local.score };
}

// ---- "Continue anyway" memory: this browser session only, per site, 30 minutes ----
async function allowHost(host) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  const now = Date.now();
  for (const h of Object.keys(allowed)) if (allowed[h] < now) delete allowed[h];
  allowed[host] = now + ALLOW_MINUTES * 60 * 1000;
  await chrome.storage.session.set({ allowed });
}
async function isAllowed(host) {
  const { allowed = {} } = await chrome.storage.session.get('allowed');
  return (allowed[host] || 0) > Date.now();
}

function b64url(obj) {
  const bytes = new TextEncoder().encode(JSON.stringify(obj));
  let s = '';
  bytes.forEach((b) => { s += String.fromCharCode(b); });
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function warningUrl(url, verdict) {
  const settings = await SS.settings.get();
  const payload = {
    u: url, level: verdict.level, src: verdict.source,
    reasons: verdict.reasons.slice(0, 4).map((r) => ({ c: r.code, t: r.title, d: r.detail })),
    cont: SS.settings.canContinue(settings, verdict.level),
  };
  return chrome.runtime.getURL('warning.html') + '#' + b64url(payload);
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/i.test(d.url)) return;
  try {
    const host = new URL(d.url).hostname;
    if (await isAllowed(host)) return;
    const verdict = await checkUrl(d.url);
    if (verdict.level === 'threat' || verdict.level === 'warning') {
      await chrome.tabs.update(d.tabId, { url: await warningUrl(d.url, verdict) });
    }
  } catch (e) { /* never break browsing */ }
});

async function setBadge(tabId, level) {
  try {
    if (level === 'warning' || level === 'threat') {
      await chrome.action.setBadgeText({ tabId, text: '!' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#B00020' });
    } else if (level === 'caution') {
      await chrome.action.setBadgeText({ tabId, text: '?' });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: '#8A5A00' });
    } else {
      await chrome.action.setBadgeText({ tabId, text: '' });
    }
  } catch (e) { /* tab closed */ }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg && msg.type) {
      case 'CHECK_URL': return checkUrl(String(msg.url || ''));
      case 'ANALYZE_MESSAGE': {
        const result = SS.messagecheck.analyzeMessage(String(msg.text || '').slice(0, 20000));
        let dbStatus = 'disabled';
        // Look links up by hash prefix only. Nothing is opened or fetched from the links themselves.
        for (const link of result.links) {
          const fd = await feed.lookup(link.url);
          if (fd.status === 'match') {
            link.level = 'threat';
            link.reasons = SS.feed.reasons().concat(link.reasons);
            result.level = 'threat';
            result.reasons = [Object.assign({}, link.reasons[0], { title: `Link "${link.shown.slice(0, 40)}": ${link.reasons[0].title}` })].concat(result.reasons);
          }
          const db = await threatClient.lookup(link.url);
          dbStatus = db.status === 'match' ? 'match' : (dbStatus === 'match' ? 'match' : db.status);
          if (db.status === 'match') {
            link.level = 'threat';
            link.reasons = SS.threatdb.reasonsFromThreats(db.threats).concat(link.reasons);
            result.level = 'threat';
            result.reasons = link.reasons.slice(0, 1).map((r) => Object.assign({}, r, { title: `Link "${link.shown.slice(0, 40)}": ${r.title}` })).concat(result.reasons);
          }
        }
        result.dbStatus = dbStatus;
        return result;
      }
      case 'FEED_STATUS': return feed.status();
      case 'FEED_REFRESH': { const r = await feed.refresh(true); return Object.assign({}, r, await feed.status()); }
      case 'ALLOW_CONTINUE': {
        const host = new URL(String(msg.url)).hostname;
        await allowHost(host);
        return { ok: true };
      }
      case 'GO_BACK': {
        const tabId = sender.tab && sender.tab.id;
        if (tabId == null) return { ok: false };
        try { await chrome.tabs.goBack(tabId); } catch (e) {
          try { await chrome.tabs.update(tabId, { url: 'chrome://newtab/' }); } catch (e2) { await chrome.tabs.update(tabId, { url: 'about:blank' }); }
        }
        return { ok: true };
      }
      case 'PAGE_RESULT': {
        if (sender.tab) await setBadge(sender.tab.id, msg.level);
        return { ok: true };
      }
      default: return { ok: false, error: 'unknown' };
    }
  })().then(sendResponse, () => sendResponse({ ok: false, error: 'failed' }));
  return true; // async response
});

chrome.runtime.onStartup.addListener(() => { feed.refresh(false).catch(() => {}); });
chrome.runtime.onInstalled.addListener((details) => {
  feed.refresh(false).catch(() => {});
  if (details.reason === 'install') chrome.runtime.openOptionsPage();
});

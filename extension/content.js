/* ScamShield – content script. Reads the page locally; nothing here leaves your computer.
 * Shows a full-page warning only for high-confidence fake bank logins / fake virus alerts. */
(function () {
  'use strict';
  if (window.top !== window) return;
  const SS = self.SS;
  const P = SS.pagecheck;
  const DISMISS_KEY = 'scamshield-dismissed-' + location.hostname;

  let last = { level: 'none', reasons: [], score: 0 };
  let overlayShown = false;
  let runs = 0;

  const CSS = `
    :host { all: initial; }
    .wrap { position: fixed; inset: 0; z-index: 2147483647; color: #fff; overflow: auto;
      background: radial-gradient(900px 480px at 50% -140px, rgba(255,60,90,.40), transparent 70%),
        repeating-linear-gradient(135deg, rgba(255,107,125,.05) 0 14px, transparent 14px 28px), #1b0208;
      font: 22px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; display: flex; align-items: flex-start; justify-content: center; }
    .card { max-width: 780px; width: 100%; padding: 32px 24px 48px; box-sizing: border-box; }
    .brand { font: 15px ui-monospace, Menlo, Consolas, monospace; letter-spacing: .16em; text-transform: uppercase; color: #ffb3bd; margin: 0 0 16px; }
    h1 { font-size: 36px; line-height: 1.2; margin: 0 0 16px; text-shadow: 0 0 18px rgba(255,80,100,.6); }
    p { margin: 0 0 16px; }
    .actions { display: flex; flex-direction: column; gap: 14px; margin: 28px 0 8px; }
    button { font: inherit; font-weight: 700; min-height: 60px; padding: 14px 24px; border-radius: 8px; border: 2px solid #fff; cursor: pointer; }
    button:focus-visible { outline: 5px solid #ffe066; outline-offset: 3px; }
    .primary { background: #fff; color: #3a0010; font-size: 26px; min-height: 68px; box-shadow: 0 0 26px rgba(255,255,255,.35); }
    .secondary { background: transparent; color: #fff; }
    .quiet { background: transparent; color: #fff; border-color: transparent; text-decoration: underline; font-weight: 500; min-height: 48px; }
    .why { background: rgba(0,0,0,.45); border: 1px solid #b3314a; padding: 16px 20px; margin-top: 16px; }
    .why ul { margin: 0; padding-left: 24px; } .why li { margin-bottom: 12px; }
    [hidden] { display: none !important; }
    @media (prefers-reduced-motion: no-preference) { .card { animation: in .15s ease-out; } @keyframes in { from { opacity: 0 } to { opacity: 1 } } }
  `;

  function el(tag, props, children) {
    const n = document.createElement(tag);
    Object.entries(props || {}).forEach(([k, v]) => { if (k === 'text') n.textContent = v; else n.setAttribute(k, v); });
    (children || []).forEach((c) => n.appendChild(c));
    return n;
  }

  async function allowContinue() {
    try {
      const { settings } = await chrome.storage.local.get('settings');
      const mode = (settings && settings.continueMode) || 'rules-only';
      return mode !== 'never';
    } catch (e) { return true; }
  }

  async function showOverlay(result) {
    if (overlayShown) return;
    overlayShown = true;
    const host = el('div', { id: 'scamshield-warning-host' });
    const root = host.attachShadow({ mode: 'closed' });
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(CSS);
      root.adoptedStyleSheets = [sheet];
    } catch (e) { root.appendChild(el('style', { text: CSS })); }

    const top = result.reasons[0];
    const title = el('h1', { id: 'ss-title', text: top.title });
    const summary = el('p', { id: 'ss-desc', text: top.detail });
    const why = el('div', { class: 'why', id: 'ss-why', hidden: '' }, [
      el('p', { text: 'Why am I seeing this?' }),
      el('ul', {}, result.reasons.slice(0, 4).map((r) => el('li', { text: r.detail }))),
      el('p', { text: 'ScamShield checked this page on your computer. Nothing you see or type was sent anywhere. It can make mistakes. If you are not sure, go back and ask someone you trust.' }),
    ]);
    const back = el('button', { class: 'primary', type: 'button', text: 'Go Back to safety' });
    const whyBtn = el('button', { class: 'secondary', type: 'button', 'aria-expanded': 'false', 'aria-controls': 'ss-why', text: 'Why?' });
    const cont = el('button', { class: 'quiet', type: 'button', text: 'Continue Anyway' });
    const actions = el('div', { class: 'actions' }, [back, whyBtn]);
    if (await allowContinue()) actions.appendChild(cont);

    const card = el('div', { class: 'card', role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'ss-title', 'aria-describedby': 'ss-desc' }, [
      el('p', { class: 'brand', text: 'ScamShield · threat alert' }), title, summary, actions, why,
    ]);
    root.appendChild(el('div', { class: 'wrap' }, [card]));

    back.addEventListener('click', () => chrome.runtime.sendMessage({ type: 'GO_BACK' }).catch(() => { location.href = 'about:blank'; }));
    whyBtn.addEventListener('click', () => {
      const open = why.hasAttribute('hidden');
      if (open) why.removeAttribute('hidden'); else why.setAttribute('hidden', '');
      whyBtn.setAttribute('aria-expanded', String(open));
    });
    let armed = false;
    cont.addEventListener('click', () => {
      if (!armed) {
        armed = true;
        cont.textContent = 'Yes, I understand the risk. Continue.';
        return;
      }
      try { sessionStorage.setItem(DISMISS_KEY, '1'); } catch (e) { /* ignore */ }
      host.remove();
      document.documentElement.style.removeProperty('overflow');
    });

    document.documentElement.appendChild(host);
    document.documentElement.style.setProperty('overflow', 'hidden', 'important');
    back.focus();
  }

  function analyze() {
    runs += 1;
    let result;
    try { result = P.analyzePage(P.extractFeatures(document, window)); } catch (e) { return; }
    last = result;
    try { chrome.runtime.sendMessage({ type: 'PAGE_RESULT', level: result.level }).catch(() => {}); } catch (e) { /* extension reloaded */ }
    let dismissed = false;
    try { dismissed = sessionStorage.getItem(DISMISS_KEY) === '1'; } catch (e) { /* ignore */ }
    if (result.level === 'warning' && !dismissed) showOverlay(result);
  }

  // Answer the popup.
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === 'GET_PAGE_RESULT') {
      analyze();
      sendResponse({ level: last.level, score: last.score, reasons: last.reasons.map((r) => ({ code: r.code, title: r.title, detail: r.detail })) });
    }
  });

  analyze();
  // Pages often build their content a moment after load; look again a couple of times.
  setTimeout(analyze, 1500);
  setTimeout(analyze, 5000);
  let timer = null;
  try {
    new MutationObserver(() => {
      if (runs >= 12 || overlayShown) return;
      clearTimeout(timer);
      timer = setTimeout(analyze, 1000);
    }).observe(document.documentElement, { childList: true, subtree: true });
  } catch (e) { /* ignore */ }
})();

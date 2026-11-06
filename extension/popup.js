(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const RANK = { none: 0, caution: 1, warning: 2, threat: 3 };

  const HEAD = {
    threat: 'Dangerous. Do not continue.',
    warning: 'This looks like a scam.',
    caution: 'Be careful.',
    none: 'No warning signs found.',
  };
  const NONE_NOTE = 'This does not mean it is safe. Scammers invent new tricks all the time. If anything feels wrong, stop and ask someone you trust.';

  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); }
  function add(parent, tag, text, cls) { const n = document.createElement(tag); if (text != null) n.textContent = text; if (cls) n.className = cls; parent.appendChild(n); return n; }

  function render(container, level, reasons, opts) {
    opts = opts || {};
    clear(container);
    container.className = 'card status ' + level;
    add(container, 'h2', HEAD[level]);
    if (opts.intro) add(container, 'p', opts.intro);
    if (reasons.length) {
      const ul = add(container, 'ul', null, 'reasons');
      reasons.slice(0, 5).forEach((r) => {
        const li = add(ul, 'li');
        add(li, 'strong', r.title + '. ');
        li.appendChild(document.createTextNode(r.detail));
      });
    }
    if (level === 'none') add(container, 'p', NONE_NOTE, 'fineprint');
    (opts.extra || []).forEach((t) => add(container, 'p', t));
  }

  async function checkActiveTab() {
    const box = $('page-status');
    let tab;
    try { [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); } catch (e) { /* ignore */ }
    if (!tab || !tab.url || !/^https?:/i.test(tab.url)) {
      render(box, 'none', [], { intro: 'This is not a regular web page, so ScamShield has nothing to check here.' });
      box.querySelector('h2').textContent = 'Nothing to check here.';
      const note = box.querySelector('.fineprint'); if (note) note.remove();
      return;
    }
    let host = '';
    try { host = new URL(tab.url).hostname; } catch (e) { /* ignore */ }
    const verdict = await chrome.runtime.sendMessage({ type: 'CHECK_URL', url: tab.url });
    let page = { level: 'none', reasons: [] };
    try { page = await chrome.tabs.sendMessage(tab.id, { type: 'GET_PAGE_RESULT' }) || page; } catch (e) { /* no content script */ }
    const level = RANK[page.level] > RANK[verdict.level] ? page.level : verdict.level;
    const reasons = (verdict.level === level ? verdict.reasons : []).concat(page.level === level ? page.reasons : []);
    const seen = new Set();
    const uniq = reasons.filter((r) => !seen.has(r.title) && seen.add(r.title));
    const extra = [];
    if (verdict.db === 'unavailable') extra.push('The online danger list could not be reached just now, so only checks on your computer were done.');
    render(box, level, uniq, { intro: 'Website: ' + host, extra });
  }

  async function analyzeMessage() {
    const text = $('msg').value;
    const out = $('msg-result');
    if (!text.trim()) {
      clear(out); out.className = 'card status caution';
      add(out, 'p', 'Please paste a message or link first.');
      $('msg').focus();
      return;
    }
    $('analyze').disabled = true;
    let result;
    try { result = await chrome.runtime.sendMessage({ type: 'ANALYZE_MESSAGE', text }); } finally { $('analyze').disabled = false; }
    if (!result || result.ok === false) {
      clear(out); out.className = 'card status caution'; add(out, 'p', 'Something went wrong. Please try again.'); return;
    }
    const extra = (result.advice || []).slice();
    render(out, result.level, result.reasons, { extra });
    if (result.links && result.links.length) {
      add(out, 'h2', 'Links in this message');
      const ul = add(out, 'ul', null, 'reasons');
      result.links.forEach((l) => {
        const li = add(ul, 'li', null, 'link-item');
        add(li, 'strong', l.shown + ': ');
        li.appendChild(document.createTextNode(l.level === 'none' ? 'no warning signs found (not a guarantee)' : (HEAD[l.level] || '') + (l.reasons[0] ? ' ' + l.reasons[0].title + '.' : '')));
      });
    }
    if (result.dbStatus === 'unavailable') add(out, 'p', 'The online danger list could not be reached, so links were only checked on your computer.', 'fineprint');
    out.focus();
  }

  async function showDbStatus() {
    const s = await SS.settings.get();
    $('db-status').textContent = s.dbEnabled && s.proxyUrl
      ? 'Online danger list: connected'
      : 'Online danger list: not connected (checks run on this computer only)';
  }

  async function init() {
    const s = await SS.settings.get();
    document.documentElement.className = 'size-' + s.textSize;
    $('analyze').addEventListener('click', analyzeMessage);
    $('clear').addEventListener('click', () => { $('msg').value = ''; clear($('msg-result')); $('msg-result').className = ''; $('msg').focus(); });
    $('settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
    showDbStatus();
    checkActiveTab().catch(() => render($('page-status'), 'none', [], { intro: 'Could not check this page.' }));
  }
  init();
})();

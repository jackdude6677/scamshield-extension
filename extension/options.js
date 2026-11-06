(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const radio = (name) => (document.querySelector(`input[name="${name}"]:checked`) || {}).value;

  function validProxy(v) {
    if (!v) return true;
    try {
      const u = new URL(v);
      if (u.username || u.password || u.search || u.hash) return false;
      return u.protocol === 'https:' || (u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1'));
    } catch (e) { return false; }
  }

  async function load() {
    const s = await SS.settings.get();
    document.documentElement.className = 'size-' + s.textSize;
    $('size-' + s.textSize).checked = true;
    $({ 'rules-only': 'cont-rules', always: 'cont-always', never: 'cont-never' }[s.continueMode]).checked = true;
    $('db-enabled').checked = s.dbEnabled;
    $('feed-enabled').checked = s.feedEnabled;
    showFeed();
    $('proxy').value = s.proxyUrl;
  }

  $('save').addEventListener('click', async () => {
    const proxy = $('proxy').value.trim().replace(/\/+$/, '');
    const msg = $('saved');
    if (!validProxy(proxy)) {
      msg.textContent = 'The lookup service address must start with https:// and contain no password or extra parts.';
      $('proxy').setAttribute('aria-invalid', 'true');
      $('proxy').focus();
      return;
    }
    $('proxy').removeAttribute('aria-invalid');
    await SS.settings.set({ textSize: radio('size'), continueMode: radio('cont'), dbEnabled: $('db-enabled').checked, feedEnabled: $('feed-enabled').checked, proxyUrl: proxy });
    document.documentElement.className = 'size-' + radio('size');
    msg.textContent = 'Saved.';
  });
  async function showFeed(extra) {
    const st = await chrome.runtime.sendMessage({ type: 'FEED_STATUS' }).catch(() => null);
    const el = $('feed-status');
    if (!st || !st.loaded) { el.textContent = (extra || '') + 'The list has not been downloaded yet.'; return; }
    el.textContent = (extra || '') + `${st.count.toLocaleString()} known phishing addresses. Last updated ${new Date(st.at).toLocaleString()}.`;
  }
  $('feed-refresh').addEventListener('click', async () => {
    const btn = $('feed-refresh'); btn.disabled = true; $('feed-status').textContent = 'Updating…';
    const r = await chrome.runtime.sendMessage({ type: 'FEED_REFRESH' }).catch(() => null);
    btn.disabled = false;
    await showFeed(r && r.ok ? '' : 'Could not download the list right now. ');
  });
  load();
})();

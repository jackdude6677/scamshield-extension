(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  let data;
  try {
    const b64 = location.hash.slice(1).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    data = JSON.parse(new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0))));
  } catch (e) { data = null; }

  // Text size preference
  try {
    chrome.storage.local.get('settings').then(({ settings }) => {
      if (settings && settings.textSize) document.documentElement.className = 'size-' + settings.textSize;
    });
  } catch (e) { /* ignore */ }

  if (!data || !data.u || !Array.isArray(data.reasons) || !data.reasons.length) {
    $('title').textContent = 'ScamShield stopped this page';
    $('summary').textContent = 'The warning details could not be read. For safety, please go back.';
  } else {
    let host = '';
    try { host = new URL(data.u).hostname; } catch (e) { /* ignore */ }
    const top = data.reasons[0];
    $('title').textContent = data.level === 'threat' ? 'Stop. This website is dangerous.' : 'Stop. This website looks like a scam.';
    $('summary').textContent = top.t + '. ' + top.d;
    $('host').textContent = host;
    $('fulladdr').textContent = data.u;
    const list = $('reasons');
    data.reasons.forEach((r) => {
      const li = document.createElement('li');
      const b = document.createElement('strong');
      b.textContent = r.t + '. ';
      li.appendChild(b);
      li.appendChild(document.createTextNode(r.d));
      list.appendChild(li);
    });
    $('source').textContent = data.src === 'database'
      ? 'This address is listed in a public security database of dangerous sites.'
      : data.src === 'feed'
      ? 'This address is on a free public list of phishing sites. The check happened on your computer, and your address was not sent anywhere.'
      : 'ScamShield checked this address on your computer using simple rules. It can make mistakes. Your address was not sent anywhere for this check.';
    if (data.cont) $('continue').hidden = false;
  }
  $('title').focus();

  $('back').addEventListener('click', () => {
    chrome.runtime.sendMessage({ type: 'GO_BACK' }).catch(() => history.back());
  });
  $('why').addEventListener('click', () => {
    const panel = $('why-panel');
    const open = panel.hidden;
    panel.hidden = !open;
    $('why').setAttribute('aria-expanded', String(open));
    if (open) panel.scrollIntoView({ block: 'nearest' });
  });
  let armed = false;
  $('continue').addEventListener('click', async () => {
    const btn = $('continue');
    if (!armed) {
      armed = true;
      btn.classList.add('armed');
      btn.textContent = 'Yes, I understand the risk. Continue.';
      return;
    }
    if (!data) return;
    await chrome.runtime.sendMessage({ type: 'ALLOW_CONTINUE', url: data.u });
    location.replace(data.u);
  });
})();

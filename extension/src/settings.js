/* ScamShield – settings (stored only on this computer: chrome.storage.local). */
(function (g) {
  'use strict';
  const SS = (g.SS = g.SS || {});
  const DEFAULTS = {
    dbEnabled: true,          // use the threat database when a proxy is configured
    proxyUrl: '',             // https://… address of your own lookup proxy (no keys in here)
    feedEnabled: true,        // free public phishing list, checked on this computer
    feedUrl: '',              // empty = built-in default
    continueMode: 'rules-only', // 'rules-only' | 'always' | 'never'
    textSize: 'large',        // 'normal' | 'large' | 'xlarge'
  };
  async function get() {
    try {
      const { settings } = await chrome.storage.local.get('settings');
      return Object.assign({}, DEFAULTS, settings || {});
    } catch (e) { return Object.assign({}, DEFAULTS); }
  }
  async function set(patch) {
    const next = Object.assign(await get(), patch);
    await chrome.storage.local.set({ settings: next });
    return next;
  }
  /** Should the "Continue anyway" choice be offered for this verdict? */
  function canContinue(settings, verdictLevel) {
    if (settings.continueMode === 'never') return false;
    if (settings.continueMode === 'always') return true;
    return verdictLevel !== 'threat'; // confirmed database threats: no shortcut by default
  }
  SS.settings = { DEFAULTS, get, set, canContinue };
  if (typeof module !== 'undefined' && module.exports) module.exports = SS.settings;
})(typeof self !== 'undefined' ? self : globalThis);

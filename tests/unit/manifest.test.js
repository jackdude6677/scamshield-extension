const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const ext = path.join(__dirname, '..', '..', 'extension');
const manifest = JSON.parse(fs.readFileSync(path.join(ext, 'manifest.json'), 'utf8'));

test('Manifest V3 with minimal permissions and no host access beyond page scanning', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions.slice().sort(), ['activeTab', 'storage', 'webNavigation']);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.optional_host_permissions, undefined);
  for (const bad of ['tabs', 'history', 'cookies', 'webRequest', 'scripting', 'declarativeNetRequest', '<all_urls>']) {
    assert.ok(!(manifest.permissions || []).includes(bad), bad);
  }
  assert.deepEqual(manifest.content_scripts[0].matches, ['http://*/*', 'https://*/*']);
  assert.equal(manifest.content_scripts[0].all_frames, false);
});

test('every file the manifest points to exists', () => {
  const refs = [manifest.background.service_worker, manifest.action.default_popup, manifest.options_ui.page,
    ...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon), ...manifest.content_scripts[0].js];
  for (const r of refs) assert.ok(fs.existsSync(path.join(ext, r)), r);
});

test('extension pages use a strict CSP and have no inline scripts', () => {
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  for (const f of ['popup.html', 'options.html', 'warning.html']) {
    const html = fs.readFileSync(path.join(ext, f), 'utf8');
    assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), f + ' has an inline script');
    assert.ok(!/\son\w+\s*=/.test(html), f + ' has inline event handlers');
  }
});

test('no API keys or remote code anywhere in the extension', () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
  for (const f of walk(ext)) {
    if (/\.png$/.test(f)) continue;
    const t = fs.readFileSync(f, 'utf8');
    assert.ok(!/AIza[0-9A-Za-z_-]{30,}/.test(t), 'API key pattern in ' + f);
    assert.ok(!/key=|x-goog-api-key|safebrowsing\.googleapis\.com/i.test(t), 'Safe Browsing details in ' + f);
    assert.ok(!/<script[^>]+src=["']https?:/i.test(t) && !/\beval\(|new Function\(/.test(t), 'remote/eval code in ' + f);
    assert.ok(!/google-analytics|gtag\(|sentry|mixpanel|segment\.com/i.test(t), 'analytics in ' + f);
  }
});

test('network calls are only the public feed download and the optional proxy lookup', () => {
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
  const users = walk(ext).filter((f) => f.endsWith('.js') && /\bfetch\(|XMLHttpRequest|sendBeacon|WebSocket/.test(fs.readFileSync(f, 'utf8')));
  assert.deepEqual(users.map((f) => path.basename(f)).sort(), ['feed.js', 'threatdb.js']);
});

/* End-to-end test: loads the unpacked extension into real Chromium and walks through every protection.
 * Fake "scam" hostnames (*.test) are mapped to a local server, so nothing touches the internet. */
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const T = require('../../extension/src/threatdb.js');

const EXT = path.join(__dirname, '..', '..', 'extension');
const results = [];
async function step(name, fn) {
  try { await Promise.race([fn(), new Promise((_, rej) => setTimeout(() => rej(new Error('step timed out after 40s')), 40000))]); results.push([true, name]); console.log('  ok  ', name); } catch (e) { results.push([false, name]); console.log('  FAIL', name, '\n      ', e.message.split('\n').join('\n       ')); }
}

const waitUrl = async (p, re, timeout = 10000) => {
  const end = Date.now() + timeout;
  while (Date.now() < end) { if (re.test(p.url())) return; await new Promise((r) => setTimeout(r, 100)); }
  throw new Error('timed out waiting for URL ' + re + ' (now ' + p.url() + ')');
};
const waitWarning = async (p) => {
  await waitUrl(p, /warning\.html/);
  await p.waitForFunction(() => { const t = document.getElementById('title'); return t && t.textContent !== 'Loading…'; });
};

const PAGES = {
  'www.example.test': '<title>Example Domain</title><h1>Welcome to Example</h1><p>A perfectly ordinary page about gardening.</p>',
  'shop.test': '<title>Sign in | Shoe Shop</title><h1>Sign in</h1><form action="/login"><input name="email"><input type="password" name="pw"></form>',
  'fake-bank.test': `<title>Chase Online - Sign in</title><h1>Sign in to Chase Online</h1>
    <p>Unusual sign-in activity. Verify your account within 24 hours or it will be restricted.</p>
    <form action="http://collector.test/steal"><input name="user"><input type="password" name="pw"><input name="ssn" placeholder="SSN"></form>`,
  'alert-center.test': `<title>Windows Security Alert</title><h1>Your computer is infected!</h1>
    <p>Microsoft Windows Security Alert. 5 viruses detected. Do not close this window or restart your computer.
    Call Microsoft Support now: 1-888-555-0142 (toll free). Your personal information is at risk.</p>`,
  'badsite.test': '<title>Free prizes</title><h1>Totally fine page</h1>',
  'paypal.com.verify-account.test': '<title>Hello</title><h1>You reached the impostor page</h1>',
  'paypal.com.secure-check.test': '<title>Hello</title><h1>Second impostor</h1>',
};

(async () => {
  const hits = [];
  const server = http.createServer((req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    hits.push(host);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end('<!doctype html><meta charset="utf-8">' + (PAGES[host] || '<h1>unknown</h1>'));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  // Mock lookup proxy that "lists" badsite.test/malware
  const listed = await T.sha256Hex('badsite.test/malware');
  const lookups = [];
  const proxy = http.createServer((req, res) => {
    const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'POST' };
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const prefixes = JSON.parse(body).prefixes;
      lookups.push(body);
      const matches = prefixes.includes(listed.slice(0, 8)) ? [{ hash: listed, threatTypes: ['SOCIAL_ENGINEERING'] }] : [];
      res.writeHead(200, Object.assign({ 'Content-Type': 'application/json' }, cors));
      res.end(JSON.stringify({ matches, cacheSeconds: 60 }));
    });
  });
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const proxyPort = proxy.address().port;

  const userDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ss-e2e-'));
  const ctx = await chromium.launchPersistentContext(userDir, {
    headless: false,
    args: ['--headless=new', `--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--no-sandbox',
      '--host-resolver-rules=MAP *.test 127.0.0.1', '--no-first-run'],
    viewport: { width: 1000, height: 800 },
  });
  let [sw] = ctx.serviceWorkers();
  if (!sw) sw = await ctx.waitForEvent('serviceworker');
  ctx.setDefaultTimeout(10000);
  ctx.setDefaultNavigationTimeout(10000);
  const extId = new URL(sw.url()).host;
  // Close the welcome/options tab opened on install.
  await new Promise((r) => setTimeout(r, 500));
  for (const p of ctx.pages()) if (p.url().includes('options.html')) await p.close();
  const U = (host, p = '/') => `http://${host}:${port}${p}`;
  const newPage = async () => ctx.newPage();

  console.log('ScamShield e2e (extension id ' + extId + ')');

  await step('ordinary page loads untouched, no warning, no overlay', async () => {
    const p = await newPage();
    await p.goto(U('www.example.test'));
    await p.waitForTimeout(2500);
    assert.match(await p.textContent('h1'), /Welcome to Example/);
    assert.equal(await p.locator('#scamshield-warning-host').count(), 0);
    await p.close();
  });

  await step('ordinary login form on an unrelated shop is left alone', async () => {
    const p = await newPage();
    await p.goto(U('shop.test'));
    await p.waitForTimeout(2500);
    assert.equal(await p.locator('#scamshield-warning-host').count(), 0);
    await p.close();
  });

  await step('impersonating address is blocked before loading, with Go Back / Why? / Continue Anyway', async () => {
    const p = await newPage();
    await p.goto(U('www.example.test')); // history entry to go back to
    await p.goto(U('paypal.com.verify-account.test')).catch(() => {});
    await waitWarning(p);
    assert.match(await p.textContent('#title'), /Stop/);
    assert.match(await p.textContent('#summary'), /PayPal/);
    assert.equal(await p.isVisible('#back'), true);
    assert.equal(await p.isVisible('#why'), true);
    assert.equal(await p.isVisible('#continue'), true);
    assert.equal(await p.isVisible('#why-panel'), false);
    await p.click('#why');
    assert.equal(await p.isVisible('#why-panel'), true);
    assert.equal(await p.getAttribute('#why', 'aria-expanded'), 'true');
    assert.match(await p.textContent('#why-panel'), /verify-account\.test/);
    // accessibility basics: focus lands on the heading, buttons are large
    const box = await p.locator('#back').boundingBox();
    assert.ok(box.height >= 56, 'Go Back is a large target');
    // Continue needs two deliberate clicks
    await p.click('#continue');
    assert.match(await p.textContent('#continue'), /Yes, I understand/);
    assert.match(p.url(), /warning\.html/);
    await p.click('#continue');
    await waitUrl(p, /verify-account\.test/);
    assert.match(await p.textContent('h1'), /impostor/);
    await p.close();
  });

  await step('Go Back returns to the previous page', async () => {
    const p = await newPage();
    await p.goto(U('www.example.test'));
    await p.goto(U('paypal.com.secure-check.test')).catch(() => {});
    await waitWarning(p);
    await p.click('#back');
    await waitUrl(p, /www\.example\.test/);
    await p.close();
  });

  const overlayChecks = async (p) => {
    await p.locator('#scamshield-warning-host').waitFor({ state: 'attached', timeout: 8000 });
    // The warning covers the whole viewport and keyboard focus starts inside it (on "Go Back").
    const covered = await p.evaluate(() => {
      const el = document.elementFromPoint(innerWidth / 2, innerHeight / 2);
      return { top: el && el.id, active: document.activeElement && document.activeElement.id };
    });
    assert.equal(covered.top, 'scamshield-warning-host');
    assert.equal(covered.active, 'scamshield-warning-host');
  };

  await step('fake bank login page gets a full-page warning; keyboard: Why? then two-step Continue Anyway', async () => {
    const p = await newPage();
    await p.goto(U('fake-bank.test'));
    await overlayChecks(p);
    await p.keyboard.press('Tab'); // Why?
    await p.keyboard.press('Enter');
    await p.keyboard.press('Tab'); // Continue Anyway
    await p.keyboard.press('Enter'); // first press only arms it
    await p.waitForTimeout(300);
    assert.equal(await p.locator('#scamshield-warning-host').count(), 1, 'one press must not dismiss the warning');
    await p.keyboard.press('Enter');
    await p.waitForFunction(() => !document.getElementById('scamshield-warning-host'));
    assert.match(await p.textContent('h1'), /Chase/);
    await p.close();
  });

  await step('fake virus / tech-support alert gets a full-page warning', async () => {
    const p = await newPage();
    await p.goto(U('alert-center.test'));
    await overlayChecks(p);
    await p.close();
  });

  // ---- threat database (mock proxy) ----
  const opts = await ctx.newPage();
  await opts.goto(`chrome-extension://${extId}/options.html`);
  await step('settings page saves the lookup-service address and rejects bad ones', async () => {
    await opts.fill('#proxy', 'http://remote.example.com');
    await opts.click('#save');
    assert.match(await opts.textContent('#saved'), /must start with https/);
    await opts.fill('#proxy', `http://127.0.0.1:${proxyPort}`);
    await opts.check('#db-enabled');
    await opts.click('#save');
    assert.equal((await opts.textContent('#saved')).trim(), 'Saved.');
  });

  await step('page listed in the threat database is blocked; no Continue button by default', async () => {
    const p = await newPage();
    await p.goto(U('badsite.test', '/malware')).catch(() => {});
    await waitWarning(p);
    assert.match(await p.textContent('#title'), /dangerous/i);
    assert.match(await p.textContent('#summary'), /scam|phishing/i);
    assert.equal(await p.isVisible('#continue'), false);
    await p.close();
  });

  await step('unlisted page still loads; lookups only ever sent 8-character hash prefixes', async () => {
    const p = await newPage();
    await p.goto(U('www.example.test', '/secret/path?token=abc'));
    await p.waitForTimeout(1000);
    assert.match(await p.textContent('h1'), /Welcome/);
    assert.ok(lookups.length > 0);
    for (const body of lookups) {
      assert.ok(JSON.parse(body).prefixes.every((x) => /^[0-9a-f]{8}$/.test(x)));
      assert.ok(!/example|secret|token|badsite/.test(body), 'no URL text in lookups');
    }
    await p.close();
  });

  // ---- pasted message analyzer ----
  const pop = await ctx.newPage();
  await pop.goto(`chrome-extension://${extId}/popup.html`);
  await step('popup: scam message is flagged, links are not opened', async () => {
    const before = hits.length;
    await pop.fill('#msg', 'Chase Alert: your account is locked. Verify your account within 24 hours: http://chase-secure-login.test/verify');
    await pop.click('#analyze');
    await pop.locator('#msg-result h2').first().waitFor();
    assert.match(await pop.textContent('#msg-result'), /looks like a scam/i);
    assert.equal(hits.length, before, 'the link was never requested');
    assert.ok(!hits.includes('chrome-secure-login.test'));
  });

  await step('popup: ordinary message says no warning signs found, without calling it safe', async () => {
    await pop.fill('#msg', 'Hi Grandma, dinner is at 6 on Sunday. Love you!');
    await pop.click('#analyze');
    await pop.waitForFunction(() => /No warning signs found/.test(document.getElementById('msg-result').textContent));
    const t = await pop.textContent('#msg-result');
    assert.match(t, /does not mean it is safe/i);
    assert.ok(!/\bis safe\b|\bsafe to\b|\b100% safe\b/i.test(t.replace(/does not mean it is safe/i, '')));
  });

  await step('popup: empty input asks for a message', async () => {
    await pop.fill('#msg', '');
    await pop.click('#analyze');
    assert.match(await pop.textContent('#msg-result'), /paste a message/i);
  });

  await step('popup: keyboard only – Tab reaches the textarea and button; labels exist', async () => {
    assert.equal(await pop.locator('label[for="msg"]').count(), 1);
    await pop.focus('#msg');
    await pop.keyboard.press('Tab');
    assert.equal(await pop.evaluate(() => document.activeElement.id), 'analyze');
  });

  await ctx.close();
  server.close(); proxy.close();
  const failed = results.filter((r) => !r[0]).length;
  console.log(`\n${results.length - failed}/${results.length} e2e checks passed`);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });

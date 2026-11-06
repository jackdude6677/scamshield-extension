const test = require('node:test');
const assert = require('node:assert/strict');
const U = require('../../extension/src/urlcheck.js');
const D = require('../../extension/src/domain.js');
const legit = require('../fixtures/legit-urls.json');

const level = (u) => U.analyzeUrl(u).level;
const codes = (u) => U.analyzeUrl(u).reasons.map((r) => r.code);

test('legitimate sites never produce a warning or caution', () => {
  const bad = legit.filter((u) => level(u) !== 'none').map((u) => `${u} -> ${level(u)} ${codes(u)}`);
  assert.deepEqual(bad, []);
});

test('brand domain written in front of another site is a warning', () => {
  assert.equal(level('https://paypal.com.verify-account.net/login'), 'warning');
  assert.ok(codes('https://paypal.com.verify-account.net/login').includes('BRAND_DOMAIN_IN_SUBDOMAIN'));
  assert.equal(level('https://www.chase.com.secure-login.info/'), 'warning');
});

test('look-alike spellings of brands warn', () => {
  for (const u of ['https://paypa1.com/', 'https://arnazon.com/', 'https://wellsfarg0.com/', 'https://rnicrosoft.com/', 'https://faceb00k.com/login', 'https://bankofamerlca.com/']) {
    assert.equal(level(u), 'warning', u);
  }
});

test('brand name plus login words on a foreign domain warns', () => {
  for (const u of ['https://chase-secure-login.com/', 'https://paypal-account-verify.net/', 'https://secure-wellsfargo-signin.com/', 'https://netflix-billing-update.xyz/', 'https://appleid-support.top/', 'https://amazonsecurity.com/']) {
    assert.equal(level(u), 'warning', u);
  }
});

test('brand words alone, without login-style words, do not warn', () => {
  for (const u of ['https://apple-orchard.com/', 'https://chase-the-ace.com/', 'https://pineapple.com/', 'https://citizensbank.com/', 'https://purchase.com/', 'https://googlefit-stories.org/']) {
    assert.notEqual(level(u), 'warning', u);
  }
});

test('shared hosting subdomains are not judged by their subdomain', () => {
  assert.equal(level('https://paypal.github.io/'), 'none');
  assert.equal(level('https://chase.blogspot.com/'), 'none');
});

test('a one-letter typo is only a caution, never a full warning', () => {
  assert.equal(level('https://paypall.com/'), 'caution');
  assert.equal(level('https://netflis.com/'), 'caution');
});

test('"@" trick hides the real host', () => {
  const r = U.analyzeUrl('https://www.chase.com@evil-site.example/login');
  assert.equal(r.level, 'warning');
  assert.equal(r.hostname, 'evil-site.example');
});

test('mixed-script (homograph) hostnames warn', () => {
  assert.equal(level('https://аpple.com/'), 'warning'); // Cyrillic "а"
  assert.equal(level('https://xn--pple-43d.com/'), 'warning');
});

test('plain internationalised domains are not flagged', () => {
  assert.equal(level('https://münchen.de/'), 'none');
  assert.equal(level('https://例え.jp/'), 'none');
});

test('IP address hosts are a caution; private/local ones are ignored', () => {
  assert.equal(level('http://203.0.113.9/login'), 'caution');
  assert.equal(level('http://192.168.0.1/'), 'none');
  assert.equal(level('http://localhost:8080/'), 'none');
});

test('boosters alone never create a warning', () => {
  assert.equal(level('http://some-random-shop.xyz/'), 'none');
  assert.equal(level('https://a-b-c-d-e.top/'), 'none');
});

test('non-web URLs and garbage are ignored without throwing', () => {
  for (const u of ['chrome://settings', 'about:blank', 'file:///etc/hosts', 'not a url', '']) {
    assert.equal(level(u), 'none');
  }
});

test('reasons are written in plain language and name the real site', () => {
  const r = U.analyzeUrl('https://paypal.com.verify-account.net/');
  assert.match(r.reasons[0].detail, /verify-account\.net/);
  assert.match(r.reasons[0].title, /PayPal/);
});

test('domain helpers', () => {
  assert.equal(D.registrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(D.registrableDomain('a.b.example.com'), 'example.com');
  assert.equal(D.toUnicodeHost('xn--mnchen-3ya.de'), 'münchen.de');
  assert.equal(D.skeleton('paypa1'), D.skeleton('paypal'));
  assert.equal(D.editDistance('paypal', 'paypall', 1), 1);
});

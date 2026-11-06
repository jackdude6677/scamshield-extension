const test = require('node:test');
const assert = require('node:assert/strict');
const M = require('../../extension/src/messagecheck.js');

const lvl = (t) => M.analyzeMessage(t).level;
const codes = (t) => M.analyzeMessage(t).reasons.map((r) => r.code);

const SCAMS = {
  giftcards: 'This is Agent Davis from the IRS. You owe back taxes and a warrant will be issued. Buy Google Play gift cards and read me the numbers.',
  grandkid: "Grandma it's me, I'm in jail after an accident and need bail money. Please don't tell mom and dad. Send it by Western Union.",
  bank: 'Chase Alert: Unusual activity detected, your account is locked. Verify your account details within 24 hours: https://chase-secure-login.com/verify',
  package: 'USPS: Your package is on hold. Pay a $1.99 redelivery fee at usps-redelivery.top/pay',
  tech: 'Microsoft Alert: Your computer is infected with a virus. Call 1-888-555-0142 now. Install AnyDesk so our technician can fix it.',
  code: 'We sent a verification code to your phone. Please read the code back to me to confirm your identity.',
  prize: 'Congratulations! You have won the lottery. Claim your prize now, you must act immediately.',
};
for (const [name, text] of Object.entries(SCAMS)) {
  test(`scam sample "${name}" is flagged as a warning`, () => assert.equal(lvl(text), 'warning', JSON.stringify(codes(text))));
}

const FINE = {
  family: 'Hi Grandma! Dinner at 6 on Sunday. Mom is bringing the pie. Love you.',
  appointment: 'Reminder: you have an appointment with Dr. Lee tomorrow at 3pm. Reply C to confirm.',
  shipping: 'Your order #1234 has shipped and will arrive Thursday. Track it in the Amazon app.',
  news: 'Check out this article: https://www.bbc.com/news/world-12345',
  bank_real: 'Your Chase statement is ready. Sign in at chase.com to view it.',
  receipt: 'Thanks for your purchase! Your receipt total was $24.50.',
  urgent_only: 'Please call me back as soon as you can, it is urgent, about the car.',
};
for (const [name, text] of Object.entries(FINE)) {
  test(`ordinary message "${name}" does not warn`, () => assert.equal(lvl(text), 'none', JSON.stringify(codes(text))));
}

test('links are extracted, not opened; bare domains, defanged links and emails are handled', () => {
  const links = M.extractLinks('See hxxps://evil[.]example/login, www.test-site.com/a and bob@mail.example.com. Also http://1.2.3.4/x.');
  const urls = links.map((l) => l.url);
  assert.ok(urls.includes('https://evil.example/login'));
  assert.ok(urls.includes('https://www.test-site.com/a'));
  assert.ok(urls.includes('http://1.2.3.4/x'));
  assert.ok(!urls.some((u) => u.includes('mail.example.com')));
});

test('a pasted look-alike link alone warns', () => {
  const r = M.analyzeMessage('https://paypal.com.account-verify.info/signin');
  assert.equal(r.level, 'warning');
  assert.equal(r.links[0].level, 'warning');
});

test('a lone shortened link is flagged for caution but not a full warning', () => {
  const r = M.analyzeMessage('Look at this https://bit.ly/3xyz');
  assert.equal(r.links[0].reasons[0].code, 'SHORT_LINK');
  assert.notEqual(r.level, 'warning');
});

test('empty input is handled; analysis never performs network requests', async () => {
  assert.equal(M.analyzeMessage('   ').empty, true);
  const realFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('network used'); };
  try { M.analyzeMessage(SCAMS.bank); } finally { globalThis.fetch = realFetch; }
});

test('advice never says a message is safe', () => {
  const r = M.analyzeMessage(FINE.family);
  assert.equal(r.advice.length, 0);
  assert.ok(!JSON.stringify(r).match(/\bsafe\b/i));
});

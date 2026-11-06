const test = require('node:test');
const assert = require('node:assert/strict');
const P = require('../../extension/src/pagecheck.js');

const page = (o) => P.analyzePage(Object.assign({ title: '', headings: [], text: '', hasPasswordField: false, formActions: [], inputHints: [] }, o));
const codes = (r) => r.reasons.map((x) => x.code);

// ---------- fake bank / account login ----------
test('fake bank login: brand in title + password field on a foreign domain warns', () => {
  const r = page({
    url: 'https://secure-chase-verify.com/login', title: 'Chase Online - Sign in', headings: ['Sign in to Chase Online'],
    text: 'Chase Online Banking. Sign in. Verify your account within 24 hours or it will be restricted.',
    hasPasswordField: true, formActions: ['https://collector.example/post.php'], inputHints: ['username', 'password'],
  });
  assert.equal(r.level, 'warning');
  assert.ok(codes(r).includes('FAKE_LOGIN_PAGE'));
  assert.match(r.reasons.find((x) => x.code === 'FAKE_LOGIN_PAGE').title, /Chase/);
});

test('fake bank login on an innocent-looking domain still warns when several signs agree', () => {
  const r = page({
    url: 'https://my-account-portal.xyz/', title: 'Wells Fargo Sign On', headings: ['Wells Fargo'],
    text: 'Sign on to your account. Unusual sign-in activity. Confirm your identity.', hasPasswordField: true,
    formActions: ['https://other-host.example/steal'], inputHints: ['ssn', 'password'],
  });
  assert.equal(r.level, 'warning');
});

test('the real bank login page does not warn', () => {
  const r = page({
    url: 'https://secure.chase.com/web/auth/dashboard', title: 'Chase Online - Sign in', headings: ['Sign in'],
    text: 'Sign in to Chase Online. Verify your account details.', hasPasswordField: true, inputHints: ['userId', 'password'],
  });
  assert.equal(r.level, 'none');
});

test('an unrelated site with a login form does not warn', () => {
  for (const [url, title] of [['https://www.shoeshop-example.com/login', 'Sign in | Shoe Shop'], ['https://budget-helper.example/login', 'Budget Helper - Log in'], ['https://forum.example.org/login', 'Community forum login']]) {
    const r = page({ url, title, headings: [title], text: 'Log in to your account. Forgot your password?', hasPasswordField: true, inputHints: ['email', 'password'] });
    assert.equal(r.level, 'none', url);
  }
});

test('a third-party app that merely mentions a bank does not warn on a single weak signal', () => {
  const r = page({
    url: 'https://budget-helper.example/connect', title: 'Connect your accounts', headings: ['Connect Chase to Budget Helper'],
    text: 'Sign in to Budget Helper to link Chase.', hasPasswordField: true, inputHints: ['email', 'password'],
  });
  assert.notEqual(r.level, 'warning');
});

test('a news article about a bank, with no password field, does not warn', () => {
  const r = page({ url: 'https://news.example.com/chase', title: 'Chase announces new branches', headings: ['Chase announces new branches'], text: 'Sign in to read more. Verify your account to comment.', hasPasswordField: false });
  assert.equal(r.level, 'none');
});

test('another brand\'s genuine site is never called a fake bank page', () => {
  const r = page({ url: 'https://www.paypal.com/signin', title: 'PayPal: Log in', headings: ['Pay with Chase or PayPal'], text: 'Log in. Chase cards accepted.', hasPasswordField: true });
  assert.equal(r.level, 'none');
});

// ---------- fake virus / tech support ----------
const SCAM_TEXT = 'WARNING! Your computer has been infected with 5 viruses. Microsoft Windows Security Alert. Do not close or restart this computer. Call Microsoft Support now: 1-888-555-0142 (toll free). Your personal information is at risk.';

test('fake tech-support alert with phone number and pressure warns', () => {
  const r = page({ url: 'https://win-secure-alert.example.top/', title: 'Windows Security Alert', headings: ['Your computer is infected'], text: SCAM_TEXT, phoneNumbers: ['1-888-555-0142'] });
  assert.equal(r.level, 'warning');
  assert.ok(codes(r).includes('FAKE_VIRUS_ALERT'));
});

test('tech-support warning also fires with only a phone number in the text', () => {
  const r = page({ url: 'https://random-offers.example/x', title: 'Alert', text: 'Virus detected! Your computer is infected. Call 1-800-555-0100 immediately.' });
  assert.equal(r.level, 'warning');
});

test('a false alarm alone (no contact route, no pressure) does not warn', () => {
  const r = page({ url: 'https://blog.example.net/post', title: 'My PC story', text: 'My computer was infected last year and it was awful.' });
  assert.equal(r.level, 'none');
});

test('a phone number alone does not warn', () => {
  const r = page({ url: 'https://plumber.example.com/', title: 'Joe the Plumber', text: 'Call us now at 1-800-555-0199 for fast service. Toll free.' });
  assert.equal(r.level, 'none');
});

test('scam-awareness and security-vendor pages are not flagged', () => {
  const awareness = 'Scammers show pop-ups saying "Your computer is infected. Do not close this window. Call Microsoft Support now 1-888-555-0142". This is a tech support scam. How to avoid it.';
  assert.equal(page({ url: 'https://consumer.ftc.gov/articles/how-avoid-tech-support-scam', title: 'How To Avoid a Tech Support Scam', text: awareness }).level, 'none');
  assert.equal(page({ url: 'https://some-news-site.example/tech-support-scams', title: 'Beware tech support scams', text: awareness }).level, 'none');
  assert.equal(page({ url: 'https://www.mcafee.com/blogs/', title: 'Virus detected? Do not panic', text: 'Virus detected on your computer? Call support now 1-800-555-0111. Do not ignore.' }).level, 'none');
});

test('official Microsoft support is not flagged', () => {
  const r = page({ url: 'https://support.microsoft.com/en-us/windows', title: 'Windows Support', text: 'Windows Security alert: virus detected. Call Microsoft Support now 1-800-642-7676 immediately.' });
  assert.equal(r.level, 'none');
});

test('local pages and non-web pages are ignored', () => {
  assert.equal(page({ url: 'http://localhost:3000/', title: 'Windows Security Alert', text: SCAM_TEXT }).level, 'none');
  assert.equal(page({ url: 'chrome://newtab', title: 'x', text: SCAM_TEXT }).level, 'none');
});

test('a clean page reports "none" and carries no safety claim', () => {
  const r = page({ url: 'https://www.example.com/', title: 'Example', text: 'Hello' });
  assert.equal(r.level, 'none');
  assert.equal(r.reasons.length, 0);
  assert.equal('safe' in r, false);
});

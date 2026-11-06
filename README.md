# ScamShield

A free Chrome extension (Manifest V3) that helps protect people, especially older adults, from online scams.
No accounts, no ads, no tracking, no paid services.

> **ScamShield can only warn, never certify.** "No warning signs found" does **not** mean a site is safe, and the extension never says it is.

## What it does

| Protection | How it works |
|---|---|
| **Known dangerous sites** | Checks each page you open against Google Safe Browsing through a small proxy you run. Only 4-byte hash prefixes leave your computer, never URLs. Optional; off until you add a proxy. |
| **Look-alike / impersonating addresses** | Conservative rules: `paypal.com.verify-account.net`, `paypa1.com`, `chase-secure-login.com`, `https://chase.com@evil.example`, mixed-alphabet (homograph) names. |
| **Fake bank / account login pages** | Content script: page claims to be a bank/payment brand, asks for a password, and the domain isn't the brand's. Extra signals (form posts elsewhere, no HTTPS, "verify within 24h", SSN/card fields) raise confidence. |
| **Fake virus / tech-support alerts** | Content script: a false infection alarm **and** a phone number / "call support" **and** pressure ("do not close"). Security vendors, government and scam-awareness pages are exempt. |
| **Pasted message checker** | Popup → paste a text/email/link → gift-card, wire/crypto, secrecy, "grandchild in jail", fake delivery fee, one-time-code, remote-access and similar patterns, plus link checks. Links are parsed as text and **never opened**. |

Warnings are large and high-contrast, explain the *specific* risk, and offer **Go Back**, **Why?**, and (optionally) **Continue Anyway**, which needs a second confirming click, and is hidden for database-confirmed threats unless you change it in Settings.

## Install (Chrome, local)

1. `npm run package` (or use `extension/` directly). This produces `dist/scamshield-0.1.0.zip`.
2. Unzip it somewhere permanent (or just use the `extension/` folder).
3. Open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, choose the folder.
4. Pin ScamShield from the puzzle-piece menu so the shield is always visible.

Chrome will say the extension can "read and change data on websites". That is needed to look for fake login and virus-alert pages. Page text is analysed locally and is never sent anywhere.

## Permissions (minimal)

| Permission | Why |
|---|---|
| `storage` | Your settings, and a 30-minute "Continue Anyway" memory (session only). |
| `webNavigation` | See the address of a page about to load so a dangerous one can be stopped. |
| `activeTab` | Popup shows the verdict for the tab you're looking at. |
| content script on `http(s)` pages | Local, in-page detection of fake login / fake virus-alert pages. |

No `tabs`, `history`, `cookies`, `webRequest`, or host permissions. `tests/unit/manifest.test.js` enforces this.

## Threat database (optional, no keys in the extension)

```
Chrome extension ──(8-hex-char SHA-256 prefixes)──▶ your Cloudflare Worker ──(API key)──▶ Safe Browsing
                 ◀──(matching full hashes)────────                            ◀────────
 compares full hashes locally
```

See [`proxy/README.md`](proxy/README.md). Deploy the Worker (free tier), add the key as a Worker secret, restrict `ALLOWED_ORIGINS` to your extension ID, then paste the Worker URL in ScamShield → Settings.
A failed or missing lookup never blocks browsing; it just means that check didn't happen (the popup says so).

## Privacy

* No browsing history is stored. No analytics. Settings live in `chrome.storage.local` only.
* Heuristic checks run entirely on-device.
* With the database on, only 4-byte hash prefixes are sent, `credentials: omit`, `no-referrer`, to the proxy **you** configure.
* Pasted messages are analysed on-device; links inside them are never fetched.

## Development

```
npm test          # unit tests (node:test, no dependencies)
npm run test:e2e  # loads the extension in Chromium via Playwright, uses local fake scam sites
npm run package   # dist/scamshield-<version>.zip
npm run icons     # regenerate icons
```

Layout: `extension/` (the shipped code), `proxy/` (Cloudflare Worker), `tests/unit`, `tests/e2e`, `tests/fixtures/legit-urls.json` (≈110 legitimate URLs that must never warn).

### Reducing false alarms

* A warning requires a **primary** signal (impersonation, fake brand login, scam alert). "Boosters" (odd TLD, many dashes, HTTP) never warn alone.
* One-letter typos of a brand are only a *caution* (shown in the popup), never a full-screen warning.
* Brand owners' own domains, shared-hosting subdomains (`github.io` …), localhost/private IPs, security vendors, and `.gov/.edu` pages are exempt.
* Add a legitimate site that is wrongly flagged to `tests/fixtures/legit-urls.json` first, then fix the rule.

### Known limitations

* The database check runs as the page starts loading, so a listed page can flash briefly before the warning replaces it (MV3 can't pause navigations on an async lookup).
* Rules are English-only and US-centric (brands, phone formats). The brand list in `extension/src/brands.js` is deliberately short; extend it carefully.
* Heuristics will miss some scams and may rarely flag a legitimate page. Treat ScamShield as a safety net, not a guarantee.
* The Safe Browsing v5 endpoint in the Worker should be checked against Google's current documentation when you deploy.

## License

MIT

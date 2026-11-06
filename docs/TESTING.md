# Testing

| Layer | Command | What it proves |
|---|---|---|
| URL / impersonation rules | `npm test` (`urlcheck.test.js`) | Scam-style addresses warn; ~110 legitimate URLs (`tests/fixtures/legit-urls.json`) never warn or caution. |
| Page rules | `pagecheck.test.js` | Fake bank login + fake virus alert warn; real bank pages, shops, news, scam-awareness and vendor pages don't. |
| Threat DB client + proxy | `threatdb.test.js`, `proxy.test.js` | Only 8-hex-char prefixes are sent; full-hash comparison happens locally; key stays in a header on the proxy and never appears in responses; bad origins/inputs rejected. |
| Message checker | `messagecheck.test.js` | Seven scam templates warn, seven ordinary messages don't; links extracted but never fetched. |
| Packaging / privacy | `manifest.test.js` | Minimal permissions, strict CSP, no keys, no analytics, `fetch` only in `threatdb.js`. |
| Real browser | `npm run test:e2e` | Loads the unpacked extension in Chromium; blocks impersonating address; Go Back / Why? / Continue; overlays on fake bank + fake alert; database block via mock proxy; popup message checker. |

The e2e test maps `*.test` hostnames to a local server (`--host-resolver-rules`), so no real scam site is contacted.

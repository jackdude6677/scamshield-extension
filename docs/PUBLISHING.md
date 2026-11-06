# Publishing ScamShield

## Releases on GitHub (free)
```
git tag v0.1.0 && git push origin v0.1.0
```
`.github/workflows/release.yml` runs the tests, builds the zip and attaches it to a GitHub Release.
Direct link for the latest zip: `https://github.com/jackdude6677/scamshield-extension/releases/latest/download/scamshield.zip`

## Chrome Web Store (one-time US$5 developer fee)
Chrome only installs extensions in one click from the Web Store. Steps:
1. Register at https://chrome.google.com/webstore/devconsole (one-time fee).
2. Upload `dist/scamshield-<version>.zip` (`npm run package`).
3. Fill the listing. Use the permission reasons from the README. State clearly: no data collected, no remote code.
4. Privacy practices tab: "does not collect user data"; link a privacy policy (the README's Privacy section works).
5. Submit for review. Bump `version` in `extension/manifest.json` for every update.

Review will ask why a content script runs on all http(s) pages: it is needed for local, in-page detection of fake login and fake virus-alert pages.

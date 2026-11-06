# ScamShield lookup proxy

A ~100-line Cloudflare Worker (free tier) that keeps the Google Safe Browsing API key off the user's machine.

1. Create a free Google Cloud project, enable **Safe Browsing API**, create an API key (restrict it to that API).
   Safe Browsing is free for non-commercial use; check Google's current terms.
2. `cd proxy && npx wrangler deploy`
3. `npx wrangler secret put SAFE_BROWSING_API_KEY`
4. Edit `ALLOWED_ORIGINS` in `wrangler.toml` to `chrome-extension://<your extension id>`.
5. In Cloudflare, add a rate-limiting rule for the Worker route (e.g. 60 requests/min per IP).
6. In ScamShield → Settings, paste the Worker URL (`https://scamshield-lookup.<you>.workers.dev`).

Request: `POST /v1/lookup` with `{"prefixes":["a1b2c3d4"]}` (8-hex-char SHA-256 prefixes, max 30).
The Worker never receives URLs, stores nothing, and answers only the configured extension origin.
Upstream: `GET https://safebrowsing.googleapis.com/v5/hashes:search` – verify against Google's current docs when deploying.

# Notes for Claude sessions working on this repo

## The live site
- GitHub Pages serves **`main`, folder `/` (root)**: https://jackdude6677.github.io/scamshield-extension/
- The landing page is `index.html` at the repo root. The extension download is `downloads/scamshield-<version>.zip`. Rebuild it whenever `extension/` changes.

## "Done" means the owner can see it
- Work in a branch or open PR is **not live**. Say "It's in PR #N, not live yet. Merge it and the site updates about a minute later." Never call it complete before that.
- After a merge, open the live URL with `?nocache=<time>` and confirm the new page is being served, not the README or an old build. Quote the page title or take a screenshot.
- Don't change the Pages source (branch/folder) without telling the owner. Moving it off `/` takes the landing page down.
- If something is left for the owner (merge, reload, install), end with it as one clear step.

## History
JARVIS (the owner's assistant hub) started this repo. Its own build was stopped on 2026-11-07 because this Claude-built version replaced it. Don't copy JARVIS's old `app/` page back in (a white page with "Status / Sample URLs").

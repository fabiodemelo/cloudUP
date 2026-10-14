# CloudUp web page

Copy of https://www.demelos.com/tools/cloudup/ (served from
`public_html/tools/cloudup/` on the demelos server). **The live file is the
source of truth** — the page design is maintained from the Demelos.com site
project (also in github.com/fabiodemelo/demelos-website at
`toolsassets/cloudup/index.html`). This copy is only a snapshot.

## Releasing a new version

Never upload a whole page from here. Fetch the live file and patch only what
the release changes:

1. `sudo -u demel3276 cat /home/demelos.com/public_html/tools/cloudup/index.html`
2. Change in place, and nothing else:
   - the single `CloudUp_X.Y.Z_aarch64.dmg` link (keep exactly one; the top-bar
     "Download" button points to `#download`, not the DMG),
   - the `?v=NNN` on `shots/*.jpg` when screenshots change,
   - `og:image` if the hero screenshot changes.
3. Back up the live file first (`index.html.bak-<version>`), then write the
   patched copy, and refresh this snapshot from the result.

Release files sit next to the page: `CloudUp_<version>_aarch64.dmg`,
`CloudUp_<version>_aarch64.app.tar.gz` and `latest.json` (the in-app updater
feed, made with `scripts/make_appcast.py`). Screenshots are in `shots/`
(copies of `docs/screenshots/`).

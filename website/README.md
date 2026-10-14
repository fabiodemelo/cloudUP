# CloudUp web page

Source of https://www.demelos.com/tools/cloudup/ (served from
`public_html/tools/cloudup/` on the demelos server).

- `index.html` — the page. Screenshots are served from `shots/` (copies of
  `docs/screenshots/` in this repo); the logo is `logo.png`.
- Releases are published next to it: `CloudUp_<version>_aarch64.dmg` (the
  Download button), `CloudUp_<version>_aarch64.app.tar.gz` and `latest.json`
  (the in-app updater feed, made with `scripts/make_appcast.py`).

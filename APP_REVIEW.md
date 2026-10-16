# CloudUp: App Review notes

## Distribution

- **Today:** direct download, Developer ID signed and notarized (`scripts/release.sh`), DMG on
  https://www.demelos.com/tools/cloudup/, in-app updates through the Tauri updater.
- **Planned:** Mac App Store, once the app is complete. See "Mac App Store blockers" below.

## Payment model: B (free, no purchasing)

CloudUp is free. It sells nothing, has no plans, no accounts of its own and no
registration. Users connect storage they already own (S3, WebDAV, FTP, SFTP,
Swift, pCloud, Dropbox, Google Drive, OneDrive, Box). Keep it that way in a
store build: no prices, "upgrade", donate or pricing links. The only web link
is "Powered by demelos LLC" to demelos.com, which must not sell CloudUp.

## Mac App Store blockers (open)

1. Main app is not sandboxed (`src-tauri/entitlements.plist`). A store build
   needs `app-sandbox`, `network.client`, `network.server` (loopback WebDAV
   server for the Finder extension, OAuth callback), `files.user-selected.read-write`,
   `files.downloads.read-write` and the app group.
2. Self-updater (`tauri-plugin-updater`, `check_for_updates`/`install_update`,
   update banner) must be left out of the store build (2.4.5(vii)).
3. Login item uses `tauri-plugin-autostart` (LaunchAgent plist): replace with
   `SMAppService.mainApp` (works in both builds, macOS 13+).
4. Paths built from `$HOME` (`mount/finder.rs`: group container and
   `~/Library/CloudStorage`) must use `containerURLForSecurityApplicationGroupIdentifier`
   and `NSFileProviderManager getUserVisibleURL`; add `container-migration.plist`
   so existing users keep their connections.
5. `open` crate spawns `/usr/bin/open`: use NSWorkspace (tauri-plugin-opener).
   Mega shells out to an external `mega` CLI: keep it out of the store build
   (it is already hidden in the UI because it isn't functional).
6. SFTP private key is a typed file path, which the sandbox can't read: pick it
   with an open panel and keep a security-scoped bookmark.
7. Packaging: Apple Distribution signing, provisioning profiles for the app and
   the Finder extension, `productbuild` pkg signed with the Mac Installer
   Distribution certificate; `build-fileprovider.sh` hard-codes "Developer ID
   Application". Consider a universal (arm64 + x86_64) build.
8. App Store Connect: privacy policy URL (none exists yet), support URL,
   App Privacy "Data Not Collected" (once the updater ping is gone),
   `ITSAppUsesNonExemptEncryption` (TLS, SSH via vendored OpenSSL, HMAC-SHA256:
   likely exempt, confirm in the questionnaire).
9. Review access: reviewers need a working S3 or WebDAV test account in App
   Review Information. Dropbox / Google Drive / OneDrive / Box need the user's
   own OAuth client ID today; ship registered client IDs or hide them in the
   store build. OAuth opens the default browser (a past rejection on this
   account, Docas, guideline 4): consider `ASWebAuthenticationSession`.

Suggested shape: a `tauri.appstore.conf.json` merged with `tauri build --config`
plus a cargo feature that drops the updater, and a `scripts/release-appstore.sh`.

## Review notes draft (for App Store Connect, later)

CloudUp is a free utility that connects to cloud storage the user already has
(S3-compatible, WebDAV, FTP/SFTP, OpenStack Swift, pCloud, Dropbox, Google
Drive, OneDrive, Box), lets them browse, upload and download files, and adds
each connection to Finder's sidebar through a File Provider extension. It has
no accounts, purchases or ads. To mount a connection the app serves it to its
own Finder extension over a WebDAV server bound to 127.0.0.1 (network.server).
Test account: an S3 bucket's access key, secret and endpoint are in App Review
Information.

## Open recommendations (not blockers for direct download)

- Verify pCloud, Dropbox, Google Drive, OneDrive and Box against real accounts
  (only S3 and SFTP have live tests: `tests/cloud.rs`). Add live tests for them.
- Large files are held fully in memory (downloads, uploads, the Finder bridge);
  stream them instead.
- Finder extension: cache the server address instead of probing on every
  request; make folder deletes stop on the first failure and respect
  `baseVersion`.
- OAuth loopback: add a read timeout to the callback socket and answer the
  browser on an error redirect.
- OAuth client secrets are stored in `config.json` (0600) rather than the
  keychain.
- Intel Macs: ship a universal build (needs the `x86_64-apple-darwin` target).
- Accessibility: focus trap inside dialogs.

## Audit log

- 2026-10-15, v1.1.3 → v1.1.4: full audit (static scan, code review of Rust and
  frontend, Mac App Store readiness, live URLs, launch test of the notarized
  1.1.3, UI checks against a mocked backend). Interactive tour of the real app
  not run (screen control declined). Verdict for the Mac App Store: NOT READY
  (blockers above). Fixed in 1.1.4: drive deadlock on Finder side-file
  renames; Google Drive / Box new-file uploads; Dropbox download/upload host
  and overwrite; OneDrive path URLs and folder creation; pCloud rewritten to
  its documented API (it could not log in before); Google/Dropbox refresh
  tokens; S3 listings over 1,000 items and nested folder deletes; keychain
  errors no longer used as passwords; SFTP host-key verification; URLs stripped
  from network errors; FTP command injection and PASV address; downloads
  quarantined, never overwrite, and can't escape their folder; atomic 0600
  config writes; Upload button; Enter on Cancel confirming deletes; stale
  listings after switching connections; edit form wiping saved passwords;
  duplicate connections on double-click; lossy text editing of non-UTF-8 files;
  unsaved-edit prompt; Mega placeholder hidden; keyboard and screen-reader
  access; local network / Downloads usage descriptions.

# CloudUp: App Review notes

## Distribution

- **Today:** direct download, Developer ID signed and notarized (`scripts/release.sh`),
  universal DMG on https://www.demelos.com/tools/cloudup/, in-app updates
  through the Tauri updater.
- **Planned:** Mac App Store (`scripts/release-appstore.sh`), once the owner
  has done the manual steps under "Mac App Store build" below.

## Payment model: B (free, no purchasing)

CloudUp is free. It sells nothing, has no plans, no accounts of its own and no
registration. Users connect storage they already own (S3, WebDAV, FTP, SFTP,
Swift, pCloud, Dropbox, Google Drive, OneDrive, Box). Keep it that way in a
store build: no prices, "upgrade", donate or pricing links. The only web link
is "Powered by demelos LLC" to demelos.com, which must not sell CloudUp.

## Mac App Store build

`sh scripts/release-appstore.sh` builds it: universal, `--no-default-features
--features mas`, merged with `src-tauri/tauri.appstore.conf.json`, signed with
Apple Distribution, packaged with `productbuild`, then validated and uploaded
with `xcrun altool` (same App Store Connect API key as `scripts/release.sh`).
It stops with a message naming whatever is missing (profiles, certificates).
It has not run end to end yet: the profiles and the installer certificate
don't exist.

### Blockers handled in code (1.2)

1. Sandbox: `src-tauri/entitlements.appstore.plist` (app-sandbox,
   network.client, network.server for the 127.0.0.1 WebDAV server and the
   OAuth redirect, files.user-selected.read-write, files.downloads.read-write,
   files.bookmarks.app-scope, the `8V6DT796JV.net.cloudup` app group and the
   application/team identifiers). The extension has
   `fileprovider/entitlements.appstore.plist`. The direct build stays
   unsandboxed (`entitlements.plist`).
2. Self-updater: cargo feature `updater` (default) gates
   `tauri-plugin-updater` and the `check_for_updates`/`install_update`
   commands; `mas` leaves them out, and the store config drops the updater
   plugin config and updater artifacts. The frontend hides the banner when
   `check_for_updates` is missing.
3. Login item: `SMAppService.mainApp` in both builds (`src/macos.rs`).
   A login launch is recognised from the launch Apple event
   (`keyAEPropData` = `keyAELaunchedAsLogInItem`), since SMAppService can't
   pass `--login`. 1.1.x's `~/Library/LaunchAgents/CloudUp.plist` is removed
   and replaced once, at the first start of 1.2.
4. Paths: the group container comes from
   `containerURLForSecurityApplicationGroupIdentifier`, the Location folder
   from `NSFileProviderManager getUserVisibleURLForItemIdentifier`
   (old paths kept as fallbacks). `container-migration.plist` (copied to
   Contents/Resources) moves `~/Library/Application Support/net.cloudup.app`
   (config.json, secrets.json, known_hosts) into the container on the first
   sandboxed launch.
5. No child processes: NSWorkspace replaces the `open` crate (`open_path`,
   OAuth browser launch). `open_path` only opens http(s) links, mounted
   Finder Locations and files in Downloads. MEGA is native Rust now (the
   vendored `mega` crate, no external client), so the `mas` build has it too.
6. SFTP key file: saving a connection with `fields.key` stores a
   security-scoped bookmark in `fields.key_bookmark`; `sftp.rs` opens the key
   through it (falls back to the path). `~` expands to the real home, not the
   container. The SFTP form has a "Choose…" button (open panel), which is
   what grants the sandboxed build access to the key file.
7. Packaging: `build-fileprovider.sh` takes `APPLE_SIGNING_IDENTITY`,
   `FILEPROVIDER_PROFILE` and builds a universal extension; the direct
   release is universal too.
8. `ITSAppUsesNonExemptEncryption` = false in `Info.plist`: CloudUp only uses
   standard encryption (HTTPS/TLS via rustls, SSH via libssh2/OpenSSL,
   HMAC-SHA256 request signing). **Confirm this in App Store Connect's export
   compliance questions** (answer: uses encryption, exempt, standard
   algorithms only).
9. OAuth client secrets are in the keychain (`<id>#client_secret`), migrated
   from config.json on first load.

### Still to do by hand (owner)

1. App Store Connect: create the app record (bundle ID `net.cloudup.desktop`,
   SKU, name "CloudUp", primary category Utilities, price Free).
2. developer.apple.com → Identifiers: App IDs `net.cloudup.desktop` and
   `net.cloudup.desktop.files`, both with the App Groups capability and the
   group `8V6DT796JV.net.cloudup` (team-prefixed, as the code uses).
3. Profiles: two "Mac App Store Connect" distribution profiles, one per App
   ID; pass them as `APPSTORE_APP_PROFILE` / `APPSTORE_EXT_PROFILE`.
4. Certificates: "Apple Distribution" and "Mac Installer Distribution"
   (shown as "3rd Party Mac Developer Installer") in the login keychain.
5. Privacy policy URL: https://www.demelos.com/tools/cloudup/privacy.html
   (drafted in `website/privacy.html`, linked from the app footer; publish it
   first). Support URL: https://www.demelos.com/contact-us/. App Privacy:
   "Data Not Collected" (the store build makes no update check).
6. Review notes with a working test account (an S3 bucket's endpoint, access
   key and secret, or a WebDAV URL/user/password) in App Review Information;
   draft below.
7. OAuth providers: Dropbox / Google Drive / OneDrive / Box need the user's
   own OAuth client ID today. Either register CloudUp's own client IDs (and
   verify each flow), or hide those four in the store build. OAuth opens the
   default browser (a past rejection on this account, Docas, guideline 4):
   consider `ASWebAuthenticationSession`.
8. Export compliance answers (item 8 above).
9. Every upload needs a new build number (bump the version first).

Migration caveats for users moving from the direct build: settings move into
the container (the direct build then starts empty); keychain items were
created by the Developer ID build, so macOS may ask once whether the store
build may read them (or the user re-enters passwords).

## Review notes draft (for App Store Connect, later)

CloudUp is a free utility that connects to cloud storage the user already has
(S3-compatible, WebDAV, FTP/SFTP, OpenStack Swift, pCloud, Dropbox, Google
Drive, OneDrive, Box), lets them browse, upload and download files, and adds
each connection to Finder's sidebar through a File Provider extension. It has
no accounts, purchases or ads. To mount a connection the app serves it to its
own Finder extension over a WebDAV server bound to 127.0.0.1 (network.server).
Test account: an S3 bucket's access key, secret and endpoint are in App Review
Information.

## Open items (need accounts or a real Mac session)

- Run the live tests in `src-tauri/tests/cloud.rs` (variables listed at the
  top) against real S3, Backblaze B2, WebDAV, Swift, FTP, SFTP, pCloud,
  Dropbox, Google Drive, OneDrive and Box accounts, with `CM_TEST_LARGE=1` for
  the 65 MiB round trip (S3 multipart, Box chunked, OneDrive session). So far
  WebDAV and SFTP passed against local servers; the rest only have offline
  tests.
- Mount, edit, rename and delete through Finder on a real connection with the
  1.2 Finder extension (server-address cache, recursive delete, version
  checks), including a large file.
- Login item detection relies on the launch Apple event carrying
  `keyAELaunchedAsLogInItem`; verify on macOS 13, 14 and 15 that a login
  launch stays hidden (if not, the window just shows at login).

## Audit log

- 2026-10-16, 1.2.0 (not yet built for release): streaming transfers for every
  backend (no whole files in memory; temp-file spooling in the Finder bridge),
  S3 multipart uploads over 64 MiB, Box chunked uploads over 50 MB, Swift
  Static Large Objects over 5 GiB, OneDrive/Dropbox/Drive upload sessions,
  FTP/SFTP uploads via a temp name and rename, FTP binary mode, MEGA
  credentials off the command line, gated live tests for every provider;
  Finder extension server-address cache, safe recursive deletes with
  `baseVersion` checks, once-only completion handlers; dialog focus trap,
  arrow-key navigation, SFTP key picker, client secrets loaded from the
  keychain, privacy link and policy page (draft).

- 2026-10-15, 1.2 preparation: SMAppService login item, NSWorkspace instead of
  `/usr/bin/open` and a restricted `open_path`, OAuth loopback timeouts and
  error pages, client secrets in the keychain, config files tightened to 0600,
  Finder paths from macOS APIs, SFTP key bookmarks, `updater`/`mas` cargo
  features, App Store entitlements/config/script, universal direct release.
  `delete_connection` now keeps the connection if its Finder Location can't
  be removed.
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

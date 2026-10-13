# CloudUp

CloudUp is a small desktop app (Tauri 2, Rust backend + plain-JS frontend) that lets you connect to cloud storage and browse, edit, copy, and — with the optional `fuse-mount` feature — mount it as a real local drive.

No FUSE is required to browse: the app itself lists and previews remote files through a native window, so it works on any machine.

## Supported providers

| Provider | Status | Auth |
|---|---|---|
| Amazon S3 (and any S3-compatible endpoint) | ✅ Working | Access key + secret key |
| Backblaze B2 | ✅ Working | App key ID + app key (mapped onto the S3 backend with B2 endpoint/region defaults) |
| WebDAV | ✅ Working | User + password |
| OpenStack Swift | ✅ Working | Auth URL + user + password (v3 token auth) |
| FTP | ✅ Working | Host, user, password (passive mode) |
| pCloud | ✅ Working | User + password |
| Dropbox | ✅ Working | OAuth2 (user-supplied `client_id`) |
| Google Drive | ✅ Working | OAuth2 (user-supplied `client_id`) |
| OneDrive | ✅ Working | OAuth2 (user-supplied `client_id`) |
| Box | ✅ Working | OAuth2 (user-supplied `client_id`) |
| SFTP | ✅ Working | User + password, or a private key (PEM pasted as the secret, or a key file path) — `libssh2`/OpenSSL are built into the app |
| MEGA | ⚠️ Experimental | Email + password, via an external `mega` command-line client (see below) |

Credentials are stored per-connection; OAuth tokens are kept in the OS keychain where available.

### MEGA (experimental)

MEGA encrypts files client-side with a proprietary scheme, so CloudUp does not talk to MEGA directly. Instead it shells out to a command-line client named `mega` that must be on your `PATH`, invoked as:

```sh
mega --username <email> --password <password> --config <dir> ls --long mega://<path>
mega ... get mega://<path> <local-file>
mega ... put mega://<path> <local-file>
mega ... mkdir | rm | rmdir mega://<path>
```

This interface has **not yet been verified** against an existing tool — it does not match MEGA's official MEGAcmd (`mega-ls`, `mega-get`, …) or megatools (`megatools ls`, …) out of the box. Until the backend is adapted to one of them (or you provide a `mega` wrapper script with this interface), MEGA connections will report an error. Every MEGA operation surfaces a clear error message if `mega` is missing.

## Testing against live accounts

`cargo test` runs the unit tests. The live round-trip tests in `src-tauri/tests/cloud.rs` create, read, list and delete a throwaway `cloudup-test-*` folder on a real account; each one skips unless its environment variables are set:

```sh
CM_TEST_SFTP_HOST=… CM_TEST_SFTP_USER=… CM_TEST_SFTP_SECRET=… \
  cargo test --test cloud -- --nocapture
```

Variables: `CM_TEST_S3_ENDPOINT/REGION/KEY/SECRET/BUCKET`, `CM_TEST_SFTP_HOST/PORT/USER/SECRET/ROOT`, `CM_TEST_MEGA_EMAIL/PASSWORD`.

## OAuth setup (Dropbox, Google Drive, OneDrive, Box)

These four providers authenticate with OAuth2 PKCE. You must register your own app with the provider and paste the resulting `client_id` into the connection form:

- **Dropbox** — [Dropbox app console](https://www.dropbox.com/developers/apps): create an *Dropbox API* app and paste its App key (the `client_id`).
- **Google Drive** — [Google Cloud Console](https://console.cloud.google.com/apis/credentials): create an *OAuth client ID* of type *Desktop* and paste the Client ID.
- **OneDrive** — [Azure portal → App registrations](https://portal.azure.com): register a *mobile & desktop* app and paste the Application (client) ID.
- **Box** — [Box developer portal](https://developer.box.com/v3.0/apps): create an app and paste the client ID.

During "Connect", CloudUp opens the provider's consent page in your browser with a loopback redirect (`http://127.0.0.1:<port>`). You do **not** need to run a web server or register a custom redirect — when you approve, the provider hands the code back to the local app, which exchanges it for a token.

## Build & run

Prerequisites: Rust (1.77+), Node.js, and the Tauri CLI via npm.

```sh
npm install
npx tauri dev      # run the app in development
```

For a release build: `npx tauri build`.

### Mounting as a drive (optional)

The `fuse-mount` cargo feature mounts a connection as a real filesystem (macFUSE on macOS, FUSE on Linux, WinFsp on Windows). It is **not** in the default feature set and requires:

- [macFUSE](https://osxfuse.github.io/) installed on macOS
- `pkg-config` on your system

Build with it enabled:

```sh
npx tauri build --features fuse-mount   # or: cargo build --features fuse-mount
```

If macFUSE is not installed at build time, `build.rs` bundles a stub `libfuse.dylib` (in `Contents/Frameworks`) so the app still launches and browses normally; only the **Mount** action then fails, asking for macFUSE. Without `pkg-config`, you can point the build at any `pkg-config` shim via `PKG_CONFIG=…`.

> Note: the mount code targets `fuser` 0.15 and compiles, but has not yet been exercised against a real macFUSE mount; expect rough edges on large directories.

## macOS signing & notarization

- **Signing** is configured: `tauri.conf.json → bundle.macOS.signingIdentity` is `"Developer ID Application"`, so `npx tauri build` signs with the Developer ID certificate in your keychain.
- **Notarization is not set up yet.** Without it, macOS Gatekeeper blocks the app on other Macs. To notarize, set `APPLE_ID`, `APPLE_PASSWORD` (an app-specific password) and `APPLE_TEAM_ID` before `npx tauri build`, or submit the `.dmg` manually with `xcrun notarytool submit … --wait` and then `xcrun stapler staple`.
- Re-sign nested frameworks after bundling if you add native dependencies.

## Repository layout

```
src/           plain-JS frontend (served by scripts/serve.js)
scripts/       dev server
src-tauri/     Rust/Tauri backend
  src/config.rs   connection model + persistence
  src/backend.rs  Backend enum dispatch
  src/s3.rs …     per-provider backends
  src/oauth.rs    shared OAuth2 PKCE + token refresh
  src/mount/      optional FUSE mount (feature `fuse-mount`)
  src/commands.rs Tauri IPC surface
```

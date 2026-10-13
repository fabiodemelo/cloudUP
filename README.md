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
| SFTP | 🔜 Coming soon | Needs `libssh2` + OpenSSL native dependencies |
| MEGA | 🔜 Coming soon | Proprietary client-side crypto |

Credentials are stored per-connection; OAuth tokens are kept in the OS keychain where available.

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

> Note: the FUSE port to `fuser` 0.15 is in progress; expect rough edges on large directories.

## macOS signing & notarization

Placeholders — fill in before shipping a public `.dmg`:

- Set a development/production `APPLE_SIGNING_IDENTITY` (or `CSC_NAME`) for `tauri build`.
- Enable the *Hardened Runtime* + *JIT/Network Client* entitlements (`tauri.conf.json → app.security`).
- Provide an Apple notarization team ID / app-specific password (`APPLE_TEAM_ID`, `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`) for `xcrun notarytool` submission.
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

# CloudUp free license (direct-download build)

CloudUp is free, but the version downloaded from
https://www.demelos.com/tools/cloudup/ needs a free license before it does
anything: an email address, verified with an emailed 6-digit code, gets one
license key from the demelos license server (dmadmin, product `dm-cloudup`).
The same email always gets the same key back.

**The Mac App Store build has no license at all** (cargo feature `mas`, see
APP_REVIEW.md): a free store app may not require registration or unlock
anything with a key.

## Pieces

| Piece | Where |
|---|---|
| `license/start`, `license/finish` | CloudUp API, `server/api/lib/license.php` (same base URL as sync) |
| Codes | table `license_codes` in the `cloudup` database (HMAC only, 30 min, 5 guesses) |
| Licenses | dmadmin: `dmadmin_licenses` (product `dm-cloudup`, `order_ref` `cloudup-free`, 5 activations) |
| Website gate | `website/index.html`: email form, code form, then the key and the DMG link |
| App gate | `src-tauri/src/license.rs` (cargo feature `license`, on by default, off with `mas`) and `src/license.js` |

## API

Base URL: `https://www.demelos.com/tools/cloudup/api/v1/`. JSON in and out;
errors as in [sync-api.md](sync-api.md).

| Method and path | Body | Success |
|---|---|---|
| `POST license/start` | `{email}` | `202 {status: "sent"}`. Emails a 6-digit code (replacing any earlier one). 5 per hour per IP and per email. |
| `POST license/finish` | `{email, code}` | `200 {license_key, email, max_activations}`. Finds the email's active CloudUp license or issues one, and emails the key. |

`license/finish` errors: `401 bad_code` (wrong, expired or used up; 5
guesses per code, 10 tries per 15 minutes per IP), `403 license_blocked` (the
email's license was revoked or suspended; a new one is never issued in its
place), `503 license_unavailable` (dmadmin unreachable; the code is kept, so
the same code works on retry). Test mode works as for the sync API
(`cloudup-test+…@demelos.com` plus `X-CloudUp-Test` returns `test_code`).

The PHP side calls dmadmin's intake API on `127.0.0.1:3015` with the
`dm-cloudup` intake key: `GET license-intake/licenses?customer_email=` then, if
nothing is active, `POST license-intake/orders`. Env file keys:

| Key | Use |
|---|---|
| `DMADMIN_INTAKE_KEY` | Plain intake key for product `dm-cloudup` (dmadmin stores its SHA-256). Required. |
| `DMADMIN_URL` | Optional, default `http://127.0.0.1:3015/admin/api/`. |

## App check

`license.rs` posts to `https://www.demelos.com/admin/api/license/v1/validate`
with the key, product `dm-cloudup`, a random nonce and this Mac's fingerprint
(SHA-256 of `cloudup-license-v1|` and the host UUID, so the hardware id never
leaves the Mac). The label is just `CloudUp <version>`. The answer is a
payload signed with the license server's Ed25519 key, which is embedded in
the app (`PUBLIC_KEY_B64`, key id `dm-4ee864c1de46`). The app accepts it only
if the signature, nonce, key, fingerprint and product all match.

`license.json` (0600, data dir) keeps the key and the last signed "valid"
answer. CloudUp starts without the network until `next_check_before` (15
days) plus `grace_seconds` (5 days); a stale answer is re-checked at start and
every 6 hours. A refused key (revoked, suspended, expired, removed Mac) is
forgotten, every drive is unmounted, and the license screen comes back.

Until licensed, the window shows only the license screen, `mount_connection`
refuses, and `mount_auto` (start-up and Finder Location mounts) does nothing.
Activating runs `mount_auto`.

Debug builds only: `CLOUDUP_LICENSE_URL`, `CLOUDUP_LICENSE_PUBKEY` (raw
32-byte key, base64) and `CLOUDUP_LICENSE_KEY_ID` point the check at a test
server. Release builds ignore them.

## Tests

- `cargo test --lib license`: signature checks (including a real answer from
  the live server), freshness windows, key format.
- `python3 server/tests/license_test.py`: the API against the live server
  (deletes its test licenses from dmadmin at the end), or against a local copy:
  `--base http://127.0.0.1:8099/tools/cloudup/api/v1/ --env <env file> --mock <mock dmadmin URL>`.

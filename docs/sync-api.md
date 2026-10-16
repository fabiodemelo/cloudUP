# CloudUp accounts and sync: API contract (v1)

Optional demelos accounts let a user sign in on several Macs and get the same
connections everywhere. The server stores only what it can't read: every
connection, password, token and secret is encrypted on the Mac before upload.
A forgotten password plus a lost recovery key means the synced data is gone;
that is the price of the server never seeing it.

Base URL: `https://www.demelos.com/tools/cloudup/api/v1/`
JSON in and out (`Content-Type: application/json`), HTTPS only. Authenticated
calls send `Authorization: Bearer <token>`. Errors: HTTP status plus
`{"error": "<code>", "message": "<human text>"}`. Binary values are standard
base64 (with padding).

## Client-side keys

```
prelogin(email)            -> kdf params + salt (16 bytes)
master    = Argon2id(password, salt, m=65536 KiB, t=3, p=1, 32 bytes)
auth_key  = HKDF-SHA256(ikm=master, salt=none, info="cloudup-auth-v1", 32 bytes)   // sent to the server
enc_key   = HKDF-SHA256(ikm=master, salt=none, info="cloudup-enc-v1", 32 bytes)    // never leaves the Mac
vault_key = 32 random bytes, made once at sign-up                                   // encrypts the vault
wrapped_vault_key          = seal(enc_key, vault_key)
recovery_key               = 32 random bytes, shown once as Crockford base32 in groups of 4
recovery_wrapped_vault_key = seal(recovery_key, vault_key)
recovery_auth              = HKDF-SHA256(ikm=recovery_key, info="cloudup-recovery-auth-v1", 32 bytes)
seal(k, m) = nonce(24 random) || XChaCha20-Poly1305(k, nonce, m, aad="cloudup-v1")
```

`kdf` object: `{"alg": "argon2id", "m": 65536, "t": 3, "p": 1}`. The server
echoes whatever the client registered, so parameters can be raised later; it
refuses values below these defaults. Wrapped keys are exactly 72 bytes
(24 nonce + 32 key + 16 tag); salts are 16 bytes; `auth_key` and
`recovery_auth` are 32 bytes. Anything else is `400 invalid_request`.

The server stores `password_hash(auth_key, PASSWORD_ARGON2ID)` and
`password_hash(recovery_auth, PASSWORD_ARGON2ID)`, never the raw values.

## Vault plaintext (inside the encrypted blob)

```json
{
  "schema": 1,
  "updated_at": "2026-10-16T12:00:00Z",
  "connections": [ { ...Connection as in config.json..., "updated_at": "RFC 3339", "deleted": false } ],
  "secrets":       { "<connection id>": "<password or OAuth token JSON>" },
  "field_secrets": { "<connection id>": { "client_secret": "..." } },
  "known_hosts":   "<CloudUp's SFTP known_hosts file contents>"
}
```

Merge rule (client): per connection id the newer `updated_at` wins; a deleted
connection stays as a tombstone (`deleted: true`, no secrets) for 90 days so
other Macs remove it too. `known_hosts` lines are unioned.

## Endpoints

| Method and path | Auth | Body | Success |
|---|---|---|---|
| `POST prelogin` | no | `{email}` | `200 {kdf, salt}`. Emails without a verified account (unknown or not yet verified) get a stable fake salt (HMAC of the email with a server secret) and the default kdf, so the reply never reveals whether an account exists. |
| `POST register` | no | `{email, salt, kdf, auth_key, wrapped_vault_key, recovery_wrapped_vault_key, recovery_auth}` | `202 {"status":"verify"}` and a 6-digit code emailed (valid 30 min). An existing unverified account with the same email is replaced; a verified one is left untouched, answers `202` too (no enumeration) and gets an email saying someone tried to register. The Mac keeps the keys it just made until `verify` succeeds. Unverified sign-ups are purged after 7 days. |
| `POST verify` | no | `{email, code, device_name}` | `200 {token, wrapped_vault_key, vault_version}`; `401 bad_code` (wrong, expired, used up, or no such sign-up) |
| `POST resend` | no | `{email}` | `202 {"status":"sent"}` (sends a new code, replacing the old one, if the account is unverified) |
| `POST login` | no | `{email, auth_key, device_name}` | `200 {token, wrapped_vault_key, vault_version}`; `401 bad_credentials` for a wrong key, an unknown email and an unverified account alike. To finish an interrupted sign-up, `resend` and `verify`, or register again. |
| `POST logout` | yes | – | `204` (revokes this token) |
| `GET account` | yes | – | `200 {email, created_at, vault_version, vault_updated_at}` |
| `GET vault` | yes | – | `200 {version, blob, updated_at}`; `204` when no vault yet (version 0) |
| `PUT vault` | yes | `{base_version, blob}` | `200 {version}`; `409 {"error":"conflict", version, blob, updated_at}` when `base_version` isn't the current version (`blob` and `updated_at` are `null` when there is no vault yet). Blob ≤ 2 MiB of base64 text, else `413 too_large`. |
| `GET devices` | yes | – | `200 [{id, name, created_at, last_seen_at, current}]` |
| `DELETE devices/{id}` | yes | – | `204` (signs that device out); `404 not_found` if it isn't one of yours |
| `POST password` | yes | `{auth_key, new_salt, new_kdf, new_auth_key, new_wrapped_vault_key}` | `204`; every other device is signed out. `401` if `auth_key` is wrong. |
| `POST recover/start` | no | `{email, recovery_auth}` | `200 {recovery_wrapped_vault_key, reset_token}` (token valid 15 min, single use); `401 bad_credentials` otherwise |
| `POST recover/finish` | no | `{reset_token, salt, kdf, auth_key, wrapped_vault_key, device_name}` | `200 {token, vault_version}`; other devices signed out. Vault kept. `401 bad_token` if the token is unknown, used or expired. |
| `POST reset/start` | no | `{email}` | `202 {"status":"sent"}`; emails a code (valid 30 min) if a verified account exists. For users without their recovery key: finishing erases the synced vault. |
| `POST reset/finish` | no | `{email, code, salt, kdf, auth_key, wrapped_vault_key, recovery_wrapped_vault_key, recovery_auth, device_name}` | `200 {token, vault_version: 0}`; vault deleted, all devices signed out. `401 bad_code` like `verify`. |
| `DELETE account` | yes | `{auth_key}` | `204`; user, vault, devices and codes deleted at once. `401 bad_credentials` if `auth_key` is wrong. |

Tokens: 32 random bytes (base64url, 43 characters), stored as SHA-256,
expire after 90 days without use; `last_seen_at` updates at most once an hour.
A missing, unknown or expired token is `401 unauthorized`.

Codes: 6 digits, stored only as an HMAC. One live code per account and
purpose; a new one replaces the old. Each code allows 5 guesses in total, then
it is dead and the user asks for a new one.

Rate limits (sliding window):

| Action | Per IP (every request) | Per email |
|---|---|---|
| prelogin | 10 per 15 min | none |
| login, `POST password`, `DELETE account` | 10 per 15 min (shared) | 10 failures per 15 min |
| verify | 10 per 15 min | 10 failures per 15 min |
| recover/start, recover/finish | 10 per 15 min (shared) | 10 failed starts per 15 min |
| reset/finish | 10 per 15 min | 10 failures per 15 min |
| register, resend, reset/start | 5 per hour each | 5 per hour each (every request) |

IPv6 clients are counted per /64. Over the limit:
`429 {"error":"rate_limited", "message", "retry_after": seconds}` plus a
`Retry-After` header.

Other errors: `400 invalid_request` (bad JSON, missing or malformed field),
`404 not_found`, `405 method_not_allowed`, `413 too_large`,
`500 server_error`.

Emails come from `CloudUp <noreply@demelos.com>`, plain text, and contain only
the code and what it's for. They are sent after the HTTP reply is flushed, so
response times don't show whether an email went out.

Test mode (for `server/tests/api_test.py` only): for addresses matching
`cloudup-test+<a-z0-9>@demelos.com` the server never sends mail, and when the
request also carries `X-CloudUp-Test: <TEST_SECRET from the server env file>`
the `register`, `resend` and `reset/start` replies include `test_code`.
`POST test/reset-limits {emails}` with the same header clears the rate limits
of those test addresses and the caller's IP; without it the path is a 404.

## Changes from the first draft

- `login` no longer answers `403 unverified`, and `prelogin` gives unverified
  accounts the fake salt. Before, anyone could learn whether an email had an
  account: register it with keys of their own, then call `login` (403 meant
  "no account before", 401 meant "account exists") or `prelogin` (their own
  salt back meant "no account before").
- `prelogin` has no per-email limit, and the credential endpoints count only
  failures per email. A per-email limit on every request let anyone lock a
  user out of signing in with ten requests per 15 minutes, while protecting
  nothing: salts are not secret.
- Error codes, exact key sizes, the kdf floor, code attempt limits and the
  `409` shape without a vault are now spelled out.

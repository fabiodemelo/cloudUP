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
echoes whatever the client registered, so parameters can be raised later.

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
| `POST prelogin` | no | `{email}` | `200 {kdf, salt}`. Unknown emails get a stable fake salt (HMAC of the email with a server secret), so the reply never reveals whether an account exists. |
| `POST register` | no | `{email, salt, kdf, auth_key, wrapped_vault_key, recovery_wrapped_vault_key, recovery_auth}` | `202 {"status":"verify"}` and a 6-digit code emailed (valid 30 min). An existing unverified account with the same email is replaced; a verified one answers `202` too (no enumeration) and gets an email saying someone tried to register. |
| `POST verify` | no | `{email, code, device_name}` | `200 {token, wrapped_vault_key, vault_version}` |
| `POST resend` | no | `{email}` | `202` (sends a new code if the account is unverified) |
| `POST login` | no | `{email, auth_key, device_name}` | `200 {token, wrapped_vault_key, vault_version}`; `401 bad_credentials`; `403 unverified` (and a fresh code is emailed) |
| `POST logout` | yes | – | `204` (revokes this token) |
| `GET account` | yes | – | `200 {email, created_at, vault_version, vault_updated_at}` |
| `GET vault` | yes | – | `200 {version, blob, updated_at}`; `204` when no vault yet (version 0) |
| `PUT vault` | yes | `{base_version, blob}` | `200 {version}`; `409 {"error":"conflict", version, blob, updated_at}` when `base_version` isn't the current version. Blob ≤ 2 MiB (base64). |
| `GET devices` | yes | – | `200 [{id, name, created_at, last_seen_at, current}]` |
| `DELETE devices/{id}` | yes | – | `204` (signs that device out) |
| `POST password` | yes | `{auth_key, new_salt, new_kdf, new_auth_key, new_wrapped_vault_key}` | `204`; every other device is signed out. `401` if `auth_key` is wrong. |
| `POST recover/start` | no | `{email, recovery_auth}` | `200 {recovery_wrapped_vault_key, reset_token}` (token valid 15 min); `401` otherwise |
| `POST recover/finish` | no | `{reset_token, salt, kdf, auth_key, wrapped_vault_key, device_name}` | `200 {token, vault_version}`; other devices signed out. Vault kept. |
| `POST reset/start` | no | `{email}` | `202`; emails a code if the account exists. For users without their recovery key: finishing erases the synced vault. |
| `POST reset/finish` | no | `{email, code, salt, kdf, auth_key, wrapped_vault_key, recovery_wrapped_vault_key, recovery_auth, device_name}` | `200 {token, vault_version: 0}`; vault deleted, all devices signed out. |
| `DELETE account` | yes | `{auth_key}` | `204`; user, vault, devices and codes deleted at once. |

Tokens: 32 random bytes (base64url), stored as SHA-256, expire after 90 days
without use; `last_seen_at` updates at most once an hour.

Rate limits (per IP and per email, sliding window): prelogin/login/verify/
recover/reset 10 per 15 minutes, register/resend/reset-start 5 per hour.
Over the limit: `429 {"error":"rate_limited", "retry_after": seconds}`.

Emails come from `CloudUp <noreply@demelos.com>`, plain text, and contain only
the code and what it's for.

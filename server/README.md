# CloudUp sync server

The server side of optional CloudUp accounts: sign-up with an emailed code,
sign-in, devices, password change, recovery and reset, and one end-to-end
encrypted vault per account. The contract is [docs/sync-api.md](../docs/sync-api.md).
The server only ever holds Argon2id hashes and ciphertext; it cannot read a
user's connections.

Live at `https://www.demelos.com/tools/cloudup/api/v1/`.

## Layout

| Path | What it is |
|---|---|
| `api/index.php` | Router, error handling, JSON output. Every request lands here. |
| `api/.htaccess` | Rewrites every path in the folder (including `lib/`) to `index.php`. OpenLiteSpeed only honours rewrite rules in `.htaccess`, so access control is done with rewrites. |
| `api/lib/core.php` | Config, PDO, HTTP and input-validation helpers. |
| `api/lib/security.php` | Rate limits, codes, sessions, test mode, mail. |
| `api/lib/handlers.php` | One function per endpoint. |
| `schema.sql` | MariaDB tables. Idempotent (`CREATE TABLE IF NOT EXISTS`). |
| `deploy.sh` | Creates the database the first time, applies the schema, uploads, lints and swaps the code in. |
| `tests/api_test.py` | End-to-end test against the live API. |

Plain PHP (no framework, no Composer). The demelos.com vhost runs it on
lsphp 8.3 as `demel3276`; the code also runs on 8.4.

## Server pieces

- **Code:** `/home/demelos.com/public_html/tools/cloudup/api/v1/`, owned by
  `demel3276`, files 0644.
- **Database:** MariaDB `cloudup`, user `cloudup@localhost` with SELECT,
  INSERT, UPDATE and DELETE on `cloudup.*` only. Schema changes run as root
  through `deploy.sh`.
- **Env file:** `/home/demelos.com/cloudup-api.env`, owner `demel3276`, mode
  0600, outside the web root. `deploy.sh` writes it once and never prints it.

  | Key | Use |
  |---|---|
  | `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS` | Database login. |
  | `SERVER_SECRET` | HMAC key for fake prelogin salts, code hashes and rate-limit buckets. Rotating it kills live codes and changes the fake salts of unknown emails; nothing else. |
  | `TEST_SECRET` | Enables test mode (below). Empty switches it off. |
  | `LOG_FILE` | Error log. |

- **Error log:** `/home/demelos.com/cloudup-api.log` (0600). Errors only,
  with a request id; no request bodies, keys, tokens, codes or SQL values.
- **Mail:** PHP `mail()` through the local Postfix, which relays via SendGrid.
  From `CloudUp <noreply@demelos.com>`, envelope sender the same, plain text.
  Sent after the HTTP reply is flushed.

## Deploy

```sh
server/deploy.sh
```

Needs the `demelos` ssh alias with passwordless sudo. Safe to run again: the
database, user and env file are only created when the env file is missing;
the schema only adds missing tables; the code is staged in
`/home/demelos.com/.cloudup-api-stage`, linted with lsphp 8.3 and moved into
place with a rename. It ends with a `prelogin` smoke test.

Schema changes beyond new tables need an `ALTER TABLE ... ` that is safe to
rerun (for example `ADD COLUMN IF NOT EXISTS`) appended to `schema.sql`.

## Test

```sh
python3 server/tests/api_test.py
```

Runs the whole contract against the live API with throwaway accounts named
`cloudup-test+<random>@demelos.com` and deletes them at the end, pass or fail.
It reads `TEST_SECRET` from the env file over ssh and keeps it in memory.

Test mode exists only for this script:

- the server never sends mail to `cloudup-test+*@demelos.com`;
- for those addresses, with header `X-CloudUp-Test: <TEST_SECRET>`, the
  `register`, `resend` and `reset/start` replies include `test_code`, because
  the test can't read email and codes are stored only as hashes;
- `POST test/reset-limits {"emails": [...]}` with the same header clears the
  rate-limit buckets of those test addresses and of the caller's IP. Without
  the header, or with any other address, it is a 404 like any unknown path.

No other address can ever get a code in a reply.

## Housekeeping

About one request in fifty deletes expired sessions, codes and reset tokens,
rate-limit rows older than an hour, and sign-ups left unverified for 7 days.
No cron job needed.

## Backup

The vaults are ciphertext, but losing them still loses users' synced
connections. Dump the database with the server's other backups:

```sh
ssh -o RemoteCommand=none demelos \
  'sudo -n mysqldump --single-transaction --routines cloudup | gzip' \
  > cloudup-$(date +%Y%m%d).sql.gz
```

Restore with `gunzip -c file.sql.gz | ssh ... 'sudo -n mysql cloudup'`. Keep
a copy of `/home/demelos.com/cloudup-api.env` somewhere private too: without
`SERVER_SECRET` the data still works, but codes in flight die and unknown
emails get different fake salts.

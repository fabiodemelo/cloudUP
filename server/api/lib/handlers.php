<?php
// CloudUp sync API: endpoint handlers. Each returns [status, body|null].
// See docs/sync-api.md for the contract.
declare(strict_types=1);
defined('CLOUDUP_API') || exit;

function bad_credentials(): never
{
    throw new HttpError(401, 'bad_credentials', 'The email or password is wrong.');
}

function bad_code(): never
{
    throw new HttpError(401, 'bad_code', 'The code is wrong or has expired. Ask for a new one.');
}

function hash_key(string $b64): string
{
    return password_hash($b64, PASSWORD_ARGON2ID, ARGON_OPTS);
}

// ------------------------------------------------------------ sign-up and sign-in

function h_prelogin(): array
{
    $email = v_email(field(body(), 'email'));
    rl_ip('prelogin');
    $u = q('SELECT salt, kdf FROM users WHERE email = ? AND verified_at IS NOT NULL', [$email])->fetch();
    if ($u) {
        return [200, ['kdf' => json_decode($u['kdf'], true), 'salt' => base64_encode($u['salt'])]];
    }
    return [200, ['kdf' => DEFAULT_KDF, 'salt' => base64_encode(fake_salt($email))]];
}

function h_register(): array
{
    $b = body();
    $email = v_email(field($b, 'email'));
    $salt = v_b64(field($b, 'salt'), 'salt', 16, 16);
    $kdf = v_kdf(field($b, 'kdf'));
    $authKey = v_key(field($b, 'auth_key'), 'auth_key');
    $wrapped = v_wrapped(field($b, 'wrapped_vault_key'), 'wrapped_vault_key');
    $recWrapped = v_wrapped(field($b, 'recovery_wrapped_vault_key'), 'recovery_wrapped_vault_key');
    $recAuth = v_key(field($b, 'recovery_auth'), 'recovery_auth');

    rl_check('register', 'ip', ip_key());
    rl_check('register', 'email', $email);
    rl_hit('register', 'ip', ip_key());
    rl_hit('register', 'email', $email);

    // Hash before looking the email up, so both paths cost the same.
    $authHash = hash_key($authKey);
    $recHash = hash_key($recAuth);

    $code = tx(function () use ($email, $salt, $kdf, $authHash, $wrapped, $recWrapped, $recHash): ?string {
        $u = q('SELECT id, verified_at FROM users WHERE email = ? FOR UPDATE', [$email])->fetch();
        if ($u && $u['verified_at'] !== null) {
            return null; // existing account: left untouched
        }
        $fields = [new Bin($salt), json_encode($kdf), $authHash, new Bin($wrapped), new Bin($recWrapped), $recHash, dt()];
        if ($u) {
            $uid = (int) $u['id'];
            q('UPDATE users SET salt = ?, kdf = ?, auth_hash = ?, wrapped_vault_key = ?,
                      recovery_wrapped_vault_key = ?, recovery_hash = ?, created_at = ?
                WHERE id = ?', [...$fields, $uid]);
            q('DELETE FROM sessions WHERE user_id = ?', [$uid]);
            q('DELETE FROM vaults WHERE user_id = ?', [$uid]);
            q('DELETE FROM reset_tokens WHERE user_id = ?', [$uid]);
            q('DELETE FROM codes WHERE user_id = ?', [$uid]);
        } else {
            q('INSERT INTO users (salt, kdf, auth_hash, wrapped_vault_key, recovery_wrapped_vault_key,
                                  recovery_hash, created_at, email)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [...$fields, $email]);
            $uid = (int) db()->lastInsertId();
        }
        return new_code($uid, 'verify');
    });

    $resp = ['status' => 'verify'];
    if ($code === null) {
        mail_register_attempt($email);
    } else {
        mail_verify_code($email, $code);
        if (test_mode($email)) {
            $resp['test_code'] = $code;
        }
    }
    return [202, $resp];
}

function h_resend(): array
{
    $email = v_email(field(body(), 'email'));
    rl_check('resend', 'ip', ip_key());
    rl_check('resend', 'email', $email);
    rl_hit('resend', 'ip', ip_key());
    rl_hit('resend', 'email', $email);

    $resp = ['status' => 'sent'];
    $uid = q('SELECT id FROM users WHERE email = ? AND verified_at IS NULL', [$email])->fetchColumn();
    if ($uid !== false) {
        $code = tx(fn () => new_code((int) $uid, 'verify'));
        mail_verify_code($email, $code);
        if (test_mode($email)) {
            $resp['test_code'] = $code;
        }
    }
    return [202, $resp];
}

function h_verify(): array
{
    $b = body();
    $email = v_email(field($b, 'email'));
    $code = v_code(field($b, 'code'));
    $device = v_device($b['device_name'] ?? null);
    rl_ip('verify');
    rl_check('verify', 'email', $email);

    $u = q('SELECT id, verified_at, wrapped_vault_key FROM users WHERE email = ?', [$email])->fetch();
    if (!$u || $u['verified_at'] !== null || !check_code((int) $u['id'], 'verify', $code)) {
        rl_hit('verify', 'email', $email);
        bad_code();
    }
    $uid = (int) $u['id'];
    $token = tx(function () use ($uid, $device): string {
        q('UPDATE users SET verified_at = ? WHERE id = ?', [dt(), $uid]);
        return new_session($uid, $device);
    });
    return [200, [
        'token' => $token,
        'wrapped_vault_key' => base64_encode($u['wrapped_vault_key']),
        'vault_version' => vault_version($uid),
    ]];
}

function h_login(): array
{
    $b = body();
    $email = v_email(field($b, 'email'));
    $authKey = v_key(field($b, 'auth_key'), 'auth_key');
    $device = v_device($b['device_name'] ?? null);
    rl_ip('login');
    rl_check('login', 'email', $email);

    $u = q('SELECT id, auth_hash, wrapped_vault_key FROM users WHERE email = ? AND verified_at IS NOT NULL',
        [$email])->fetch();
    $ok = password_verify($authKey, $u ? $u['auth_hash'] : DUMMY_HASH);
    if (!$u || !$ok) {
        rl_hit('login', 'email', $email);
        bad_credentials();
    }
    $uid = (int) $u['id'];
    if (password_needs_rehash($u['auth_hash'], PASSWORD_ARGON2ID, ARGON_OPTS)) {
        q('UPDATE users SET auth_hash = ? WHERE id = ?', [hash_key($authKey), $uid]);
    }
    return [200, [
        'token' => new_session($uid, $device),
        'wrapped_vault_key' => base64_encode($u['wrapped_vault_key']),
        'vault_version' => vault_version($uid),
    ]];
}

function h_logout(): array
{
    $s = auth();
    q('DELETE FROM sessions WHERE id = ?', [$s['sid']]);
    return [204, null];
}

// ------------------------------------------------------------ account and vault

function h_account(): array
{
    $s = auth();
    $r = q('SELECT u.email, u.created_at, v.version, v.updated_at
              FROM users u LEFT JOIN vaults v ON v.user_id = u.id
             WHERE u.id = ?', [$s['uid']])->fetch();
    return [200, [
        'email' => $r['email'],
        'created_at' => rfc3339($r['created_at']),
        'vault_version' => $r['version'] === null ? 0 : (int) $r['version'],
        'vault_updated_at' => rfc3339($r['updated_at']),
    ]];
}

function h_vault_get(): array
{
    $s = auth();
    $v = q('SELECT version, `blob`, updated_at FROM vaults WHERE user_id = ?', [$s['uid']])->fetch();
    if (!$v) {
        return [204, null];
    }
    return [200, [
        'version' => (int) $v['version'],
        'blob' => base64_encode($v['blob']),
        'updated_at' => rfc3339($v['updated_at']),
    ]];
}

function h_vault_put(): array
{
    $s = auth();
    $b = body();
    $base = field($b, 'base_version');
    if (!is_int($base) || $base < 0) {
        bad('base_version');
    }
    $blobB64 = field($b, 'blob');
    if (is_string($blobB64) && strlen($blobB64) > MAX_BLOB_CHARS) {
        throw new HttpError(413, 'too_large', 'The vault is larger than 2 MiB.');
    }
    $blob = v_b64($blobB64, 'blob', 1, intdiv(MAX_BLOB_CHARS, 4) * 3);

    return tx(function () use ($s, $base, $blob): array {
        q('SELECT id FROM users WHERE id = ? FOR UPDATE', [$s['uid']]); // serialises writers
        $cur = q('SELECT version, `blob`, updated_at FROM vaults WHERE user_id = ?', [$s['uid']])->fetch();
        $version = $cur ? (int) $cur['version'] : 0;
        if ($base !== $version) {
            throw new HttpError(409, 'conflict', 'The vault changed on another Mac. Merge and try again.', [
                'version' => $version,
                'blob' => $cur ? base64_encode($cur['blob']) : null,
                'updated_at' => $cur ? rfc3339($cur['updated_at']) : null,
            ]);
        }
        $next = $version + 1;
        if ($cur) {
            q('UPDATE vaults SET version = ?, `blob` = ?, updated_at = ? WHERE user_id = ?',
                [$next, new Bin($blob), dt(), $s['uid']]);
        } else {
            q('INSERT INTO vaults (user_id, version, `blob`, updated_at) VALUES (?, ?, ?, ?)',
                [$s['uid'], $next, new Bin($blob), dt()]);
        }
        return [200, ['version' => $next]];
    });
}

function h_devices(): array
{
    $s = auth();
    $rows = q('SELECT id, device_name, created_at, last_seen_at FROM sessions
                WHERE user_id = ? AND expires_at > ? ORDER BY created_at, id', [$s['uid'], dt()])->fetchAll();
    $out = [];
    foreach ($rows as $r) {
        $out[] = [
            'id' => (int) $r['id'],
            'name' => $r['device_name'],
            'created_at' => rfc3339($r['created_at']),
            'last_seen_at' => rfc3339($r['last_seen_at']),
            'current' => (int) $r['id'] === $s['sid'],
        ];
    }
    return [200, $out];
}

function h_device_delete(string $id): array
{
    $s = auth();
    if (!preg_match('/^[1-9][0-9]{0,18}$/D', $id)) {
        throw new HttpError(404, 'not_found', 'No such device.');
    }
    $n = q('DELETE FROM sessions WHERE id = ? AND user_id = ?', [(int) $id, $s['uid']])->rowCount();
    if ($n !== 1) {
        throw new HttpError(404, 'not_found', 'No such device.');
    }
    return [204, null];
}

/** Check the current auth_key of a signed-in user (password change, deletion). */
function require_auth_key(array $s, string $authKey): void
{
    rl_ip('login');
    rl_check('login', 'email', $s['email']);
    $hash = q('SELECT auth_hash FROM users WHERE id = ?', [$s['uid']])->fetchColumn();
    if ($hash === false || !password_verify($authKey, $hash)) {
        rl_hit('login', 'email', $s['email']);
        bad_credentials();
    }
}

function h_password(): array
{
    $s = auth();
    $b = body();
    $authKey = v_key(field($b, 'auth_key'), 'auth_key');
    $salt = v_b64(field($b, 'new_salt'), 'new_salt', 16, 16);
    $kdf = v_kdf(field($b, 'new_kdf'));
    $newKey = v_key(field($b, 'new_auth_key'), 'new_auth_key');
    $wrapped = v_wrapped(field($b, 'new_wrapped_vault_key'), 'new_wrapped_vault_key');
    require_auth_key($s, $authKey);
    $newHash = hash_key($newKey);
    tx(function () use ($s, $salt, $kdf, $newHash, $wrapped): void {
        q('UPDATE users SET salt = ?, kdf = ?, auth_hash = ?, wrapped_vault_key = ? WHERE id = ?',
            [new Bin($salt), json_encode($kdf), $newHash, new Bin($wrapped), $s['uid']]);
        q('DELETE FROM sessions WHERE user_id = ? AND id <> ?', [$s['uid'], $s['sid']]);
        q('DELETE FROM reset_tokens WHERE user_id = ?', [$s['uid']]);
        q("DELETE FROM codes WHERE user_id = ? AND purpose = 'reset'", [$s['uid']]);
    });
    return [204, null];
}

function h_account_delete(): array
{
    $s = auth();
    $authKey = v_key(field(body(), 'auth_key'), 'auth_key');
    require_auth_key($s, $authKey);
    q('DELETE FROM users WHERE id = ?', [$s['uid']]); // cascades to everything else
    return [204, null];
}

// ------------------------------------------------------------ recovery and reset

function h_recover_start(): array
{
    $b = body();
    $email = v_email(field($b, 'email'));
    $recAuth = v_key(field($b, 'recovery_auth'), 'recovery_auth');
    rl_ip('recover');
    rl_check('recover', 'email', $email);

    $u = q('SELECT id, recovery_hash, recovery_wrapped_vault_key FROM users
             WHERE email = ? AND verified_at IS NOT NULL', [$email])->fetch();
    $ok = password_verify($recAuth, $u ? $u['recovery_hash'] : DUMMY_HASH);
    if (!$u || !$ok) {
        rl_hit('recover', 'email', $email);
        throw new HttpError(401, 'bad_credentials', 'The email or recovery key is wrong.');
    }
    $uid = (int) $u['id'];
    $token = b64url(random_bytes(32));
    tx(function () use ($uid, $token): void {
        q('DELETE FROM reset_tokens WHERE user_id = ?', [$uid]);
        q('INSERT INTO reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)',
            [$uid, new Bin(hash('sha256', $token, true)), dt(time() + RESET_TOKEN_TTL), dt()]);
    });
    return [200, [
        'recovery_wrapped_vault_key' => base64_encode($u['recovery_wrapped_vault_key']),
        'reset_token' => $token,
    ]];
}

function h_recover_finish(): array
{
    $b = body();
    $token = v_token(field($b, 'reset_token'), 'reset_token');
    $salt = v_b64(field($b, 'salt'), 'salt', 16, 16);
    $kdf = v_kdf(field($b, 'kdf'));
    $authKey = v_key(field($b, 'auth_key'), 'auth_key');
    $wrapped = v_wrapped(field($b, 'wrapped_vault_key'), 'wrapped_vault_key');
    $device = v_device($b['device_name'] ?? null);
    rl_ip('recover');

    $r = q('SELECT id, user_id, expires_at FROM reset_tokens WHERE token_hash = ?',
        [new Bin(hash('sha256', $token, true))])->fetch();
    if (!$r || ts($r['expires_at']) <= time()) {
        throw new HttpError(401, 'bad_token', 'The recovery took too long. Start again.');
    }
    $uid = (int) $r['user_id'];
    $authHash = hash_key($authKey);
    $session = tx(function () use ($r, $uid, $salt, $kdf, $authHash, $wrapped, $device): string {
        if (q('DELETE FROM reset_tokens WHERE id = ?', [(int) $r['id']])->rowCount() !== 1) {
            throw new HttpError(401, 'bad_token', 'The recovery took too long. Start again.');
        }
        q('UPDATE users SET salt = ?, kdf = ?, auth_hash = ?, wrapped_vault_key = ? WHERE id = ?',
            [new Bin($salt), json_encode($kdf), $authHash, new Bin($wrapped), $uid]);
        q('DELETE FROM sessions WHERE user_id = ?', [$uid]);
        q('DELETE FROM reset_tokens WHERE user_id = ?', [$uid]);
        q("DELETE FROM codes WHERE user_id = ? AND purpose = 'reset'", [$uid]);
        return new_session($uid, $device);
    });
    return [200, ['token' => $session, 'vault_version' => vault_version($uid)]];
}

function h_reset_start(): array
{
    $email = v_email(field(body(), 'email'));
    rl_check('reset-start', 'ip', ip_key());
    rl_check('reset-start', 'email', $email);
    rl_hit('reset-start', 'ip', ip_key());
    rl_hit('reset-start', 'email', $email);

    $resp = ['status' => 'sent'];
    $uid = q('SELECT id FROM users WHERE email = ? AND verified_at IS NOT NULL', [$email])->fetchColumn();
    if ($uid !== false) {
        $code = tx(fn () => new_code((int) $uid, 'reset'));
        mail_reset_code($email, $code);
        if (test_mode($email)) {
            $resp['test_code'] = $code;
        }
    }
    return [202, $resp];
}

function h_reset_finish(): array
{
    $b = body();
    $email = v_email(field($b, 'email'));
    $code = v_code(field($b, 'code'));
    $salt = v_b64(field($b, 'salt'), 'salt', 16, 16);
    $kdf = v_kdf(field($b, 'kdf'));
    $authKey = v_key(field($b, 'auth_key'), 'auth_key');
    $wrapped = v_wrapped(field($b, 'wrapped_vault_key'), 'wrapped_vault_key');
    $recWrapped = v_wrapped(field($b, 'recovery_wrapped_vault_key'), 'recovery_wrapped_vault_key');
    $recAuth = v_key(field($b, 'recovery_auth'), 'recovery_auth');
    $device = v_device($b['device_name'] ?? null);
    rl_ip('reset');
    rl_check('reset', 'email', $email);

    $uid = q('SELECT id FROM users WHERE email = ? AND verified_at IS NOT NULL', [$email])->fetchColumn();
    if ($uid === false || !check_code((int) $uid, 'reset', $code)) {
        rl_hit('reset', 'email', $email);
        bad_code();
    }
    $uid = (int) $uid;
    $authHash = hash_key($authKey);
    $recHash = hash_key($recAuth);
    $session = tx(function () use ($uid, $salt, $kdf, $authHash, $wrapped, $recWrapped, $recHash, $device): string {
        q('UPDATE users SET salt = ?, kdf = ?, auth_hash = ?, wrapped_vault_key = ?,
                  recovery_wrapped_vault_key = ?, recovery_hash = ?
            WHERE id = ?',
            [new Bin($salt), json_encode($kdf), $authHash, new Bin($wrapped), new Bin($recWrapped), $recHash, $uid]);
        q('DELETE FROM vaults WHERE user_id = ?', [$uid]);
        q('DELETE FROM sessions WHERE user_id = ?', [$uid]);
        q('DELETE FROM reset_tokens WHERE user_id = ?', [$uid]);
        q('DELETE FROM codes WHERE user_id = ?', [$uid]);
        return new_session($uid, $device);
    });
    return [200, ['token' => $session, 'vault_version' => 0]];
}

// ------------------------------------------------------------ test support

/** POST test/reset-limits {emails:[...]}: clears the rate-limit buckets of
 *  the given test addresses and of the caller's IP. Needs the test secret;
 *  otherwise it answers exactly like an unknown path. */
function h_test_reset_limits(): array
{
    $emails = body()['emails'] ?? null;
    $secret = cfg('TEST_SECRET');
    if (strlen($secret) < 32 || !hash_equals($secret, header_value('X-CloudUp-Test'))
        || !is_array($emails) || count($emails) > 50) {
        throw new HttpError(404, 'not_found', 'Not found.');
    }
    $buckets = [];
    foreach (array_keys(RATE_LIMITS) as $action) {
        $buckets[] = rl_bucket($action, 'ip', ip_key());
        foreach ($emails as $e) {
            if (!is_string($e) || !is_test_email($e)) {
                throw new HttpError(404, 'not_found', 'Not found.');
            }
            $buckets[] = rl_bucket($action, 'email', $e);
        }
    }
    $in = implode(',', array_fill(0, count($buckets), '?'));
    q("DELETE FROM rate_limits WHERE bucket IN ($in)", $buckets);
    return [204, null];
}

// ------------------------------------------------------------ housekeeping

/** Runs on about 1 in 50 requests: drops expired rows. */
function housekeeping(): void
{
    $now = time();
    q('DELETE FROM sessions WHERE expires_at <= ?', [dt($now)]);
    q('DELETE FROM codes WHERE expires_at <= ?', [dt($now)]);
    q('DELETE FROM reset_tokens WHERE expires_at <= ?', [dt($now)]);
    q('DELETE FROM rate_limits WHERE at <= ?', [$now - 3600]);
    q('DELETE FROM users WHERE verified_at IS NULL AND created_at <= ?', [dt($now - UNVERIFIED_TTL)]);
}

<?php
// CloudUp sync API: rate limits, codes, sessions, mail and test mode.
declare(strict_types=1);
defined('CLOUDUP_API') || exit;

// ---------------------------------------------------------------- rate limits

/** Every rate-limited action: [limit, window seconds]. */
const RATE_LIMITS = [
    'prelogin'    => [10, 900],
    'login'       => [10, 900],   // login, password change, account deletion
    'verify'      => [10, 900],
    'recover'     => [10, 900],   // recover/start and recover/finish
    'reset'       => [10, 900],   // reset/finish
    'register'    => [5, 3600],
    'resend'      => [5, 3600],
    'reset-start' => [5, 3600],
];

function rl_bucket(string $action, string $kind, string $value): string
{
    return $action . ':' . $kind . ':'
        . substr(hash_hmac('sha256', $kind . ':' . $value, secret('rate-limit')), 0, 40);
}

/** 429 if the bucket is full. Sliding window over logged hits. */
function rl_check(string $action, string $kind, string $value): void
{
    [$limit, $window] = RATE_LIMITS[$action];
    $now = time();
    $row = q(
        'SELECT COUNT(*) AS n, MIN(at) AS first FROM rate_limits WHERE bucket = ? AND at > ?',
        [rl_bucket($action, $kind, $value), $now - $window],
    )->fetch();
    if ((int) $row['n'] >= $limit) {
        $retry = max(1, (int) $row['first'] + $window - $now);
        throw new HttpError(429, 'rate_limited', 'Too many attempts. Try again later.', ['retry_after' => $retry]);
    }
}

function rl_hit(string $action, string $kind, string $value): void
{
    q('INSERT INTO rate_limits (bucket, at) VALUES (?, ?)', [rl_bucket($action, $kind, $value), time()]);
}

/** Check and count a request from this client's IP. */
function rl_ip(string $action): void
{
    rl_check($action, 'ip', ip_key());
    rl_hit($action, 'ip', ip_key());
}

// ---------------------------------------------------------------- codes

function code_hash(int $uid, string $purpose, string $code): string
{
    return hash_hmac('sha256', "$uid:$purpose:$code", secret('code'), true);
}

/** Make a fresh 6-digit code (replacing any earlier one) and return it. */
function new_code(int $uid, string $purpose): string
{
    $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    q('DELETE FROM codes WHERE user_id = ? AND purpose = ?', [$uid, $purpose]);
    q(
        'INSERT INTO codes (user_id, purpose, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)',
        [$uid, $purpose, new Bin(code_hash($uid, $purpose, $code)), dt(time() + CODE_TTL), dt()],
    );
    return $code;
}

/** Spend one attempt on the code; true (and the code is consumed) if it matches.
 *  Runs in autocommit so a wrong guess is counted even though the caller fails. */
function check_code(int $uid, string $purpose, string $code): bool
{
    $row = q(
        'SELECT id, code_hash, expires_at, attempts FROM codes WHERE user_id = ? AND purpose = ?',
        [$uid, $purpose],
    )->fetch();
    if (!$row || ts($row['expires_at']) <= time() || (int) $row['attempts'] >= CODE_MAX_ATTEMPTS) {
        return false;
    }
    $spent = q(
        'UPDATE codes SET attempts = attempts + 1 WHERE id = ? AND attempts < ?',
        [(int) $row['id'], CODE_MAX_ATTEMPTS],
    )->rowCount();
    if ($spent !== 1 || !hash_equals($row['code_hash'], code_hash($uid, $purpose, $code))) {
        return false;
    }
    return q('DELETE FROM codes WHERE id = ?', [(int) $row['id']])->rowCount() === 1;
}

// ---------------------------------------------------------------- sessions

function new_session(int $uid, string $device): string
{
    $token = b64url(random_bytes(32));
    $now = time();
    q(
        'INSERT INTO sessions (user_id, token_hash, device_name, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        [$uid, new Bin(hash('sha256', $token, true)), $device, dt($now), dt($now), dt($now + SESSION_TTL)],
    );
    return $token;
}

/** The signed-in session for this request: ['sid', 'uid', 'email'], or 401. */
function auth(): array
{
    $h = header_value('Authorization');
    if (!preg_match('/^Bearer ([A-Za-z0-9_-]{43})$/D', $h, $m)) {
        throw new HttpError(401, 'unauthorized', 'Sign in again.');
    }
    $row = q(
        'SELECT s.id, s.user_id, s.last_seen_at, s.expires_at, u.email
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = ?',
        [new Bin(hash('sha256', $m[1], true))],
    )->fetch();
    $now = time();
    if (!$row || ts($row['expires_at']) <= $now) {
        throw new HttpError(401, 'unauthorized', 'Sign in again.');
    }
    if ($now - ts($row['last_seen_at']) >= SEEN_INTERVAL) {
        q('UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?',
            [dt($now), dt($now + SESSION_TTL), (int) $row['id']]);
    }
    return ['sid' => (int) $row['id'], 'uid' => (int) $row['user_id'], 'email' => $row['email']];
}

function vault_version(int $uid): int
{
    $v = q('SELECT version FROM vaults WHERE user_id = ?', [$uid])->fetchColumn();
    return $v === false ? 0 : (int) $v;
}

/** Stable per-email salt for accounts that don't exist (or aren't verified). */
function fake_salt(string $email): string
{
    return substr(hash_hmac('sha256', $email, secret('prelogin-salt'), true), 0, 16);
}

// ---------------------------------------------------------------- test mode

/** Throwaway addresses used by server/tests/api_test.py. Never emailed. */
function is_test_email(string $email): bool
{
    return (bool) preg_match('/^cloudup-test\+[a-z0-9]{1,40}@demelos\.com$/D', $email);
}

/** True only for a test address AND the X-CloudUp-Test header matching
 *  TEST_SECRET from the env file. Then responses carry the emailed code. */
function test_mode(string $email): bool
{
    $secret = cfg('TEST_SECRET');
    if (strlen($secret) < 32 || !is_test_email($email)) {
        return false;
    }
    return hash_equals($secret, header_value('X-CloudUp-Test'));
}

// ---------------------------------------------------------------- mail

/** Queue a plain-text email; sent after the response is flushed, so the
 *  reply time doesn't show whether an email went out. */
function queue_mail(string $to, string $subject, string $text): void
{
    $GLOBALS['cloudup_mail'][] = [$to, $subject, $text];
}

function send_queued_mail(): void
{
    foreach ($GLOBALS['cloudup_mail'] ?? [] as [$to, $subject, $text]) {
        if (is_test_email($to)) {
            continue; // test accounts never get mail
        }
        $headers = implode("\r\n", [
            'From: CloudUp <noreply@demelos.com>',
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            'Auto-Submitted: auto-generated',
        ]);
        if (!@mail($to, $subject, $text, $headers, '-f noreply@demelos.com')) {
            log_error('mail() failed');
        }
    }
    $GLOBALS['cloudup_mail'] = [];
}

function mail_verify_code(string $to, string $code): void
{
    queue_mail($to, 'Your CloudUp verification code',
        "Your CloudUp verification code is $code\n\n"
        . "Enter it in CloudUp to finish creating your account. It expires in 30 minutes.\n\n"
        . "If you didn't create a CloudUp account, ignore this email.\n");
}

function mail_reset_code(string $to, string $code): void
{
    queue_mail($to, 'Your CloudUp password reset code',
        "Your CloudUp password reset code is $code\n\n"
        . "Enter it in CloudUp to choose a new password. It expires in 30 minutes.\n"
        . "Resetting without your recovery key erases the connections synced to your account; "
        . "the copies on your Macs stay.\n\n"
        . "If you didn't ask for this, ignore this email. Your password stays the same.\n");
}

function mail_register_attempt(string $to): void
{
    queue_mail($to, 'CloudUp sign-up attempt',
        "Someone tried to create a CloudUp account with this email address, which already has one.\n\n"
        . "If it was you, sign in instead. If you forgot your password, use \"Forgot password\" on the sign-in screen.\n\n"
        . "If it wasn't you, ignore this email. Nothing has changed.\n");
}

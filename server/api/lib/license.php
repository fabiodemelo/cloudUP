<?php
// CloudUp license: an emailed code proves the address, then the demelos
// license server (dmadmin) finds or issues the free CloudUp license for it.
// Contract: docs/license-api.md in the CloudUp repo.
declare(strict_types=1);
defined('CLOUDUP_API') || exit;

const LICENSE_PRODUCT = 'dm-cloudup';           // dmadmin product key_slug
const LICENSE_MAX_ACTIVATIONS = 5;              // Macs per license
const LICENSE_ORDER_REF = 'cloudup-free';
const LICENSE_TEST_ORDER_REF = 'cloudup-api-test';
const DMADMIN_DEFAULT_URL = 'http://127.0.0.1:3015/admin/api/';
const DMADMIN_TIMEOUT = 15;
const DMADMIN_CONNECT_TIMEOUT = 5;
const CLOUDUP_PAGE = 'https://www.demelos.com/tools/cloudup/';
const LICENSE_CODE_MIN_AGE = 60;               // a code isn't replaced before this (seconds)
const LICENSE_LOCK_TIMEOUT = 10;               // seconds to wait for another finish of the same email

// ---------------------------------------------------------------- codes

function license_code_hash(string $email, string $code): string
{
    return hash_hmac('sha256', "license:$email:$code", secret('code'), true);
}

/** A fresh 6-digit code for this email, replacing any earlier one; null
 *  when the live code is under a minute old (repeated starts, by the person
 *  or by someone else typing their address, don't keep replacing it). */
function new_license_code(string $email): ?string
{
    $live = q('SELECT created_at, expires_at, attempts FROM license_codes WHERE email = ?', [$email])->fetch();
    if ($live && ts($live['expires_at']) > time() && (int) $live['attempts'] < CODE_MAX_ATTEMPTS
        && time() - ts($live['created_at']) < LICENSE_CODE_MIN_AGE) {
        return null;
    }
    $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    q(
        'INSERT INTO license_codes (email, code_hash, expires_at, attempts, created_at) VALUES (?, ?, ?, 0, ?)
         ON DUPLICATE KEY UPDATE code_hash = VALUES(code_hash), expires_at = VALUES(expires_at),
                                 attempts = 0, created_at = VALUES(created_at)',
        [$email, new Bin(license_code_hash($email, $code)), dt(time() + CODE_TTL), dt()],
    );
    return $code;
}

/** Spend one attempt on the code. True if it matches; the code stays until
 *  consume_license_code(), so a license-server outage doesn't burn it. */
function check_license_code(string $email, string $code): bool
{
    $row = q('SELECT code_hash, expires_at, attempts FROM license_codes WHERE email = ?', [$email])->fetch();
    if (!$row || ts($row['expires_at']) <= time() || (int) $row['attempts'] >= CODE_MAX_ATTEMPTS) {
        return false;
    }
    $spent = q(
        'UPDATE license_codes SET attempts = attempts + 1 WHERE email = ? AND attempts < ?',
        [$email, CODE_MAX_ATTEMPTS],
    )->rowCount();
    return $spent === 1 && hash_equals($row['code_hash'], license_code_hash($email, $code));
}

function consume_license_code(string $email): void
{
    q('DELETE FROM license_codes WHERE email = ?', [$email]);
}

// ---------------------------------------------------------------- license server

/** Call the dmadmin license intake API. Returns its `data` object. */
function dmadmin(string $method, string $path, ?array $payload = null): array
{
    $key = cfg('DMADMIN_INTAKE_KEY');
    if (strlen($key) < 32) {
        throw new RuntimeException('DMADMIN_INTAKE_KEY missing or short');
    }
    $ch = curl_init(rtrim(cfg('DMADMIN_URL', DMADMIN_DEFAULT_URL), '/') . '/' . $path);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CUSTOMREQUEST => $method,
        CURLOPT_TIMEOUT => DMADMIN_TIMEOUT,
        CURLOPT_CONNECTTIMEOUT => DMADMIN_CONNECT_TIMEOUT,
        CURLOPT_HTTPHEADER => [
            'Accept: application/json',
            'Content-Type: application/json',
            'x-intake-key: ' . $key,
        ],
    ]);
    if ($payload !== null) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_SLASHES));
    }
    $raw = curl_exec($ch);
    $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    $err = curl_error($ch);
    if ($raw === false) {
        throw new RuntimeException("license server unreachable ($err)");
    }
    $json = json_decode((string) $raw, true);
    if ($status < 200 || $status >= 300 || !is_array($json) || ($json['success'] ?? false) !== true) {
        throw new RuntimeException("license server answered HTTP $status on $method " . strtok($path, '?'));
    }
    return is_array($json['data'] ?? null) ? $json['data'] : [];
}

function license_is_live(array $l): bool
{
    if (($l['status'] ?? '') !== 'active') {
        return false;
    }
    $exp = $l['expires_at'] ?? null;
    return $exp === null || strtotime((string) $exp) > time();
}

/** The email's live CloudUp license key, issuing one if it has none.
 *  A revoked or suspended license is never replaced by a new one. */
function license_for(string $email): string
{
    $licenses = dmadmin('GET', 'license-intake/licenses?customer_email=' . rawurlencode($email))['licenses'] ?? [];
    foreach ($licenses as $l) {
        if (is_array($l) && license_is_live($l) && is_string($l['license_key'] ?? null)) {
            return $l['license_key'];
        }
    }
    foreach ($licenses as $l) {
        if (in_array($l['status'] ?? '', ['revoked', 'suspended'], true)) {
            throw new HttpError(403, 'license_blocked',
                'The CloudUp license for this email is turned off. Contact support@demelos.com.');
        }
    }
    $issued = dmadmin('POST', 'license-intake/orders', [
        'product_slug' => LICENSE_PRODUCT,
        'customer_email' => $email,
        'order_ref' => is_test_email($email) ? LICENSE_TEST_ORDER_REF : LICENSE_ORDER_REF,
        'max_activations' => LICENSE_MAX_ACTIVATIONS,
    ]);
    $key = $issued['license_key'] ?? null;
    if (!is_string($key) || !preg_match('/^DM(-[0-9A-Z]{4}){6}$/D', $key)) {
        throw new RuntimeException('license server returned no key');
    }
    return $key;
}

// ---------------------------------------------------------------- endpoints

function h_license_start(): array
{
    $email = v_email(field(body(), 'email'));
    rl_check('license-start', 'ip', ip_key());
    rl_check('license-start', 'email', $email);
    rl_hit('license-start', 'ip', ip_key());
    rl_hit('license-start', 'email', $email);

    $code = new_license_code($email);
    $resp = ['status' => 'sent'];
    if ($code !== null) {
        mail_license_code($email, $code);
        if (test_mode($email)) {
            $resp['test_code'] = $code;
        }
    }
    return [202, $resp];
}

function h_license_finish(): array
{
    $b = body();
    $email = v_email(field($b, 'email'));
    $code = v_code(field($b, 'code'));
    rl_ip('license-finish');
    rl_check('license-finish', 'email', $email);

    if (!check_license_code($email, $code)) {
        rl_hit('license-finish', 'email', $email);
        bad_code();
    }
    // One finish per email at a time, so two at once can't issue two licenses.
    $lock = 'cloudup-license:' . substr(hash('sha256', $email), 0, 40);
    if ((int) q('SELECT GET_LOCK(?, ?)', [$lock, LICENSE_LOCK_TIMEOUT])->fetchColumn() !== 1) {
        throw new HttpError(503, 'license_unavailable', 'We could not create your license right now. Try the same code again in a minute.');
    }
    try {
        $key = license_for($email);
    } catch (HttpError $e) {
        throw $e;
    } catch (Throwable $e) {
        log_error('license: ' . describe($e));
        throw new HttpError(503, 'license_unavailable',
            'We could not create your license right now. Try the same code again in a minute.');
    } finally {
        q('SELECT RELEASE_LOCK(?)', [$lock]);
    }
    consume_license_code($email);
    mail_license_key($email, $key);
    return [200, ['license_key' => $key, 'email' => $email, 'max_activations' => LICENSE_MAX_ACTIVATIONS]];
}

// ---------------------------------------------------------------- mail

function mail_license_code(string $to, string $code): void
{
    queue_mail($to, 'Your CloudUp code',
        "Your CloudUp code is $code\n\n"
        . "Enter it on the CloudUp page or in the app to get your free license. It expires in 30 minutes.\n\n"
        . "If you didn't ask for this, ignore this email.\n");
}

function mail_license_key(string $to, string $key): void
{
    queue_mail($to, 'Your CloudUp license',
        "Thanks for using CloudUp. Your free license key:\n\n"
        . "    $key\n\n"
        . "It works on up to " . LICENSE_MAX_ACTIVATIONS . " Macs. CloudUp asks for it the first time it opens:\n"
        . "paste the key, or enter this email address and the code we send you.\n\n"
        . "Download CloudUp: " . CLOUDUP_PAGE . "\n\n"
        . "Keep this email. If you lose the key, verify your email again on the CloudUp page and we'll send the same key.\n");
}

<?php
// CloudUp accounts and end-to-end encrypted sync, API v1.
// Contract: docs/sync-api.md in the CloudUp repo. Every request is routed
// here by .htaccess; the server only ever sees encrypted vaults and hashes.
declare(strict_types=1);

const CLOUDUP_API = true;
ini_set('display_errors', '0');
ini_set('log_errors', '0');
error_reporting(E_ALL);

require __DIR__ . '/lib/core.php';
require __DIR__ . '/lib/security.php';
require __DIR__ . '/lib/handlers.php';

set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
    if (!(error_reporting() & $no)) {
        return false; // silenced with @
    }
    throw new ErrorException($msg, 0, $no, $file, $line);
});

/** [method => handler] per path; {id} paths are matched below. */
const ROUTES = [
    'prelogin'           => ['POST' => 'h_prelogin'],
    'register'           => ['POST' => 'h_register'],
    'verify'             => ['POST' => 'h_verify'],
    'resend'             => ['POST' => 'h_resend'],
    'login'              => ['POST' => 'h_login'],
    'logout'             => ['POST' => 'h_logout'],
    'account'            => ['GET' => 'h_account', 'DELETE' => 'h_account_delete'],
    'vault'              => ['GET' => 'h_vault_get', 'PUT' => 'h_vault_put'],
    'devices'            => ['GET' => 'h_devices'],
    'password'           => ['POST' => 'h_password'],
    'recover/start'      => ['POST' => 'h_recover_start'],
    'recover/finish'     => ['POST' => 'h_recover_finish'],
    'reset/start'        => ['POST' => 'h_reset_start'],
    'reset/finish'       => ['POST' => 'h_reset_finish'],
    'test/reset-limits'  => ['POST' => 'h_test_reset_limits'],
];

function route(): array
{
    $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    $path = (string) parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
    if (!str_starts_with($path, API_PREFIX)) {
        throw new HttpError(404, 'not_found', 'Not found.');
    }
    $path = trim(substr($path, strlen(API_PREFIX)), '/');

    $args = [];
    $methods = ROUTES[$path] ?? null;
    if ($methods === null && preg_match('#^devices/([^/]+)$#D', $path, $m)) {
        $methods = ['DELETE' => 'h_device_delete'];
        $args = [$m[1]];
    }
    if ($methods === null) {
        throw new HttpError(404, 'not_found', 'Not found.');
    }
    $handler = $methods[$method] ?? null;
    if ($handler === null) {
        header('Allow: ' . implode(', ', array_keys($methods)));
        throw new HttpError(405, 'method_not_allowed', 'Method not allowed.');
    }
    if (random_int(1, 50) === 1) {
        try {
            housekeeping();
        } catch (Throwable $e) {
            log_error('housekeeping: ' . describe($e));
        }
    }
    return $handler(...$args);
}

/** A loggable description of an exception, without SQL values or input. */
function describe(Throwable $e): string
{
    $where = basename($e->getFile()) . ':' . $e->getLine();
    if ($e instanceof PDOException) {
        $info = $e->errorInfo ?? [];
        return 'PDOException SQLSTATE ' . ($info[0] ?? $e->getCode()) . ' (' . ($info[1] ?? '-') . ") at $where";
    }
    return get_class($e) . ': ' . $e->getMessage() . " at $where";
}

function emit(int $status, ?array $body, array $headers = []): void
{
    http_response_code($status);
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    foreach ($headers as $h) {
        header($h);
    }
    if ($status === 204 || $body === null) {
        header('Content-Length: 0');
        return;
    }
    $json = json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    header('Content-Type: application/json; charset=utf-8');
    header('Content-Length: ' . strlen($json));
    echo $json;
}

try {
    [$status, $body] = route();
    emit($status, $body);
} catch (HttpError $e) {
    $headers = isset($e->extra['retry_after']) ? ['Retry-After: ' . $e->extra['retry_after']] : [];
    emit($e->status, ['error' => $e->error, 'message' => $e->getMessage()] + $e->extra, $headers);
} catch (Throwable $e) {
    log_error(describe($e));
    emit(500, ['error' => 'server_error', 'message' => 'Something went wrong on our side. Try again later.']);
}

// Mail goes out after the reply, so response time says nothing about
// whether an account exists.
if (function_exists('litespeed_finish_request')) {
    litespeed_finish_request();
} elseif (function_exists('fastcgi_finish_request')) {
    fastcgi_finish_request();
}
try {
    send_queued_mail();
} catch (Throwable $e) {
    log_error(describe($e));
}

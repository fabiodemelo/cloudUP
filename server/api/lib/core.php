<?php
// CloudUp sync API: configuration, database, HTTP and validation helpers.
declare(strict_types=1);
defined('CLOUDUP_API') || exit;

const DEFAULT_ENV_FILE = '/home/demelos.com/cloudup-api.env';
const DEFAULT_LOG_FILE = '/home/demelos.com/cloudup-api.log';
const API_PREFIX = '/tools/cloudup/api/v1/';

const MAX_BLOB_CHARS = 2097152;              // 2 MiB of base64 text
const MAX_BODY_BYTES = MAX_BLOB_CHARS + 65536;
const SESSION_TTL = 90 * 86400;              // sliding, from last use
const SEEN_INTERVAL = 3600;                  // last_seen_at granularity
const CODE_TTL = 1800;                       // emailed codes: 30 minutes
const CODE_MAX_ATTEMPTS = 5;
const RESET_TOKEN_TTL = 900;                 // recover/start token: 15 minutes
const UNVERIFIED_TTL = 7 * 86400;            // unverified sign-ups are purged after a week
const WRAPPED_KEY_BYTES = 72;                // nonce(24) || ciphertext(32) || tag(16)
const ARGON_OPTS = ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1];
const DEFAULT_KDF = ['alg' => 'argon2id', 'm' => 65536, 't' => 3, 'p' => 1];
// password_hash() of 32 random bytes nobody knows, with ARGON_OPTS. Verified
// against when the account doesn't exist, so the reply takes the same time.
const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$WFZ6a0xnTmVsa0pvZEo2ZA$GLmK07HnR25h/sL0D3gSKIrI59RaDhEKyWBU2ezOrVA';

final class HttpError extends Exception
{
    public function __construct(
        public readonly int $status,
        public readonly string $error,
        string $message,
        public readonly array $extra = [],
    ) {
        parent::__construct($message);
    }
}

/** Raw bytes to bind as a binary parameter. */
final class Bin
{
    public function __construct(public readonly string $bytes) {}
}

// ---------------------------------------------------------------- config

function cfg(string $key, string $default = ''): string
{
    static $c = null;
    if ($c === null) {
        $path = getenv('CLOUDUP_ENV_FILE') ?: DEFAULT_ENV_FILE;
        $lines = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            $c = [];
            throw new RuntimeException('config file unreadable');
        }
        $c = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            $eq = strpos($line, '=');
            if ($eq === false) {
                continue;
            }
            $c[trim(substr($line, 0, $eq))] = trim(substr($line, $eq + 1));
        }
    }
    return $c[$key] ?? $default;
}

/** A purpose-bound key derived from SERVER_SECRET. */
function secret(string $purpose): string
{
    $s = cfg('SERVER_SECRET');
    if (strlen($s) < 32) {
        throw new RuntimeException('SERVER_SECRET missing or short');
    }
    return hash_hmac('sha256', 'cloudup-' . $purpose, $s, true);
}

// ---------------------------------------------------------------- logging

function request_id(): string
{
    static $id = null;
    return $id ??= bin2hex(random_bytes(6));
}

/** Errors only. Never pass request bodies, keys, tokens or codes here. */
function log_error(string $msg): void
{
    try {
        $file = cfg('LOG_FILE', DEFAULT_LOG_FILE);
    } catch (Throwable) {
        $file = DEFAULT_LOG_FILE;
    }
    $line = gmdate('Y-m-d\TH:i:s\Z') . ' ' . request_id() . ' '
        . str_replace(["\r", "\n"], ' ', $msg) . "\n";
    @file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
}

// ---------------------------------------------------------------- database

function db(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=utf8mb4',
            cfg('DB_HOST', 'localhost'),
            cfg('DB_NAME', 'cloudup'),
        );
        $pdo = new PDO($dsn, cfg('DB_USER'), cfg('DB_PASS'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ]);
        $pdo->exec("SET time_zone = '+00:00'");
    }
    return $pdo;
}

function q(string $sql, array $params = []): PDOStatement
{
    $st = db()->prepare($sql);
    $i = 1;
    foreach ($params as $p) {
        if ($p instanceof Bin) {
            $st->bindValue($i, $p->bytes, PDO::PARAM_LOB);
        } elseif (is_int($p)) {
            $st->bindValue($i, $p, PDO::PARAM_INT);
        } elseif ($p === null) {
            $st->bindValue($i, null, PDO::PARAM_NULL);
        } else {
            $st->bindValue($i, (string) $p, PDO::PARAM_STR);
        }
        $i++;
    }
    $st->execute();
    return $st;
}

function tx(callable $fn): mixed
{
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $r = $fn();
        $pdo->commit();
        return $r;
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $e;
    }
}

/** DATETIME string (UTC) for a unix time. */
function dt(?int $t = null): string
{
    return gmdate('Y-m-d H:i:s', $t ?? time());
}

/** Unix time from a DATETIME string (UTC). */
function ts(string $dt): int
{
    return (int) (new DateTimeImmutable($dt, new DateTimeZone('UTC')))->getTimestamp();
}

/** RFC 3339 for a DATETIME string (UTC), or null. */
function rfc3339(?string $dt): ?string
{
    return $dt === null ? null : gmdate('Y-m-d\TH:i:s\Z', ts($dt));
}

// ---------------------------------------------------------------- HTTP

function body(): array
{
    static $b = null;
    if ($b !== null) {
        return $b;
    }
    $in = fopen('php://input', 'rb');
    $raw = $in ? stream_get_contents($in, MAX_BODY_BYTES + 1) : '';
    if ($raw === false) {
        $raw = '';
    }
    if (strlen($raw) > MAX_BODY_BYTES) {
        throw new HttpError(413, 'too_large', 'The request is too large.');
    }
    if (trim($raw) === '') {
        return $b = [];
    }
    try {
        $v = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        throw new HttpError(400, 'invalid_request', 'The body must be a JSON object.');
    }
    if (!is_array($v) || ($v !== [] && array_is_list($v))) {
        throw new HttpError(400, 'invalid_request', 'The body must be a JSON object.');
    }
    return $b = $v;
}

function field(array $b, string $name): mixed
{
    if (!array_key_exists($name, $b)) {
        throw new HttpError(400, 'invalid_request', "Missing field: $name.");
    }
    return $b[$name];
}

function bad(string $name): never
{
    throw new HttpError(400, 'invalid_request', "Invalid field: $name.");
}

function header_value(string $name): string
{
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    $v = $_SERVER[$key] ?? $_SERVER['REDIRECT_' . $key] ?? null;
    if ($v === null && function_exists('getallheaders')) {
        foreach (getallheaders() as $k => $val) {
            if (strcasecmp($k, $name) === 0) {
                $v = $val;
                break;
            }
        }
    }
    return is_string($v) ? $v : '';
}

const CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function ip_in_cidr(string $ip, string $cidr): bool
{
    [$net, $bits] = explode('/', $cidr);
    $a = @inet_pton($ip);
    $n = @inet_pton($net);
    if ($a === false || $n === false || strlen($a) !== strlen($n)) {
        return false;
    }
    $bits = (int) $bits;
    $bytes = intdiv($bits, 8);
    if (substr($a, 0, $bytes) !== substr($n, 0, $bytes)) {
        return false;
    }
    $rem = $bits % 8;
    if ($rem === 0) {
        return true;
    }
    $mask = (0xFF << (8 - $rem)) & 0xFF;
    return (ord($a[$bytes]) & $mask) === (ord($n[$bytes]) & $mask);
}

/** The client's address. Trusts CF-Connecting-IP only from Cloudflare's edge. */
function client_ip(): string
{
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    $cf = header_value('CF-Connecting-IP');
    if ($cf !== '' && filter_var($cf, FILTER_VALIDATE_IP)) {
        foreach (CLOUDFLARE_RANGES as $r) {
            if (ip_in_cidr($ip, $r)) {
                return $cf;
            }
        }
    }
    return $ip;
}

/** Rate-limit key for the client: the IPv4 address, or the IPv6 /64. */
function ip_key(): string
{
    $ip = client_ip();
    $bin = @inet_pton($ip);
    if ($bin !== false && strlen($bin) === 16) {
        return bin2hex(substr($bin, 0, 8)) . '::/64';
    }
    return $ip;
}

// ---------------------------------------------------------------- validation

function v_email(mixed $v): string
{
    if (!is_string($v)) {
        bad('email');
    }
    $e = strtolower(trim($v));
    if ($e === '' || strlen($e) > 254 || preg_match('/[^\x21-\x7e]/', $e)
        || filter_var($e, FILTER_VALIDATE_EMAIL) === false) {
        bad('email');
    }
    return $e;
}

/** Standard padded base64, canonical form only. Returns the raw bytes. */
function v_b64(mixed $v, string $name, int $minBytes, int $maxBytes): string
{
    if (!is_string($v) || strlen($v) % 4 !== 0
        || strlen($v) > intdiv($maxBytes + 2, 3) * 4) {
        bad($name);
    }
    $raw = base64_decode($v, true);
    if ($raw === false || base64_encode($raw) !== $v
        || strlen($raw) < $minBytes || strlen($raw) > $maxBytes) {
        bad($name);
    }
    return $raw;
}

/** A 32-byte key sent as base64. Returns the canonical base64 text, which is
 *  what gets password-hashed (1:1 with the bytes, and free of NUL bytes). */
function v_key(mixed $v, string $name): string
{
    v_b64($v, $name, 32, 32);
    return $v;
}

function v_wrapped(mixed $v, string $name): string
{
    return v_b64($v, $name, WRAPPED_KEY_BYTES, WRAPPED_KEY_BYTES);
}

function v_kdf(mixed $v): array
{
    if (!is_array($v) || array_is_list($v)) {
        bad('kdf');
    }
    $keys = array_keys($v);
    sort($keys);
    if ($keys !== ['alg', 'm', 'p', 't'] || $v['alg'] !== 'argon2id'
        || !is_int($v['m']) || !is_int($v['t']) || !is_int($v['p'])
        || $v['m'] < DEFAULT_KDF['m'] || $v['m'] > 4194304
        || $v['t'] < DEFAULT_KDF['t'] || $v['t'] > 64
        || $v['p'] < DEFAULT_KDF['p'] || $v['p'] > 64) {
        bad('kdf');
    }
    return ['alg' => 'argon2id', 'm' => $v['m'], 't' => $v['t'], 'p' => $v['p']];
}

function v_code(mixed $v): string
{
    if (!is_string($v) || !preg_match('/^[0-9]{6}$/D', $v)) {
        bad('code');
    }
    return $v;
}

function v_token(mixed $v, string $name): string
{
    if (!is_string($v) || !preg_match('/^[A-Za-z0-9_-]{43}$/D', $v)) {
        bad($name);
    }
    return $v;
}

function v_device(mixed $v): string
{
    if ($v === null) {
        return 'Mac';
    }
    if (!is_string($v) || strlen($v) > 1000 || !mb_check_encoding($v, 'UTF-8')) {
        bad('device_name');
    }
    $v = trim((string) preg_replace('/[\x00-\x1F\x7F]/u', '', $v));
    if (mb_strlen($v, 'UTF-8') > 100) {
        $v = mb_substr($v, 0, 100, 'UTF-8');
    }
    return $v === '' ? 'Mac' : $v;
}

function b64url(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

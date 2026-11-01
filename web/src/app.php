<?php
declare(strict_types=1);

function prefunk_config(): array
{
    static $config;
    if ($config === null) {
        $path = dirname(__DIR__) . '/config.php';
        if (!is_file($path)) {
            throw new RuntimeException('Missing config.php. Copy config.example.php and fill it in.');
        }
        $config = require $path;
    }
    return $config;
}

function db(): PDO
{
    static $pdo;
    if ($pdo === null) {
        $c = prefunk_config()['db'];
        $pdo = new PDO($c['dsn'], $c['user'], $c['password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    }
    return $pdo;
}

function boot_session(): void
{
    $c = prefunk_config()['session'];
    session_name($c['name']);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (bool)$c['secure'],
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    session_start();
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('X-Frame-Options: DENY');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
    header('Cache-Control: no-store');
}

function user(): ?array
{
    if (empty($_SESSION['user_id'])) return null;
    $stmt = db()->prepare('SELECT id, email, created_at FROM users WHERE id = ?');
    $stmt->execute([(int)$_SESSION['user_id']]);
    return $stmt->fetch() ?: null;
}

function require_user(): array
{
    $current = user();
    if (!$current) {
        flash('Please sign in to continue.', 'notice');
        redirect('/login');
    }
    return $current;
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}

function verify_csrf(): void
{
    $token = $_POST['_csrf'] ?? ($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
    if (!is_string($token) || !hash_equals($_SESSION['csrf'] ?? '', $token)) {
        http_response_code(419);
        exit('This form expired. Go back, refresh, and try again.');
    }
}

function json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

function flash(string $message, string $type = 'notice'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

function take_flash(): ?array
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    return $flash;
}

function redirect(string $path): never
{
    header('Location: ' . $path, true, 303);
    exit;
}

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function route(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
    $path = is_string($path) ? rtrim($path, '/') : '/';
    return $path === '' ? '/' : $path;
}

function enforce_rate_limit(string $key, int $maxHits, int $windowSeconds): bool
{
    $bucket = hash('sha256', $key);
    $pdo = db();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare('SELECT hits, window_started_at FROM rate_limits WHERE bucket_key = ? FOR UPDATE');
        $stmt->execute([$bucket]);
        $row = $stmt->fetch();
        $expired = !$row || strtotime($row['window_started_at']) < time() - $windowSeconds;
        if ($expired) {
            $stmt = $pdo->prepare(
                'INSERT INTO rate_limits (bucket_key, hits, window_started_at) VALUES (?, 1, NOW())
                 ON DUPLICATE KEY UPDATE hits = 1, window_started_at = NOW()'
            );
            $stmt->execute([$bucket]);
            $allowed = true;
        } elseif ((int)$row['hits'] >= $maxHits) {
            $allowed = false;
        } else {
            $stmt = $pdo->prepare('UPDATE rate_limits SET hits = hits + 1 WHERE bucket_key = ?');
            $stmt->execute([$bucket]);
            $allowed = true;
        }
        $pdo->commit();
        return $allowed;
    } catch (Throwable $error) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $error;
    }
}

<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');

$cspNonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self' 'nonce-$cspNonce' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'");
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
}

function loadEnv($path) {
    if (!file_exists($path)) {
        throw new Exception("Fichier .env introuvable: $path");
    }
    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        [$key, $value] = array_pad(explode('=', $line, 2), 2, '');
        $key = trim($key);
        $value = trim($value);
        $value = trim($value, "\"'");
        putenv($key . '=' . $value);
    }
}

loadEnv(__DIR__ . '/../../.env');

define('GOOGLE_CLIENT_ID',     getenv('GOOGLE_CLIENT_ID') ?: '');
define('GOOGLE_CLIENT_SECRET', getenv('GOOGLE_CLIENT_SECRET') ?: '');
define('GOOGLE_REDIRECT_URI',  getenv('GOOGLE_REDIRECT_URI') ?: 'https://notekeep.alwaysdata.net/google-oauth');

function csrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrfCheck() {
    $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $sent)) {
        http_response_code(403);
        echo json_encode(['error' => 'Requête invalide (CSRF)']);
        exit;
    }
}

$host = getenv('DB_HOST');
$port = getenv('DB_PORT') ?: '3306';
$db   = getenv('DB_NAME');
$user = getenv('DB_USER');
$pass = getenv('DB_PASSWORD');

try {
    // Connexion via socket Unix si DB_HOST commence par '/'
    if ($host && $host[0] === '/') {
        $dsn = "mysql:unix_socket=$host;dbname=$db;charset=utf8mb4";
    } else {
        $dsn = "mysql:host=$host;port=$port;dbname=$db;charset=utf8mb4";
    }
    $pdo = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    error_log('Connexion DB échouée: ' . $e->getMessage());
    http_response_code(500);
    die(json_encode(['error' => $e->getMessage()]));
}
function clientIp() {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function rateLimited(PDO $pdo, string $action, int $maxAttempts, int $windowSeconds): bool {
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM auth_attempts
         WHERE ip = :ip AND action = :action
         AND created_at > (NOW() - INTERVAL :window SECOND)"
    );
    $stmt->bindValue(':ip', clientIp());
    $stmt->bindValue(':action', $action);
    $stmt->bindValue(':window', $windowSeconds, PDO::PARAM_INT);
    $stmt->execute();
    return (int)$stmt->fetchColumn() >= $maxAttempts;
}

function rateLimitedByIdentifier(PDO $pdo, string $action, string $identifier, int $maxAttempts, int $windowSeconds): bool {
    $hash = hash('sha256', strtolower($identifier));
    $stmt = $pdo->prepare(
        "SELECT COUNT(*) FROM auth_attempts
         WHERE identifier_hash = :hash AND action = :action
         AND created_at > (NOW() - INTERVAL :window SECOND)"
    );
    $stmt->bindValue(':hash', $hash);
    $stmt->bindValue(':action', $action);
    $stmt->bindValue(':window', $windowSeconds, PDO::PARAM_INT);
    $stmt->execute();
    return (int)$stmt->fetchColumn() >= $maxAttempts;
}

function recordAttempt(PDO $pdo, string $action, ?string $identifier = null): void {
    $hash = $identifier !== null ? hash('sha256', strtolower($identifier)) : null;
    $stmt = $pdo->prepare(
        "INSERT INTO auth_attempts (ip, action, identifier_hash) VALUES (:ip, :action, :hash)"
    );
    $stmt->execute([':ip' => clientIp(), ':action' => $action, ':hash' => $hash]);
}

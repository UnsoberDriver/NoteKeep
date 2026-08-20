<?php
// --- Normalise HTTPS derrière le proxy d'alwaysdata ---
// alwaysdata termine le HTTPS en amont et transmet en HTTP en interne,
// donc $_SERVER['HTTPS'] est absent même si le visiteur est en https://.
// On le déduit du header envoyé par le proxy.
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}

// --- En-têtes de sécurité (envoyés sur chaque requête passant par config.php) ---
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Charge les variables depuis le fichier .env situé un niveau au-dessus de htdocs
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
        $value = trim($value, "\"'"); // retire les guillemets éventuels
        putenv($key . '=' . $value);
    }
}

// htdocs/config.php -> ../.env (un dossier au-dessus de htdocs)
loadEnv(__DIR__ . '/../.env');

// --- Protection CSRF ---
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
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$db;charset=utf8mb4", $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    error_log('Connexion DB échouée: ' . $e->getMessage());
    http_response_code(500);
    die(json_encode(['error' => 'Erreur serveur, réessayez plus tard.']));
}

$pdo->exec("CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
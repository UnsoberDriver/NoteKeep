<?php
// Normalise HTTPS derrière le proxy d'alwaysdata (voir config.php)
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();
require __DIR__ . '/config.php';
header('Content-Type: application/json; charset=utf-8');

$action = $_GET['action'] ?? '';
$data = json_decode(file_get_contents('php://input'), true) ?? [];

try {
    if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();

        // Anti brute-force / anti spam sur les inscriptions (par IP)
        $_SESSION['register_attempts'] = $_SESSION['register_attempts'] ?? [];
        $now = time();
        $_SESSION['register_attempts'] = array_filter($_SESSION['register_attempts'], fn($t) => $t > $now - 3600);
        if (count($_SESSION['register_attempts']) >= 5) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez plus tard.']);
            exit;
        }

        $username = trim($data['username'] ?? '');
        $email    = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';

        if ($username === '' || $email === '' || $password === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Champs requis manquants']);
            exit;
        }
        if (strlen($password) < 8 || strlen($password) > 72) {
            http_response_code(400);
            echo json_encode(['error' => 'Le mot de passe doit faire entre 8 et 72 caractères']);
            exit;
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            http_response_code(400);
            echo json_encode(['error' => 'Email invalide']);
            exit;
        }
        if (!preg_match('/^[a-zA-Z0-9_.-]{3,50}$/', $username)) {
            http_response_code(400);
            echo json_encode(['error' => 'Nom d\'utilisateur invalide (3-50 caractères, lettres/chiffres/._-)']);
            exit;
        }

        $check = $pdo->prepare("SELECT id FROM users WHERE username = :u OR email = :e");
        $check->execute([':u' => $username, ':e' => $email]);
        if ($check->fetch()) {
            $_SESSION['register_attempts'][] = $now;
            http_response_code(409);
            echo json_encode(['error' => 'Inscription impossible avec ces informations.']);
            exit;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (:u, :e, :p)");
        $stmt->execute([':u' => $username, ':e' => $email, ':p' => $hash]);

        $userId = $pdo->lastInsertId();
        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $username;

        echo json_encode(['id' => $userId, 'username' => $username, 'email' => $email]);
        exit;
    }

    if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();
        $identifier = trim($data['identifier'] ?? '');
        $password   = $data['password'] ?? '';

        // Anti brute-force basique par IP
        $_SESSION['login_attempts'] = $_SESSION['login_attempts'] ?? [];
        $now = time();
        $_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'], fn($t) => $t > $now - 60);
        if (count($_SESSION['login_attempts']) >= 10) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez dans une minute.']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :i OR email = :i");
        $stmt->execute([':i' => $identifier]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            $_SESSION['login_attempts'][] = $now;
            http_response_code(401);
            echo json_encode(['error' => 'Identifiants invalides']);
            exit;
        }

        unset($_SESSION['login_attempts']);
        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];

        echo json_encode(['id' => $user['id'], 'username' => $user['username'], 'email' => $user['email']]);
        exit;
    }

    if ($action === 'csrf_token' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        echo json_encode(['token' => csrfToken()]);
        exit;
    }

    if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();
        $_SESSION = [];
        session_destroy();
        echo json_encode(['ok' => true]);
        exit;
    }

    if ($action === 'me' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Non connecté']);
            exit;
        }
        echo json_encode(['id' => $_SESSION['user_id'], 'username' => $_SESSION['username']]);
        exit;
    }

    http_response_code(404);
    echo json_encode(['error' => 'Action inconnue']);

} catch (Exception $e) {
    error_log('auth.php error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur, réessayez plus tard.']);
}
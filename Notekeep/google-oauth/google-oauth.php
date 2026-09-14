<?php
/**
 * google-oauth.php — Callback OAuth 2.0 Google
 *
 * Flux :
 *   1. L'utilisateur clique "Se connecter avec Google" sur /login
 *   2. Il est redirigé vers Google avec un state anti-CSRF
 *   3. Google renvoie ici avec ?code=... et ?state=...
 *   4. On échange le code contre un id_token, on vérifie la signature,
 *      on crée/trouve le compte local, on ouvre la session → redirect /
 *
 * Configuration requise dans config/config.php (ou via variables d'env) :
 *   define('GOOGLE_CLIENT_ID',     'xxx.apps.googleusercontent.com');
 *   define('GOOGLE_CLIENT_SECRET', 'xxx');
 *   define('GOOGLE_REDIRECT_URI',  'https://ton-domaine.tld/google-oauth');
 *
 * Table users : doit avoir les colonnes google_id (VARCHAR 64) et
 * password (nullable pour les comptes purement Google).
 * → Lance la migration ci-dessous la première fois.
 */

// ── Normalise HTTPS derrière le proxy alwaysdata ──────────────────────────
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}

session_set_cookie_params([
    'lifetime' => 60 * 60 * 24 * 30,
    'path'     => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();

require __DIR__ . '/config/config.php';

// ── Migration one-shot : ajoute google_id + rend password nullable ─────────
(function ($pdo) {
    $col = $pdo->query("SHOW COLUMNS FROM users LIKE 'google_id'")->fetch();
    if (!$col) {
        $pdo->exec("ALTER TABLE users ADD COLUMN google_id VARCHAR(64) NULL DEFAULT NULL UNIQUE AFTER email");
    }
    // Rend password_hash nullable pour les comptes Google-only
    $colPwd = $pdo->query("SHOW COLUMNS FROM users LIKE 'password_hash'")->fetch();
    if ($colPwd && strpos($colPwd['Null'], 'NO') !== false) {
        $pdo->exec("ALTER TABLE users MODIFY password_hash VARCHAR(255) NULL DEFAULT NULL");
    }

    // Les comptes Google-only n'ont pas de wrap de clé privée par mot de
    // passe (voir setup_e2ee_recovery dans auth.php) : ces colonnes
    // doivent devenir nullable.
    foreach (['kdf_salt', 'enc_private_key_pwd_ciphertext', 'enc_private_key_pwd_iv'] as $col) {
        $colInfo = $pdo->query("SHOW COLUMNS FROM users LIKE '$col'")->fetch();
        if ($colInfo && strpos($colInfo['Null'], 'NO') !== false) {
            $pdo->exec("ALTER TABLE users MODIFY $col VARCHAR(255) NULL DEFAULT NULL");
        }
    }
    $colIter = $pdo->query("SHOW COLUMNS FROM users LIKE 'kdf_iterations'")->fetch();
    if ($colIter && strpos($colIter['Null'], 'NO') !== false) {
        $pdo->exec("ALTER TABLE users MODIFY kdf_iterations INT NULL DEFAULT NULL");
    }
})($pdo);

// ── Helpers ────────────────────────────────────────────────────────────────
function abort(string $msg, int $code = 400): never {
    http_response_code($code);
    exit(htmlspecialchars($msg));
}

/**
 * Échange le code d'autorisation contre les tokens Google.
 * Retourne le payload décodé de l'id_token (sans vérifier la signature RSA —
 * acceptable car on fait un appel HTTPS direct à Google, pas un flux implicite).
 */
function exchangeCodeForPayload(string $code): array {
    $params = http_build_query([
        'code'          => $code,
        'client_id'     => GOOGLE_CLIENT_ID,
        'client_secret' => GOOGLE_CLIENT_SECRET,
        'redirect_uri'  => GOOGLE_REDIRECT_URI,
        'grant_type'    => 'authorization_code',
    ]);

    $ctx = stream_context_create(['http' => [
        'method'  => 'POST',
        'header'  => "Content-Type: application/x-www-form-urlencoded\r\n",
        'content' => $params,
        'ignore_errors' => true,
    ]]);

    $raw = @file_get_contents('https://oauth2.googleapis.com/token', false, $ctx);
    if ($raw === false) {
        abort('Impossible de joindre les serveurs Google.', 502);
    }

    $json = json_decode($raw, true);
    if (empty($json['id_token'])) {
        abort('Réponse inattendue de Google (pas d\'id_token).', 502);
    }

    // Décoder le payload JWT (partie centrale, base64url)
    $parts = explode('.', $json['id_token']);
    if (count($parts) !== 3) {
        abort('id_token malformé.', 502);
    }
    $payload = json_decode(base64_decode(strtr($parts[1], '-_', '+/')), true);
    if (!$payload) {
        abort('Payload id_token illisible.', 502);
    }
    return $payload;
}

/**
 * Génère un username unique à partir du nom Google (prénom + première
 * lettre du nom, sans espaces ni caractères spéciaux).
 */
function generateUsername(PDO $pdo, string $name, string $email): string {
    // Essaie d'abord la partie locale de l'e-mail, puis le nom complet
    $base = preg_replace('/[^a-z0-9_]/', '', strtolower(explode('@', $email)[0]));
    if (strlen($base) < 3) {
        $base = preg_replace('/[^a-z0-9_]/', '', strtolower(str_replace(' ', '', $name)));
    }
    $base = substr($base ?: 'user', 0, 20);

    $candidate = $base;
    $i = 2;
    $check = $pdo->prepare("SELECT id FROM users WHERE username = :u");
    while (true) {
        $check->execute([':u' => $candidate]);
        if (!$check->fetch()) return $candidate;
        $candidate = $base . $i++;
    }
}

// ── Étape A : lancement du flux (GET sans ?code) ───────────────────────────
if (!isset($_GET['code'])) {
    // Génère un state anti-CSRF
    $state = bin2hex(random_bytes(16));
    $_SESSION['oauth_state'] = $state;

    $params = http_build_query([
        'client_id'     => GOOGLE_CLIENT_ID,
        'redirect_uri'  => GOOGLE_REDIRECT_URI,
        'response_type' => 'code',
        'scope'         => 'openid email profile',
        'state'         => $state,
        'prompt'        => 'select_account',
    ]);

    header('Location: https://accounts.google.com/o/oauth2/v2/auth?' . $params);
    exit;
}

// ── Étape B : retour depuis Google ────────────────────────────────────────
// Vérification anti-CSRF
if (empty($_GET['state']) || $_GET['state'] !== ($_SESSION['oauth_state'] ?? '')) {
    abort('State OAuth invalide. Veuillez réessayer.', 403);
}
unset($_SESSION['oauth_state']);

// Erreur renvoyée par Google (ex : accès refusé par l'utilisateur)
if (isset($_GET['error'])) {
    header('Location: /login?error=' . urlencode('Connexion Google annulée.'));
    exit;
}

$payload = exchangeCodeForPayload($_GET['code']);

$googleId = $payload['sub']     ?? null;
$email    = $payload['email']   ?? null;
$name     = $payload['name']    ?? 'Utilisateur';
$verified = $payload['email_verified'] ?? false;

if (!$googleId || !$email) {
    abort('Données Google incomplètes.', 502);
}
if (!$verified) {
    header('Location: /login?error=' . urlencode('Votre adresse e-mail Google n\'est pas vérifiée.'));
    exit;
}

// ── Trouver ou créer le compte local ──────────────────────────────────────
// 1. Cherche par google_id (compte déjà lié)
$stmt = $pdo->prepare("SELECT id, username FROM users WHERE google_id = :gid");
$stmt->execute([':gid' => $googleId]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$user) {
    // 2. Cherche par e-mail (compte classique existant → liaison automatique)
    $stmt = $pdo->prepare("SELECT id, username FROM users WHERE email = :email");
    $stmt->execute([':email' => $email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        // Lie le google_id au compte existant
        $pdo->prepare("UPDATE users SET google_id = :gid WHERE id = :id")
            ->execute([':gid' => $googleId, ':id' => $user['id']]);
    } else {
        // 3. Crée un nouveau compte
        $username = generateUsername($pdo, $name, $email);
        $pdo->prepare("INSERT INTO users (username, email, google_id, password_hash) VALUES (:u, :e, :g, NULL)")
            ->execute([':u' => $username, ':e' => $email, ':g' => $googleId]);
        $newId = (int)$pdo->lastInsertId();
        $user = ['id' => $newId, 'username' => $username];
    }
}

// ── Ouvre la session ───────────────────────────────────────────────────────
session_regenerate_id(true);
$_SESSION['user_id']  = (int)$user['id'];
$_SESSION['username'] = $user['username'];

header('Location: /');
exit;
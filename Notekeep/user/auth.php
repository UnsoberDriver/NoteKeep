<?php
// N'accepte X-Forwarded-Proto que si la connexion vient d'un proxy de confiance.
// Sans cette vérification, n'importe quel visiteur peut forcer HTTPS='on'
// et obtenir un cookie session marqué 'secure' sur une connexion HTTP claire.
(function () {
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    $raw = getenv('TRUSTED_PROXY_IPS') ?: '';
    $trustedIps = array_filter(array_map('trim', explode(',', $raw)));
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])
        && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'
        && $remote !== ''
        && in_array($remote, $trustedIps, true)
    ) {
        $_SERVER['HTTPS'] = 'on';
    }
})();
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();
require __DIR__ . '/../config/config.php';
header('Content-Type: application/json; charset=utf-8');

$action = $_GET['action'] ?? '';
$data = json_decode(file_get_contents('php://input'), true) ?? [];

try {
    if ($action === 'register' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();

        if (trim($data['website'] ?? '') !== '') {
            error_log('Honeypot déclenché (register) - IP: ' . clientIp());
            echo json_encode(['id' => 0, 'username' => '', 'email' => '']);
            exit;
        }

        if (rateLimited($pdo, 'register', 5, 3600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez plus tard.']);
            exit;
        }

        $turnstileToken = $data['turnstileToken'] ?? '';
        if (!verifyTurnstile($turnstileToken)) {
            http_response_code(400);
            echo json_encode(['error' => 'Vérification anti-bot échouée. Réessayez.']);
            exit;
        }

        $username = trim($data['username'] ?? '');
        $email    = trim($data['email'] ?? '');
        $password = $data['password'] ?? '';

        $publicKey           = $data['public_key'] ?? '';
        $kdfSalt              = $data['kdf_salt'] ?? '';
        $kdfIterations         = (int)($data['kdf_iterations'] ?? 0);
        $encPwdCiphertext      = $data['enc_private_key_pwd']['ciphertext'] ?? '';
        $encPwdIv              = $data['enc_private_key_pwd']['iv'] ?? '';
        $encRecoveryCiphertext = $data['enc_private_key_recovery']['ciphertext'] ?? '';
        $encRecoveryIv         = $data['enc_private_key_recovery']['iv'] ?? '';

        if ($username === '' || $email === '' || $password === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Champs requis manquants']);
            exit;
        }
        if ($publicKey === '' || $kdfSalt === '' || $kdfIterations <= 0
            || $encPwdCiphertext === '' || $encPwdIv === ''
            || $encRecoveryCiphertext === '' || $encRecoveryIv === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Données de chiffrement manquantes']);
            exit;
        }
        if (strlen($password) < 8 || strlen($password) > 72) {
            http_response_code(400);
            echo json_encode(['error' => 'Le mot de passe doit faire entre 8 et 72 caractères']);
            exit;
        }
        if (strlen($email) > 255) {
            http_response_code(400);
            echo json_encode(['error' => 'Email trop long (255 caractères max)']);
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
            recordAttempt($pdo, 'register', $email);
            http_response_code(409);
            echo json_encode(['error' => 'Inscription impossible avec ces informations.']);
            exit;
        }

        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users
            (username, email, password_hash, public_key, kdf_salt, kdf_iterations,
             enc_private_key_pwd_ciphertext, enc_private_key_pwd_iv,
             enc_private_key_recovery_ciphertext, enc_private_key_recovery_iv, e2ee_enabled)
            VALUES (:u, :e, :p, :pub, :salt, :iter, :epc, :epi, :erc, :eri, 1)");
        $stmt->execute([
            ':u' => $username, ':e' => $email, ':p' => $hash,
            ':pub' => $publicKey, ':salt' => $kdfSalt, ':iter' => $kdfIterations,
            ':epc' => $encPwdCiphertext, ':epi' => $encPwdIv,
            ':erc' => $encRecoveryCiphertext, ':eri' => $encRecoveryIv,
        ]);

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

        if (trim($data['website'] ?? '') !== '') {
            error_log('Honeypot déclenché (login) - IP: ' . clientIp());
            http_response_code(401);
            echo json_encode(['error' => 'Identifiants invalides']);
            exit;
        }

        if (rateLimited($pdo, 'login', 10, 60)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez dans une minute.']);
            exit;
        }
        if ($identifier !== '' && rateLimitedByIdentifier($pdo, 'login', $identifier, 10, 300)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives sur ce compte, réessayez plus tard.']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = :i OR email = :i");
        $stmt->execute([':i' => $identifier]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            recordAttempt($pdo, 'login', $identifier !== '' ? $identifier : null);
            http_response_code(401);
            echo json_encode(['error' => 'Identifiants invalides']);
            exit;
        }

        session_regenerate_id(true);
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];

        echo json_encode([
            'id' => $user['id'],
            'username' => $user['username'],
            'email' => $user['email'],
            'e2ee' => [
                'public_key' => $user['public_key'],
                'kdf_salt' => $user['kdf_salt'],
                'kdf_iterations' => (int)$user['kdf_iterations'],
                'enc_private_key_pwd' => [
                    'ciphertext' => $user['enc_private_key_pwd_ciphertext'],
                    'iv' => $user['enc_private_key_pwd_iv'],
                ],
            ],
        ]);
        exit;
    }

    // --- Étape 1 : demande d'OTP par email ---
    // L'utilisateur entre son identifiant, on génère un OTP à 6 chiffres,
    // on le stocke hashé en base (valable 15 min), et on envoie l'email.
    if ($action === 'request_otp' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();

        if (rateLimited($pdo, 'request_otp', 3, 600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez plus tard.']);
            exit;
        }

        $identifier = trim($data['identifier'] ?? '');
        if ($identifier === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Identifiant requis']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id, email, username FROM users WHERE username = :i OR email = :i");
        $stmt->execute([':i' => $identifier]);
        $user = $stmt->fetch();

        // Réponse identique que l'utilisateur existe ou non (évite l'énumération).
        if (!$user) {
            recordAttempt($pdo, 'request_otp', $identifier);
            echo json_encode(['ok' => true]);
            exit;
        }

        // Génère un OTP à 6 chiffres cryptographiquement sûr.
        $otp = str_pad((string)random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $otpHash = hash('sha256', $otp);
        $expiresAt = date('Y-m-d H:i:s', time() + 900); // 15 minutes

        // Invalide les OTP précédents pour ce compte.
        $pdo->prepare("UPDATE password_resets SET used = 1 WHERE user_id = :uid")
            ->execute([':uid' => $user['id']]);

        $pdo->prepare("INSERT INTO password_resets (user_id, otp_hash, expires_at) VALUES (:uid, :hash, :exp)")
            ->execute([':uid' => $user['id'], ':hash' => $otpHash, ':exp' => $expiresAt]);

        $sent = sendOtpEmail($user['email'], $user['username'], $otp);
        if (!$sent) {
            http_response_code(500);
            echo json_encode(['error' => 'Impossible d\'envoyer l\'email. Réessayez.']);
            exit;
        }

        echo json_encode(['ok' => true]);
        exit;
    }

    // --- Étape 2 : reset avec OTP vérifié ---
    // Le client a déchiffré la clé privée côté client avec la recovery key
    // stockée côté serveur (déverrouillée via l'OTP), et renvoie ici la
    // clé privée re-chiffrée avec le nouveau mot de passe.
    if ($action === 'reset_with_otp' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();

        if (rateLimited($pdo, 'reset_otp', 3, 3600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez plus tard.']);
            exit;
        }

        $identifier  = trim($data['identifier'] ?? '');
        $otp         = trim($data['otp'] ?? '');
        $newPassword = $data['new_password'] ?? '';
        $newSalt     = $data['kdf_salt'] ?? '';
        $newIter     = (int)($data['kdf_iterations'] ?? 0);
        $newCipher   = $data['enc_private_key_pwd']['ciphertext'] ?? '';
        $newIv       = $data['enc_private_key_pwd']['iv'] ?? '';
        // Présents uniquement si le client a généré une NOUVELLE paire de
        // clés (reset sans recovery key) : il faut alors aussi mettre à
        // jour public_key et le wrap recovery, sinon public_key reste
        // désynchronisée de la nouvelle clé privée et le déchiffrement
        // échoue silencieusement pour toutes les notes.
        $newPublicKey       = $data['public_key'] ?? null;
        $newEncRecoveryCt   = $data['enc_private_key_recovery']['ciphertext'] ?? null;
        $newEncRecoveryIv   = $data['enc_private_key_recovery']['iv'] ?? null;

        if ($identifier === '' || strlen($otp) !== 6 || strlen($newPassword) < 8 || strlen($newPassword) > 72
            || $newSalt === '' || $newIter <= 0 || $newCipher === '' || $newIv === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Champs requis manquants ou invalides']);
            exit;
        }

        // Limite les tentatives de brute-force de l'OTP sur ce compte,
        // en plus de la limite par IP (qui reste contournable via X-Forwarded-For).
        if (rateLimitedByIdentifier($pdo, 'reset_otp', $identifier, 3, 3600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives sur ce compte, réessayez plus tard.']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :i OR email = :i");
        $stmt->execute([':i' => $identifier]);
        $user = $stmt->fetch();
        if (!$user) {
            recordAttempt($pdo, 'reset_otp', $identifier);
            http_response_code(400);
            echo json_encode(['error' => 'Réinitialisation impossible.']);
            exit;
        }

        $otpHash = hash('sha256', $otp);
        $reset = $pdo->prepare("SELECT id FROM password_resets
            WHERE user_id = :uid AND otp_hash = :hash AND used = 0 AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1");
        $reset->execute([':uid' => $user['id'], ':hash' => $otpHash]);
        $resetRow = $reset->fetch();

        if (!$resetRow) {
            recordAttempt($pdo, 'reset_otp', $identifier);
            http_response_code(400);
            echo json_encode(['error' => 'Code invalide ou expiré.']);
            exit;
        }

        // Invalide l'OTP utilisé.
        $pdo->prepare("UPDATE password_resets SET used = 1 WHERE id = :id")
            ->execute([':id' => $resetRow['id']]);

        $newHash = password_hash($newPassword, PASSWORD_DEFAULT);

        if ($newPublicKey !== null && $newEncRecoveryCt !== null && $newEncRecoveryIv !== null) {
            // Nouvelle paire de clés générée côté client : public_key et le
            // wrap recovery doivent être remplacés en même temps que le wrap
            // mot de passe, sinon ils restent liés à l'ancienne paire.
            $pdo->prepare("UPDATE users SET
                password_hash = :hash, kdf_salt = :salt, kdf_iterations = :iter,
                enc_private_key_pwd_ciphertext = :epc, enc_private_key_pwd_iv = :epi,
                public_key = :pub,
                enc_private_key_recovery_ciphertext = :erc, enc_private_key_recovery_iv = :eri
                WHERE id = :id")
                ->execute([
                    ':hash' => $newHash, ':salt' => $newSalt, ':iter' => $newIter,
                    ':epc' => $newCipher, ':epi' => $newIv,
                    ':pub' => $newPublicKey,
                    ':erc' => $newEncRecoveryCt, ':eri' => $newEncRecoveryIv,
                    ':id' => $user['id'],
                ]);
        } else {
            $pdo->prepare("UPDATE users SET
                password_hash = :hash, kdf_salt = :salt, kdf_iterations = :iter,
                enc_private_key_pwd_ciphertext = :epc, enc_private_key_pwd_iv = :epi
                WHERE id = :id")
                ->execute([
                    ':hash' => $newHash, ':salt' => $newSalt, ':iter' => $newIter,
                    ':epc' => $newCipher, ':epi' => $newIv, ':id' => $user['id'],
                ]);
        }

        echo json_encode(['ok' => true]);
        exit;
    }

    // --- Récupération du blob E2EE pour le reset via OTP ---
    // Retourne enc_private_key_recovery pour que le client puisse déchiffrer
    // la clé privée avec la recovery key (stockée côté client via l'OTP).
    if ($action === 'recovery_blob_otp' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();

        if (rateLimited($pdo, 'recovery_blob', 3, 3600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez plus tard.']);
            exit;
        }

        $identifier = trim($data['identifier'] ?? '');
        $otp        = trim($data['otp'] ?? '');

        if ($identifier === '' || strlen($otp) !== 6) {
            http_response_code(400);
            echo json_encode(['error' => 'Paramètres manquants']);
            exit;
        }

        if (rateLimitedByIdentifier($pdo, 'recovery_blob', $identifier, 3, 3600)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives sur ce compte, réessayez plus tard.']);
            exit;
        }

        $stmt = $pdo->prepare("SELECT id, enc_private_key_recovery_ciphertext, enc_private_key_recovery_iv, public_key
            FROM users WHERE username = :i OR email = :i");
        $stmt->execute([':i' => $identifier]);
        $user = $stmt->fetch();
        if (!$user) {
            recordAttempt($pdo, 'recovery_blob', $identifier);
            hash('sha256', $otp); // uniformise le timing avec le cas OTP invalide
            http_response_code(400);
            echo json_encode(['error' => 'Code invalide ou expiré.']);
            exit;
        }

        $otpHash = hash('sha256', $otp);
        $reset = $pdo->prepare("SELECT id FROM password_resets
            WHERE user_id = :uid AND otp_hash = :hash AND used = 0 AND expires_at > NOW()
            ORDER BY created_at DESC LIMIT 1");
        $reset->execute([':uid' => $user['id'], ':hash' => $otpHash]);
        $resetRow = $reset->fetch();
        if (!$resetRow) {
            recordAttempt($pdo, 'recovery_blob', $identifier);
            http_response_code(400);
            echo json_encode(['error' => 'Code invalide ou expiré.']);
            exit;
        }

        // Invalide l'OTP immédiatement : ne peut pas être réutilisé pour reset_with_otp.
        $pdo->prepare("UPDATE password_resets SET used = 1 WHERE id = :id")
            ->execute([':id' => $resetRow['id']]);

        echo json_encode([
            'enc_private_key_recovery' => [
                'ciphertext' => $user['enc_private_key_recovery_ciphertext'],
                'iv'         => $user['enc_private_key_recovery_iv'],
            ],
            'public_key' => $user['public_key'],
        ]);
        exit;
    }

    // SUPPRIMÉ (faille critique de contournement d'authentification) :
    // l'ancien endpoint 'reset_with_recovery' changeait le mot de passe de
    // n'importe quel compte (identifier + new_password arbitraires) SANS
    // jamais vérifier que l'appelant possédait réellement la recovery key.
    // Le seul flux de réinitialisation supporté est désormais celui basé
    // sur l'OTP envoyé par email (voir 'request_otp' / 'reset_with_otp'),
    // qui est vérifiable côté serveur via otp_hash.
    if ($action === 'reset_with_recovery') {
        http_response_code(410);
        echo json_encode(['error' => 'Cette méthode de réinitialisation n\'est plus disponible. Utilisez la réinitialisation par code envoyé par email.']);
        exit;
    }

    // SUPPRIMÉ (divulgation non authentifiée) : l'ancien endpoint
    // 'recovery_blob' renvoyait le blob chiffré enc_private_key_recovery
    // et la clé publique de N'IMPORTE QUEL compte à quiconque connaissait
    // son identifiant, sans aucune authentification ni OTP, et permettait
    // en plus l'énumération de comptes (404 vs 200). Utilisez
    // 'recovery_blob_otp', qui exige un OTP valide avant de servir ce blob.
    if ($action === 'recovery_blob') {
        http_response_code(410);
        echo json_encode(['error' => 'Cette méthode n\'est plus disponible. Utilisez la réinitialisation par code envoyé par email.']);
        exit;
    }

    // --- E2EE pour comptes sans mot de passe (connexion Google) ---
    // Même principe que setup_e2ee, mais on ne fournit qu'un wrap par
    // recovery key : il n'y a pas de mot de passe à dériver. La recovery
    // key est générée côté client et doit être conservée sur l'appareil
    // (voir front-end) puisqu'elle n'est jamais envoyée au serveur.
    if ($action === 'setup_e2ee_recovery' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Non connecté']);
            exit;
        }
        $check = $pdo->prepare("SELECT public_key FROM users WHERE id = :id");
        $check->execute([':id' => $_SESSION['user_id']]);
        if ($check->fetchColumn()) {
            http_response_code(409);
            echo json_encode(['error' => 'Chiffrement déjà configuré pour ce compte']);
            exit;
        }

        $publicKey             = $data['public_key'] ?? '';
        $encRecoveryCiphertext = $data['enc_private_key_recovery']['ciphertext'] ?? '';
        $encRecoveryIv         = $data['enc_private_key_recovery']['iv'] ?? '';

        if ($publicKey === '' || $encRecoveryCiphertext === '' || $encRecoveryIv === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Données de chiffrement manquantes']);
            exit;
        }

        $upd = $pdo->prepare("UPDATE users SET
            public_key = :pub,
            enc_private_key_recovery_ciphertext = :erc, enc_private_key_recovery_iv = :eri,
            e2ee_enabled = 1
            WHERE id = :id");
        $upd->execute([
            ':pub' => $publicKey,
            ':erc' => $encRecoveryCiphertext, ':eri' => $encRecoveryIv,
            ':id' => $_SESSION['user_id'],
        ]);

        echo json_encode(['ok' => true]);
        exit;
    }

    // Permet au front de savoir, juste après connexion (Google ou classique),
    // si l'E2EE est déjà configuré pour ce compte et avec quelle méthode.
    if ($action === 'e2ee_status' && $_SERVER['REQUEST_METHOD'] === 'GET') {
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Non connecté']);
            exit;
        }
        $stmt = $pdo->prepare("SELECT public_key, kdf_salt, kdf_iterations,
            enc_private_key_pwd_ciphertext, enc_private_key_pwd_iv,
            enc_private_key_recovery_ciphertext, enc_private_key_recovery_iv,
            password_hash
            FROM users WHERE id = :id");
        $stmt->execute([':id' => $_SESSION['user_id']]);
        $user = $stmt->fetch();
        if (!$user) {
            http_response_code(404);
            echo json_encode(['error' => 'Utilisateur introuvable']);
            exit;
        }

        $hasE2ee = !empty($user['public_key']);
        $hasPasswordWrap = !empty($user['enc_private_key_pwd_ciphertext']);

        echo json_encode([
            'e2ee_configured' => $hasE2ee,
            'has_password' => !empty($user['password_hash']),
            'public_key' => $user['public_key'],
            'kdf_salt' => $user['kdf_salt'],
            'kdf_iterations' => $user['kdf_iterations'] !== null ? (int)$user['kdf_iterations'] : null,
            'enc_private_key_pwd' => $hasPasswordWrap ? [
                'ciphertext' => $user['enc_private_key_pwd_ciphertext'],
                'iv' => $user['enc_private_key_pwd_iv'],
            ] : null,
            'enc_private_key_recovery' => !empty($user['enc_private_key_recovery_ciphertext']) ? [
                'ciphertext' => $user['enc_private_key_recovery_ciphertext'],
                'iv' => $user['enc_private_key_recovery_iv'],
            ] : null,
        ]);
        exit;
    }

    if ($action === 'setup_e2ee' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Non connecté']);
            exit;
        }
        $check = $pdo->prepare("SELECT public_key FROM users WHERE id = :id");
        $check->execute([':id' => $_SESSION['user_id']]);
        if ($check->fetchColumn()) {
            http_response_code(409);
            echo json_encode(['error' => 'Chiffrement déjà configuré pour ce compte']);
            exit;
        }

        $publicKey             = $data['public_key'] ?? '';
        $kdfSalt                = $data['kdf_salt'] ?? '';
        $kdfIterations           = (int)($data['kdf_iterations'] ?? 0);
        $encPwdCiphertext        = $data['enc_private_key_pwd']['ciphertext'] ?? '';
        $encPwdIv                = $data['enc_private_key_pwd']['iv'] ?? '';
        $encRecoveryCiphertext   = $data['enc_private_key_recovery']['ciphertext'] ?? '';
        $encRecoveryIv           = $data['enc_private_key_recovery']['iv'] ?? '';

        if ($publicKey === '' || $kdfSalt === '' || $kdfIterations <= 0
            || $encPwdCiphertext === '' || $encPwdIv === ''
            || $encRecoveryCiphertext === '' || $encRecoveryIv === '') {
            http_response_code(400);
            echo json_encode(['error' => 'Données de chiffrement manquantes']);
            exit;
        }

        $upd = $pdo->prepare("UPDATE users SET
            public_key = :pub, kdf_salt = :salt, kdf_iterations = :iter,
            enc_private_key_pwd_ciphertext = :epc, enc_private_key_pwd_iv = :epi,
            enc_private_key_recovery_ciphertext = :erc, enc_private_key_recovery_iv = :eri,
            e2ee_enabled = 1
            WHERE id = :id");
        $upd->execute([
            ':pub' => $publicKey, ':salt' => $kdfSalt, ':iter' => $kdfIterations,
            ':epc' => $encPwdCiphertext, ':epi' => $encPwdIv,
            ':erc' => $encRecoveryCiphertext, ':eri' => $encRecoveryIv,
            ':id' => $_SESSION['user_id'],
        ]);

        echo json_encode(['ok' => true]);
        exit;
    }

    if ($action === 'verify_password' && $_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();
        if (!isset($_SESSION['user_id'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Non connecté']);
            exit;
        }
        if (rateLimited($pdo, 'verify_password', 10, 60)) {
            http_response_code(429);
            echo json_encode(['error' => 'Trop de tentatives, réessayez dans une minute.']);
            exit;
        }
        $password = $data['password'] ?? '';
        $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = :id");
        $stmt->execute([':id' => $_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($password, $user['password_hash'])) {
            recordAttempt($pdo, 'verify_password', (string)$_SESSION['user_id']);
            http_response_code(401);
            echo json_encode(['error' => 'Mot de passe incorrect']);
            exit;
        }

        echo json_encode(['ok' => true]);
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
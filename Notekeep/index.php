<?php
// Normalise HTTPS derrière le proxy d'alwaysdata (voir config.php)
if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}
session_set_cookie_params([
    'lifetime' => 60 * 60 * 24 * 30,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Lax',
    'secure' => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
]);
session_start();
if (!isset($_SESSION['user_id'])) {
    // Distingue un appel API (fetch depuis le JS front-end, avec ?action=...)
    // d'une navigation classique dans le navigateur : un appel API doit
    // recevoir une vraie erreur JSON 401, pas une redirection HTML que le
    // fetch() suivrait silencieusement en essayant de parser du HTML comme
    // du JSON (ce qui échouait auparavant avec une erreur peu explicite).
    if (isset($_GET['action'])) {
        http_response_code(401);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Non connecté']);
        exit;
    }
    header('Location: /login');
    exit;
}
require __DIR__ . '/config/config.php';

// --- Migrations de schéma : ne s'exécutent qu'une seule fois, pas à
// chaque requête. Avant, ~10 CREATE/ALTER/SHOW COLUMNS tournaient sur
// CHAQUE chargement de la page, ce qui explique le TTFB de 20s constaté.
// Un fichier marqueur versionné évite de refaire ce travail tant que le
// schéma n'a pas changé (incrémenter SCHEMA_VERSION si on ajoute une
// migration ci-dessous).
const SCHEMA_VERSION = 5;
$schemaMarkerFile = __DIR__ . '/config/.schema_version';

function runSchemaMigrations($pdo) {
    $pdo->exec("CREATE TABLE IF NOT EXISTS shopping_lists (
    id INT AUTO_INCREMENT PRIMARY KEY,
    owner_id INT NOT NULL,
    name VARCHAR(100) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$pdo->exec("CREATE TABLE IF NOT EXISTS shopping_list_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    list_id INT NOT NULL,
    user_id INT NOT NULL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_list_user (list_id, user_id),
    FOREIGN KEY (list_id) REFERENCES shopping_lists(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$pdo->exec("CREATE TABLE IF NOT EXISTS courses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    list_id INT NOT NULL,
    user_id INT NOT NULL,
    label VARCHAR(255) NOT NULL,
    checked TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (list_id) REFERENCES shopping_lists(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// --- E2EE des articles : label devient optionnel (legacy), remplacé par
// un ciphertext chiffré côté client avec la clé de liste. ---
$colEnc = $pdo->query("SHOW COLUMNS FROM courses LIKE 'enc_label_ciphertext'")->fetch();
if (!$colEnc) {
    $pdo->exec("ALTER TABLE courses ADD COLUMN enc_label_ciphertext MEDIUMTEXT NULL AFTER label");
    $pdo->exec("ALTER TABLE courses ADD COLUMN enc_label_iv VARCHAR(64) NULL AFTER enc_label_ciphertext");
    $pdo->exec("ALTER TABLE courses MODIFY label VARCHAR(255) NOT NULL DEFAULT ''");
}
$colDeleted = $pdo->query("SHOW COLUMNS FROM courses LIKE 'deleted'")->fetch();
if (!$colDeleted) {
    $pdo->exec("ALTER TABLE courses ADD COLUMN deleted TINYINT(1) NOT NULL DEFAULT 0 AFTER checked");
}

// --- Clé de liste E2EE, wrappée individuellement pour chaque membre via
// ECDH (voir crypto.js: createListKey / wrapListKeyForMember / unwrapListKey).
// Le serveur ne voit jamais la clé de liste en clair.
$pdo->exec("CREATE TABLE IF NOT EXISTS list_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    list_id INT NOT NULL,
    user_id INT NOT NULL,
    enc_key_ciphertext MEDIUMTEXT NOT NULL,
    enc_key_iv VARCHAR(64) NOT NULL,
    sender_public_key TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_list_user (list_id, user_id),
    FOREIGN KEY (list_id) REFERENCES shopping_lists(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// --- Migration: anciennes installations sans list_id ---
$col = $pdo->query("SHOW COLUMNS FROM courses LIKE 'list_id'")->fetch();
if (!$col) {
    $pdo->exec("ALTER TABLE courses ADD COLUMN list_id INT NULL AFTER id");
    $usersWithCourses = $pdo->query("SELECT DISTINCT user_id FROM courses WHERE list_id IS NULL")->fetchAll(PDO::FETCH_COLUMN);
    foreach ($usersWithCourses as $uid) {
        $ins = $pdo->prepare("INSERT INTO shopping_lists (owner_id, name) VALUES (:uid, 'Courses')");
        $ins->execute([':uid' => $uid]);
        $newListId = $pdo->lastInsertId();
        $upd = $pdo->prepare("UPDATE courses SET list_id = :lid WHERE user_id = :uid AND list_id IS NULL");
        $upd->execute([':lid' => $newListId, ':uid' => $uid]);
    }
    $pdo->exec("ALTER TABLE courses MODIFY list_id INT NOT NULL");
    $pdo->exec("ALTER TABLE courses ADD CONSTRAINT fk_courses_list FOREIGN KEY (list_id) REFERENCES shopping_lists(id) ON DELETE CASCADE");
}

$pdo->exec("CREATE TABLE IF NOT EXISTS list_activity (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    list_id INT NOT NULL,
    actor_user_id INT NOT NULL,
    enc_ciphertext MEDIUMTEXT NOT NULL,
    enc_iv VARCHAR(64) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (list_id) REFERENCES shopping_lists(id) ON DELETE CASCADE,
    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_list_created (list_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$pdo->exec("CREATE TABLE IF NOT EXISTS notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    type VARCHAR(50) NOT NULL,
    payload JSON NOT NULL,
    is_read TINYINT(1) NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_user_read (user_id, is_read, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

$pdo->exec("CREATE TABLE IF NOT EXISTS notes (
    id BIGINT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '',
    pinned TINYINT(1) NOT NULL DEFAULT 0,
    deleted TINYINT(1) NOT NULL DEFAULT 0,
    color VARCHAR(20) NOT NULL DEFAULT '',
    images MEDIUMTEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
try {
    $pdo->exec("ALTER TABLE notes ADD COLUMN IF NOT EXISTS color VARCHAR(20) NOT NULL DEFAULT ''");
} catch (Exception $e) {
    // colonne déjà existante ou version MySQL ne supportant pas IF NOT EXISTS
}
try {
    $pdo->exec("ALTER TABLE notes ADD COLUMN IF NOT EXISTS images MEDIUMTEXT NOT NULL DEFAULT ''");
} catch (Exception $e) {
    // colonne déjà existante ou version MySQL ne supportant pas IF NOT EXISTS
}
try {
    $pdo->exec("ALTER TABLE notes ADD COLUMN IF NOT EXISTS protected TINYINT(1) NOT NULL DEFAULT 0");
} catch (Exception $e) {
    // colonne déjà existante ou version MySQL ne supportant pas IF NOT EXISTS
}
// --- Groupes de notes ---
$pdo->exec("CREATE TABLE IF NOT EXISTS note_groups (
    id BIGINT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
try {
    $pdo->exec("ALTER TABLE notes ADD COLUMN IF NOT EXISTS group_id BIGINT NULL DEFAULT NULL");
} catch (Exception $e) {}

// --- Documents (fichiers) ---
$pdo->exec("CREATE TABLE IF NOT EXISTS documents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    filename VARCHAR(255) NOT NULL,
    mime_type VARCHAR(150) NOT NULL DEFAULT 'application/octet-stream',
    size BIGINT NOT NULL DEFAULT 0,
    data LONGBLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// --- Documents texte (toujours éditables) ---
$pdo->exec("CREATE TABLE IF NOT EXISTS text_documents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    title VARCHAR(255) NOT NULL DEFAULT '',
    content MEDIUMTEXT NOT NULL DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

// Exécute les migrations seulement si la version du schéma a changé.
if ((int)@file_get_contents($schemaMarkerFile) !== SCHEMA_VERSION) {
    runSchemaMigrations($pdo);
    @file_put_contents($schemaMarkerFile, (string)SCHEMA_VERSION);
}

// Garantit qu'un utilisateur a toujours au moins une liste
function ensureDefaultList($pdo, $userId) {
    $stmt = $pdo->prepare("SELECT id FROM shopping_lists WHERE owner_id = :uid LIMIT 1");
    $stmt->execute([':uid' => $userId]);
    $row = $stmt->fetch();
    if ($row) return $row['id'];
    $memberOf = $pdo->prepare("SELECT list_id FROM shopping_list_members WHERE user_id = :uid LIMIT 1");
    $memberOf->execute([':uid' => $userId]);
    $row2 = $memberOf->fetch();
    if ($row2) return $row2['list_id'];
    $ins = $pdo->prepare("INSERT INTO shopping_lists (owner_id, name) VALUES (:uid, 'Courses')");
    $ins->execute([':uid' => $userId]);
    return $pdo->lastInsertId();
}

function hasListAccess($pdo, $listId, $userId) {
    $stmt = $pdo->prepare("SELECT 1 FROM shopping_lists WHERE id = :lid AND owner_id = :uid
        UNION
        SELECT 1 FROM shopping_list_members WHERE list_id = :lid AND user_id = :uid");
    $stmt->execute([':lid' => $listId, ':uid' => $userId]);
    return (bool)$stmt->fetch();
}


$userId = $_SESSION['user_id'];

// Clé publique de l'utilisateur, nécessaire côté client pour dériver la
// clé de chiffrement des notes (voir crypto.js). C'est une donnée
// publique, aucun risque à l'injecter dans le HTML.
$stmtPub = $pdo->prepare("SELECT public_key FROM users WHERE id = :uid");
$stmtPub->execute([':uid' => $userId]);
$myPublicKey = $stmtPub->fetchColumn() ?: '';

if (isset($_GET['action'])) {
    header('Content-Type: application/json; charset=utf-8');
    $action = $_GET['action'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrfCheck();
    }

    try {
        // --- Listes de courses (magasins) ---
        if ($action === 'lists_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            ensureDefaultList($pdo, $userId);
            $stmt = $pdo->prepare("
                SELECT l.id, l.name, l.owner_id, (l.owner_id = :uid) AS is_owner, u.username AS owner_name
                FROM shopping_lists l
                JOIN users u ON u.id = l.owner_id
                WHERE l.owner_id = :uid
                UNION
                SELECT l.id, l.name, l.owner_id, 0 AS is_owner, u.username AS owner_name
                FROM shopping_lists l
                JOIN users u ON u.id = l.owner_id
                JOIN shopping_list_members m ON m.list_id = l.id
                WHERE m.user_id = :uid
                ORDER BY name ASC
            ");
            $stmt->execute([':uid' => $userId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['id'] = (int)$r['id'];
                $r['is_owner'] = (bool)$r['is_owner'];
            }
            echo json_encode($rows);
            exit;
        }

        if ($action === 'lists_add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $name = trim($data['name'] ?? '');
            if ($name === '') {
                http_response_code(400);
                echo json_encode(['error' => 'nom requis']);
                exit;
            }
            if (mb_strlen($name) > 100) {
                http_response_code(400);
                echo json_encode(['error' => 'nom trop long (100 caractères max)']);
                exit;
            }
            $wrappedKey = $data['wrapped_key'] ?? null;
            if (!$wrappedKey || empty($wrappedKey['ciphertext']) || empty($wrappedKey['iv'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Clé de liste chiffrée requise']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO shopping_lists (owner_id, name) VALUES (:uid, :name)");
            $stmt->execute([':uid' => $userId, ':name' => $name]);
            $newListId = $pdo->lastInsertId();
            $insKey = $pdo->prepare("INSERT INTO list_keys (list_id, user_id, enc_key_ciphertext, enc_key_iv, sender_public_key) VALUES (:lid, :uid, :ec, :iv, :pub)");
            $insKey->execute([
                ':lid' => $newListId, ':uid' => $userId,
                ':ec' => $wrappedKey['ciphertext'], ':iv' => $wrappedKey['iv'],
                ':pub' => $myPublicKey,
            ]);
            echo json_encode(['id' => $newListId, 'name' => $name, 'owner_id' => $userId, 'is_owner' => true, 'owner_name' => $_SESSION['username']]);
            exit;
        }

        if ($action === 'lists_rename' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $name = trim($data['name'] ?? '');
            if ($name === '') {
                http_response_code(400);
                echo json_encode(['error' => 'nom requis']);
                exit;
            }
            if (mb_strlen($name) > 100) {
                http_response_code(400);
                echo json_encode(['error' => 'nom trop long (100 caractères max)']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE shopping_lists SET name = :name WHERE id = :id AND owner_id = :uid");
            $stmt->execute([':name' => $name, ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'lists_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("DELETE FROM shopping_lists WHERE id = :id AND owner_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'lists_members' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $listId = (int)($_GET['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $owner = $pdo->prepare("SELECT u.id, u.username FROM shopping_lists l JOIN users u ON u.id = l.owner_id WHERE l.id = :lid");
            $owner->execute([':lid' => $listId]);
            $ownerRow = $owner->fetch();
            $stmt = $pdo->prepare("SELECT u.id, u.username FROM shopping_list_members m JOIN users u ON u.id = m.user_id WHERE m.list_id = :lid ORDER BY u.username");
            $stmt->execute([':lid' => $listId]);
            echo json_encode(['owner' => $ownerRow, 'members' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            exit;
        }

        if ($action === 'lists_add_member' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            $identifier = trim($data['identifier'] ?? '');
            $stmt = $pdo->prepare("SELECT owner_id FROM shopping_lists WHERE id = :id");
            $stmt->execute([':id' => $listId]);
            $list = $stmt->fetch();
            if (!$list || !hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $u = $pdo->prepare("SELECT id, username, public_key FROM users WHERE username = :i OR email = :i");
            $u->execute([':i' => $identifier]);
            $target = $u->fetch();
            if (!$target) {
                http_response_code(404);
                echo json_encode(['error' => 'Utilisateur introuvable']);
                exit;
            }
            if ((int)$target['id'] === $userId) {
                http_response_code(400);
                echo json_encode(['error' => 'Vous êtes déjà membre de cette liste']);
                exit;
            }
            $ins = $pdo->prepare("INSERT IGNORE INTO shopping_list_members (list_id, user_id) VALUES (:lid, :uid)");
            $ins->execute([':lid' => $listId, ':uid' => $target['id']]);

            // Notifie le membre invité (seulement s'il a bien été inséré, pas s'il était déjà membre).
            if ($ins->rowCount() > 0) {
                $listNameRow = $pdo->prepare("SELECT name FROM shopping_lists WHERE id = :lid");
                $listNameRow->execute([':lid' => $listId]);
                $listName = $listNameRow->fetchColumn() ?: 'une liste';
                $notifPayload = json_encode([
                    'list_id'    => $listId,
                    'list_name'  => $listName,
                    'invited_by' => $_SESSION['username'],
                ]);
                $pdo->prepare("INSERT INTO notifications (user_id, type, payload) VALUES (:uid, 'list_invite', :payload)")
                    ->execute([':uid' => $target['id'], ':payload' => $notifPayload]);
            }

            // Le client va maintenant devoir wrapper la cle de liste pour ce
            // membre (avec sa cle publique) puis appeler lists_store_key.
            echo json_encode(['id' => $target['id'], 'username' => $target['username'], 'public_key' => $target['public_key']]);
            exit;
        }

        // Récupère la clé de liste wrappée pour l'utilisateur courant
        // (+ la clé publique de l'expéditeur, nécessaire pour l'ECDH d'unwrap).
        if ($action === 'lists_get_key' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $listId = (int)($_GET['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT enc_key_ciphertext, enc_key_iv, sender_public_key FROM list_keys WHERE list_id = :lid AND user_id = :uid");
            $stmt->execute([':lid' => $listId, ':uid' => $userId]);
            $row = $stmt->fetch();
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'Clé de liste introuvable']);
                exit;
            }
            echo json_encode([
                'ciphertext' => $row['enc_key_ciphertext'],
                'iv' => $row['enc_key_iv'],
                'sender_public_key' => $row['sender_public_key'],
            ]);
            exit;
        }

        // Stocke la clé de liste wrappée pour un membre donné (appelé par
        // qui que ce soit ayant déjà accès à la clé, juste après l'avoir
        // re-wrappée pour le nouveau membre côté client).
        if ($action === 'lists_store_key' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            $targetUserId = (int)($data['user_id'] ?? 0);
            $wrappedKey = $data['wrapped_key'] ?? null;
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            if (!hasListAccess($pdo, $listId, $targetUserId)) {
                http_response_code(400);
                echo json_encode(['error' => 'Utilisateur cible non membre de la liste']);
                exit;
            }
            if (!$wrappedKey || empty($wrappedKey['ciphertext']) || empty($wrappedKey['iv'])) {
                http_response_code(400);
                echo json_encode(['error' => 'Clé chiffrée requise']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO list_keys (list_id, user_id, enc_key_ciphertext, enc_key_iv, sender_public_key)
                VALUES (:lid, :uid, :ec, :iv, :pub)
                ON DUPLICATE KEY UPDATE enc_key_ciphertext = :ec, enc_key_iv = :iv, sender_public_key = :pub");
            $stmt->execute([
                ':lid' => $listId, ':uid' => $targetUserId,
                ':ec' => $wrappedKey['ciphertext'], ':iv' => $wrappedKey['iv'],
                ':pub' => $myPublicKey,
            ]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'lists_remove_member' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            $memberId = (int)($data['user_id'] ?? 0);
            $stmt = $pdo->prepare("SELECT owner_id FROM shopping_lists WHERE id = :id");
            $stmt->execute([':id' => $listId]);
            $list = $stmt->fetch();
            if (!$list) {
                http_response_code(404);
                echo json_encode(['error' => 'Liste introuvable']);
                exit;
            }
            // le propriétaire peut retirer n'importe quel membre, un membre peut se retirer lui-même
            if ((int)$list['owner_id'] !== $userId && $memberId !== $userId) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $del = $pdo->prepare("DELETE FROM shopping_list_members WHERE list_id = :lid AND user_id = :mid");
            $del->execute([':lid' => $listId, ':mid' => $memberId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        // --- Notifications ---
        if ($action === 'notifications_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $stmt = $pdo->prepare("SELECT id, type, payload, is_read, created_at FROM notifications WHERE user_id = :uid ORDER BY created_at DESC LIMIT 50");
            $stmt->execute([':uid' => $userId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['payload'] = json_decode($r['payload'], true);
                $r['is_read'] = (bool)$r['is_read'];
            }
            echo json_encode($rows);
            exit;
        }

        if ($action === 'notifications_read' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $ids = array_map('intval', $data['ids'] ?? []);
            if (empty($ids)) {
                // Marque toutes comme lues
                $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = :uid")
                    ->execute([':uid' => $userId]);
            } else {
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $stmt = $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE user_id = ? AND id IN ($placeholders)");
                $stmt->execute(array_merge([$userId], $ids));
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notifications_respond' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $notifId = (int)($data['notif_id'] ?? 0);
            $accept  = (bool)($data['accept'] ?? false);

            // Vérifie que la notif appartient bien à l'utilisateur connecté
            $stmt = $pdo->prepare("SELECT id, type, payload FROM notifications WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $notifId, ':uid' => $userId]);
            $notif = $stmt->fetch();
            if (!$notif) {
                http_response_code(404);
                echo json_encode(['error' => 'Notification introuvable']);
                exit;
            }
            if ($notif['type'] !== 'list_invite') {
                http_response_code(400);
                echo json_encode(['error' => 'Type de notification non géré']);
                exit;
            }

            $payload = json_decode($notif['payload'], true);
            $listId  = (int)($payload['list_id'] ?? 0);

            if (!$accept) {
                // Refus : retirer le membre et sa clé de liste
                $pdo->prepare("DELETE FROM shopping_list_members WHERE list_id = :lid AND user_id = :uid")
                    ->execute([':lid' => $listId, ':uid' => $userId]);
                $pdo->prepare("DELETE FROM list_keys WHERE list_id = :lid AND user_id = :uid")
                    ->execute([':lid' => $listId, ':uid' => $userId]);
            }

            // Dans les deux cas, marque la notif comme lue
            $pdo->prepare("UPDATE notifications SET is_read = 1 WHERE id = :id")
                ->execute([':id' => $notifId]);

            echo json_encode(['ok' => true, 'accepted' => $accept]);
            exit;
        }

        if ($action === 'notifications_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $ids = array_map('intval', $data['ids'] ?? []);
            if (empty($ids)) {
                // Aucun id fourni : supprime toutes les notifications de l'utilisateur
                $pdo->prepare("DELETE FROM notifications WHERE user_id = :uid")
                    ->execute([':uid' => $userId]);
            } else {
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $stmt = $pdo->prepare("DELETE FROM notifications WHERE user_id = ? AND id IN ($placeholders)");
                $stmt->execute(array_merge([$userId], $ids));
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        // --- Articles ---
        if ($action === 'list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $listId = (int)($_GET['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT id, enc_label_ciphertext, enc_label_iv, checked FROM courses WHERE list_id = :lid AND deleted = 0 ORDER BY checked ASC, id ASC");
            $stmt->execute([':lid' => $listId]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            exit;
        }

        if ($action === 'trash_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $listId = (int)($_GET['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT id, enc_label_ciphertext, enc_label_iv, checked FROM courses WHERE list_id = :lid AND deleted = 1 ORDER BY id DESC");
            $stmt->execute([':lid' => $listId]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            exit;
        }

        if ($action === 'add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            $encCiphertext = $data['enc_label_ciphertext'] ?? '';
            $encIv = $data['enc_label_iv'] ?? '';
            if ($encCiphertext === '' || $encIv === '') {
                http_response_code(400);
                echo json_encode(['error' => 'article chiffré requis']);
                exit;
            }
            if (strlen($encCiphertext) > 4000) {
                http_response_code(400);
                echo json_encode(['error' => 'article trop long']);
                exit;
            }
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO courses (list_id, user_id, label, enc_label_ciphertext, enc_label_iv) VALUES (:lid, :uid, '', :ec, :iv)");
            $stmt->execute([':lid' => $listId, ':uid' => $userId, ':ec' => $encCiphertext, ':iv' => $encIv]);
            echo json_encode(['id' => $pdo->lastInsertId(), 'enc_label_ciphertext' => $encCiphertext, 'enc_label_iv' => $encIv, 'checked' => 0]);
            exit;
        }

        if ($action === 'toggle' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("UPDATE courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                SET c.checked = 1 - c.checked
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            if ($stmt->rowCount() === 0) {
                http_response_code(404);
                echo json_encode(['error' => 'Article introuvable ou accès refusé']);
                exit;
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("UPDATE courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                SET c.deleted = 1
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            if ($stmt->rowCount() === 0) {
                http_response_code(404);
                echo json_encode(['error' => 'Article introuvable ou accès refusé']);
                exit;
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'restore' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("UPDATE courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                SET c.deleted = 0
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            if ($stmt->rowCount() === 0) {
                http_response_code(404);
                echo json_encode(['error' => 'Article introuvable ou accès refusé']);
                exit;
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'permanent_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("DELETE c FROM courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            if ($stmt->rowCount() === 0) {
                http_response_code(404);
                echo json_encode(['error' => 'Article introuvable ou accès refusé']);
                exit;
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $encCiphertext = $data['enc_label_ciphertext'] ?? '';
            $encIv = $data['enc_label_iv'] ?? '';
            if ($encCiphertext === '' || $encIv === '') {
                http_response_code(400);
                echo json_encode(['error' => 'article chiffré requis']);
                exit;
            }
            if (strlen($encCiphertext) > 4000) {
                http_response_code(400);
                echo json_encode(['error' => 'article trop long']);
                exit;
            }
            $check = $pdo->prepare("SELECT c.id FROM courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $check->execute([':id' => $id, ':uid' => $userId]);
            if (!$check->fetch()) {
                http_response_code(404);
                echo json_encode(['error' => 'Article introuvable ou accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                SET c.enc_label_ciphertext = :ec, c.enc_label_iv = :iv
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':ec' => $encCiphertext, ':iv' => $encIv, ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'clear_checked' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE courses SET deleted = 1 WHERE checked = 1 AND deleted = 0 AND list_id = :lid");
            $stmt->execute([':lid' => $listId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        // --- Notes ---
        if ($action === 'notes_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            // Période de transition : les notes créées avant le E2EE ont
            // title/body en clair (enc_ciphertext NULL) ; les nouvelles
            // n'ont que enc_ciphertext/enc_iv. On renvoie les deux, le
            // client préfère le chiffré s'il existe (voir loadNotes()).
            $stmt = $pdo->prepare("SELECT id, title, body, enc_ciphertext, enc_iv, pinned, deleted, color, images, protected, group_id FROM notes WHERE user_id = :uid ORDER BY id DESC");
            $stmt->execute([':uid' => $userId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['pinned'] = (bool)$r['pinned'];
                $r['deleted'] = (bool)$r['deleted'];
                $r['protected'] = (bool)$r['protected'];
                $r['id'] = (int)$r['id'];
                $r['group_id'] = $r['group_id'] ? (int)$r['group_id'] : null;
                $decoded = json_decode($r['images'] ?: '[]', true);
                $r['images'] = is_array($decoded) ? $decoded : [];
            }
            // Groupes
            $gStmt = $pdo->prepare("SELECT id, title FROM note_groups WHERE user_id = :uid");
            $gStmt->execute([':uid' => $userId]);
            $groups = $gStmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($groups as &$g) { $g['id'] = (int)$g['id']; }
            echo json_encode(['notes' => $rows, 'groups' => $groups]);
            exit;
        }

        if ($action === 'notes_group_create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $groupId = (int)($data['group_id'] ?? 0);
            $noteIds = array_map('intval', $data['note_ids'] ?? []);
            $title = trim($data['title'] ?? '');
            if ($groupId <= 0 || count($noteIds) < 2) {
                http_response_code(400); echo json_encode(['error' => 'Données invalides']); exit;
            }
            $pdo->prepare("INSERT INTO note_groups (id, user_id, title) VALUES (:id, :uid, :title)")
                ->execute([':id' => $groupId, ':uid' => $userId, ':title' => $title]);
            $placeholders = implode(',', array_fill(0, count($noteIds), '?'));
            $params = array_merge([$groupId, $userId], $noteIds, [$userId]);
            $pdo->prepare("UPDATE notes SET group_id = ? WHERE user_id = ? AND id IN ($placeholders) AND user_id = ?")
                ->execute($params);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_group_set' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $noteId = (int)($data['note_id'] ?? 0);
            $groupId = isset($data['group_id']) ? (int)$data['group_id'] : null;
            if ($noteId <= 0) {
                http_response_code(400); echo json_encode(['error' => 'note_id requis']); exit;
            }
            if ($groupId) {
                $pdo->prepare("UPDATE notes SET group_id = :gid WHERE id = :id AND user_id = :uid")
                    ->execute([':gid' => $groupId, ':id' => $noteId, ':uid' => $userId]);
            } else {
                $pdo->prepare("UPDATE notes SET group_id = NULL WHERE id = :id AND user_id = :uid")
                    ->execute([':id' => $noteId, ':uid' => $userId]);
                // Si le groupe est maintenant vide ou n'a plus qu'une note, le dissoudre
                $oldGroupId = (int)($data['old_group_id'] ?? 0);
                if ($oldGroupId) {
                    $count = $pdo->prepare("SELECT COUNT(*) FROM notes WHERE group_id = :gid AND user_id = :uid AND deleted = 0");
                    $count->execute([':gid' => $oldGroupId, ':uid' => $userId]);
                    if ((int)$count->fetchColumn() <= 1) {
                        // Retirer la dernière note du groupe et supprimer le groupe
                        $pdo->prepare("UPDATE notes SET group_id = NULL WHERE group_id = :gid AND user_id = :uid")
                            ->execute([':gid' => $oldGroupId, ':uid' => $userId]);
                        $pdo->prepare("DELETE FROM note_groups WHERE id = :id AND user_id = :uid")
                            ->execute([':id' => $oldGroupId, ':uid' => $userId]);
                    }
                }
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            // Le serveur ne reçoit et ne stocke QUE du ciphertext : il ne
            // peut ni lire ni valider le titre/corps de la note (c'est le
            // but du E2EE). La validation de longueur se fait côté client
            // avant chiffrement.
            $encCiphertext = $data['enc_ciphertext'] ?? '';
            $encIv = $data['enc_iv'] ?? '';
            $color = trim($data['color'] ?? '');
            if (!preg_match('/^[a-zA-Z0-9#]{0,20}$/', $color)) {
                $color = '';
            }
            if ($id <= 0 || $encCiphertext === '' || $encIv === '') {
                http_response_code(400);
                echo json_encode(['error' => 'id ou données chiffrées manquantes']);
                exit;
            }
            // Colonne enc_ciphertext en MEDIUMTEXT : large marge de sécurité,
            // on garde tout de même une limite haute contre les abus.
            if (strlen($encCiphertext) > 400000) {
                http_response_code(400);
                echo json_encode(['error' => 'note trop volumineuse']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT id FROM notes WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            if ($stmt->fetch()) {
                $stmt = $pdo->prepare("UPDATE notes SET enc_ciphertext = :ec, enc_iv = :ei, color = :color WHERE id = :id AND user_id = :uid");
                $stmt->execute([':ec' => $encCiphertext, ':ei' => $encIv, ':color' => $color, ':id' => $id, ':uid' => $userId]);
            } else {
                $protected = !empty($data['protected']) ? 1 : 0;
                $stmt = $pdo->prepare("INSERT INTO notes (id, user_id, enc_ciphertext, enc_iv, color, protected) VALUES (:id, :uid, :ec, :ei, :color, :protected)");
                $stmt->execute([':id' => $id, ':uid' => $userId, ':ec' => $encCiphertext, ':ei' => $encIv, ':color' => $color, ':protected' => $protected]);
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_image_add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            // L'image est chiffrée côté client avant l'envoi (voir
            // renderNoteImages / handler d'ajout dans le JS) : le serveur
            // ne peut plus valider qu'il s'agit réellement d'une image
            // (getimagesizefromstring nécessiterait de voir le contenu en
            // clair). Cette validation se fait maintenant côté client,
            // AVANT chiffrement. On garde ici uniquement des garde-fous
            // sur la taille du blob chiffré, contre l'abus/le spam.
            $encCiphertext = $data['enc_ciphertext'] ?? '';
            $encIv = $data['enc_iv'] ?? '';
            if ($id <= 0 || $encCiphertext === '' || $encIv === '') {
                http_response_code(400);
                echo json_encode(['error' => 'paramètres manquants']);
                exit;
            }
            if (strlen($encCiphertext) > 8 * 1024 * 1024) {
                http_response_code(413);
                echo json_encode(['error' => 'image trop volumineuse']);
                exit;
            }

            $stmt = $pdo->prepare("SELECT images FROM notes WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            $row = $stmt->fetch();
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'note introuvable']);
                exit;
            }
            $images = json_decode($row['images'] ?: '[]', true);
            if (!is_array($images)) $images = [];

            // Limite le nombre d'images par note pour éviter le spam /
            // la saturation de la colonne (MEDIUMTEXT, 16 Mo max).
            if (count($images) >= 20) {
                http_response_code(400);
                echo json_encode(['error' => "Nombre maximum d'images atteint pour cette note (20)"]);
                exit;
            }

            $imgId = uniqid('img_', true);
            $images[] = ['id' => $imgId, 'enc_ciphertext' => $encCiphertext, 'enc_iv' => $encIv];
            $stmt = $pdo->prepare("UPDATE notes SET images = :images WHERE id = :id AND user_id = :uid");
            $stmt->execute([':images' => json_encode($images), ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true, 'imageId' => $imgId]);
            exit;
        }

        if ($action === 'notes_image_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $imgId = $data['imageId'] ?? '';
            $stmt = $pdo->prepare("SELECT images FROM notes WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            $row = $stmt->fetch();
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'note introuvable']);
                exit;
            }
            $images = json_decode($row['images'] ?: '[]', true);
            if (!is_array($images)) $images = [];
            $images = array_values(array_filter($images, fn($im) => ($im['id'] ?? '') !== $imgId));
            $stmt = $pdo->prepare("UPDATE notes SET images = :images WHERE id = :id AND user_id = :uid");
            $stmt->execute([':images' => json_encode($images), ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $check = $pdo->prepare("SELECT protected FROM notes WHERE id = :id AND user_id = :uid");
            $check->execute([':id' => $id, ':uid' => $userId]);
            $row = $check->fetch();
            if ($row && (int)$row['protected'] === 1) {
                http_response_code(403);
                echo json_encode(['error' => 'Cette note ne peut pas être supprimée']);
                exit;
            }
            $stmt = $pdo->prepare("DELETE FROM notes WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_set_deleted' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $deleted = !empty($data['deleted']) ? 1 : 0;
            if ($deleted === 1) {
                $check = $pdo->prepare("SELECT protected FROM notes WHERE id = :id AND user_id = :uid");
                $check->execute([':id' => $id, ':uid' => $userId]);
                $row = $check->fetch();
                if ($row && (int)$row['protected'] === 1) {
                    http_response_code(403);
                    echo json_encode(['error' => 'Cette note ne peut pas être supprimée']);
                    exit;
                }
            }
            $stmt = $pdo->prepare("UPDATE notes SET deleted = :d WHERE id = :id AND user_id = :uid");
            $stmt->execute([':d' => $deleted, ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_set_pinned' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $pinned = !empty($data['pinned']) ? 1 : 0;
            $stmt = $pdo->prepare("UPDATE notes SET pinned = :p WHERE id = :id AND user_id = :uid");
            $stmt->execute([':p' => $pinned, ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        // --- Documents ---
        if ($action === 'documents_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $stmt = $pdo->prepare("SELECT id, filename, mime_type, size, created_at FROM documents WHERE user_id = :uid ORDER BY created_at DESC");
            $stmt->execute([':uid' => $userId]);
            echo json_encode(['documents' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            exit;
        }

        if ($action === 'documents_add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $filename = trim($data['filename'] ?? '');
            $mimeType = $data['mime_type'] ?? 'application/octet-stream';
            $b64 = $data['data'] ?? '';
            if ($filename === '' || $b64 === '') {
                http_response_code(400);
                echo json_encode(['error' => 'paramètres manquants']);
                exit;
            }
            if (strlen($b64) > 20 * 1024 * 1024) {
                http_response_code(413);
                echo json_encode(['error' => 'fichier trop volumineux']);
                exit;
            }
            $binary = base64_decode($b64, true);
            if ($binary === false) {
                http_response_code(400);
                echo json_encode(['error' => 'données invalides']);
                exit;
            }
            $countStmt = $pdo->prepare("SELECT COUNT(*) FROM documents WHERE user_id = :uid");
            $countStmt->execute([':uid' => $userId]);
            if ((int)$countStmt->fetchColumn() >= 200) {
                http_response_code(400);
                echo json_encode(['error' => 'Nombre maximum de documents atteint (200)']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO documents (user_id, filename, mime_type, size, data) VALUES (:uid, :fn, :mt, :sz, :data)");
            $stmt->execute([
                ':uid' => $userId,
                ':fn' => $filename,
                ':mt' => $mimeType,
                ':sz' => strlen($binary),
                ':data' => $binary,
            ]);
            echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
            exit;
        }

        if ($action === 'documents_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("DELETE FROM documents WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'documents_download' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $id = (int)($_GET['id'] ?? 0);
            $stmt = $pdo->prepare("SELECT filename, mime_type, data FROM documents WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            $row = $stmt->fetch();
            if (!$row) {
                http_response_code(404);
                echo json_encode(['error' => 'document introuvable']);
                exit;
            }
            header('Content-Type: ' . $row['mime_type']);
            header('Content-Disposition: attachment; filename="' . str_replace('"', '', $row['filename']) . '"');
            header('Content-Length: ' . strlen($row['data']));
            echo $row['data'];
            exit;
        }

        // --- Documents texte (toujours éditables) ---
        if ($action === 'text_documents_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $stmt = $pdo->prepare("SELECT id, title, content, updated_at FROM text_documents WHERE user_id = :uid ORDER BY updated_at DESC");
            $stmt->execute([':uid' => $userId]);
            echo json_encode(['documents' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
            exit;
        }

        if ($action === 'text_documents_create' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $stmt = $pdo->prepare("INSERT INTO text_documents (user_id, title, content) VALUES (:uid, '', '')");
            $stmt->execute([':uid' => $userId]);
            echo json_encode(['ok' => true, 'id' => (int)$pdo->lastInsertId()]);
            exit;
        }

        if ($action === 'text_documents_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $title = $data['title'] ?? '';
            $content = $data['content'] ?? '';
            $stmt = $pdo->prepare("UPDATE text_documents SET title = :t, content = :c, updated_at = NOW() WHERE id = :id AND user_id = :uid");
            $stmt->execute([':t' => $title, ':c' => $content, ':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'text_documents_delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("DELETE FROM text_documents WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        // --- Notifications / activité de liste (chiffrées comme les articles) ---
        // Le serveur ne reçoit et ne stocke que du ciphertext : il ne peut pas
        // lire le texte des notifications ("X a ajouté Y"), seulement savoir
        // qu'un évènement a eu lieu sur telle liste, à quel moment, par qui.
        if ($action === 'activity_add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            $encCiphertext = $data['enc_ciphertext'] ?? '';
            $encIv = $data['enc_iv'] ?? '';
            if ($encCiphertext === '' || $encIv === '') {
                http_response_code(400);
                echo json_encode(['error' => 'notification chiffrée requise']);
                exit;
            }
            if (strlen($encCiphertext) > 2000) {
                http_response_code(400);
                echo json_encode(['error' => 'notification trop longue']);
                exit;
            }
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO list_activity (list_id, actor_user_id, enc_ciphertext, enc_iv) VALUES (:lid, :uid, :ec, :iv)");
            $stmt->execute([':lid' => $listId, ':uid' => $userId, ':ec' => $encCiphertext, ':iv' => $encIv]);
            // Purge légère : garde les 200 dernières entrées par liste pour
            // éviter une croissance illimitée de la table.
            $pdo->prepare("DELETE FROM list_activity WHERE list_id = :lid AND id NOT IN (
                SELECT id FROM (SELECT id FROM list_activity WHERE list_id = :lid ORDER BY id DESC LIMIT 200) t
            )")->execute([':lid' => $listId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'activity_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $listId = (int)($_GET['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT a.id, a.enc_ciphertext, a.enc_iv, a.created_at, a.actor_user_id, u.username AS actor_name
                FROM list_activity a JOIN users u ON u.id = a.actor_user_id
                WHERE a.list_id = :lid ORDER BY a.id DESC LIMIT 50");
            $stmt->execute([':lid' => $listId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) { $r['id'] = (int)$r['id']; $r['actor_user_id'] = (int)$r['actor_user_id']; }
            echo json_encode($rows);
            exit;
        }

        http_response_code(404);
        echo json_encode(['error' => 'action inconnue']);
        exit;
    } catch (Exception $e) {
        error_log('index.php API error: ' . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Erreur serveur, réessayez plus tard.']);
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NoteKeep</title>
<link rel="manifest" href="/manifest.json">
<meta name="theme-color" content="#C97A4A">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>%F0%9F%92%A1</text></svg>">
<meta name="csrf-token" content="<?= htmlspecialchars(csrfToken()) ?>">
<meta name="e2ee-public-key" content="<?= htmlspecialchars($myPublicKey) ?>">
<meta name="e2ee-user-id" content="<?= (int)$userId ?>">
<meta name="my-username" content="<?= htmlspecialchars($_SESSION['username']) ?>">
<link rel="stylesheet" href="assets/style.css?v=2">
<style>
.mobile-topbar{ display: none; }
.doc-tb-btn{
  width:36px; height:30px; display:flex; align-items:center; justify-content:center;
  background:transparent; border:none; color:var(--ink); border-radius:5px; font-size:13px; cursor:pointer;
}
.doc-tb-btn:hover{ background:rgba(255,255,255,0.08); }
.doc-tb-sep{ width:80%; height:1px; background:var(--line); margin:4px 0; }
.doc-tb-select{
  background:#2a2a26; color:#eee; border:1px solid #444; border-radius:5px;
  padding:3px 4px; font-size:12px; height:26px;
}
html[data-theme="dark"]{ --bg:#000000 !important; }
html[data-theme="light"]{ --bg:#ffffff !important; }
body{ background:var(--bg) !important; }
.sidebar{
  background: #130d1c !important;
  border-right: 1px solid #241a33 !important;
}
.sidebar .side-item.active{ background: rgba(233,180,120,0.18) !important; }
.sidebar .side-item:hover{ background: rgba(255,255,255,0.05) !important; }
body.doc-view-active header{ display:none; }
body.doc-view-active main{ max-width:none; padding:0; margin:0; min-height:100vh; }
body.doc-view-active #documentView{ max-width:900px; margin:0 auto; padding:20px 24px 60px; min-height:100vh; }
@media (max-width: 720px){
  .app{ flex-direction: column; min-height: 100dvh; }
  .mobile-topbar{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 16px;
    background: var(--card);
    border-bottom: 1px solid var(--line);
    position: sticky;
    top: 0;
    z-index: 40;
  }
  .mobile-topbar-brand{ font-size: 18px; letter-spacing: 0.5px; }
  .mobile-topbar-brand span{ color: var(--accent); }
  #settingsBtnMobile{
    width: 34px; height: 34px; border-radius: 50%;
    border: 1px solid var(--line); background: var(--card);
    color: var(--ink); font-size: 15px; line-height: 1;
  }
  .sidebar{
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    width: 100%;
    flex-direction: row;
    align-items: center;
    justify-content: space-around;
    padding: 8px 10px calc(8px + env(safe-area-inset-bottom));
    gap: 0;
    border-right: none;
    border-top: 1px solid var(--line);
    z-index: 50;
  }
  .sidebar-brand{ display: none; }
  #settingsBtn{ display: none; }
  .side-item{ flex-direction: column; padding: 6px 10px; width: auto; border-radius: 10px; }
  .side-item span.side-label{ display: none; }
  .side-icon{ font-size: 20px; }
  .content{ padding-bottom: 64px; }
  header{ padding: 16px 14px 10px; }
  h1{ font-size: 22px; }
  main{ padding: 8px 14px 40px; }
  .composer{ padding: 16px 12px; }
  .composer input{ font-size: 18px; }
  .grid{ grid-template-columns: 1fr 1fr; gap: 10px; }
  .lists-bar{ gap: 6px; }
  #listTabs{ flex: 1 1 auto; overflow-x: auto; flex-wrap: nowrap !important; }
  #shareListBtn{ flex-shrink: 0; }
  .courses-composer input{ font-size: 16px; }
  .course-item{ padding: 12px; }
}
@media (max-width: 420px){
  .grid{ grid-template-columns: 1fr; }
}
:focus-visible{outline:2px solid #4a90d9;outline-offset:2px;}
.pwd-modal-input:focus,
.pwd-modal-input:focus-visible{outline:2px solid #fff;outline-offset:2px;}
@media (prefers-reduced-motion: reduce){*{animation-duration:.01ms !important;transition-duration:.01ms !important;}}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0;}
@media print{
  @page{ size:A4; margin:15mm; }
  body *{ visibility:hidden; }
  .doc-a4-sheet, .doc-a4-sheet *{ visibility:visible; }
  .doc-a4-sheet{ min-height:0 !important; width:100% !important; box-shadow:none !important; position:absolute; top:0; left:0; margin:0 !important; }
  .doc-body-editable{ min-height:0 !important; padding:0 !important; }
}
/* Scrollbar sombre (Chromium + Firefox) */
:root { color-scheme: dark; }
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: #1a1a18; }
::-webkit-scrollbar-thumb { background: #444; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #666; }
* { scrollbar-color: #444 #1a1a18; scrollbar-width: thin; }
/* Curseur texte uniquement quand la note est ouverte */
.note.expanded .note-title,
.note.expanded .note-body { cursor: text; }

/* Plein écran */
.note:fullscreen {
  background: #1a1a18;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 40px 20px;
  overflow: hidden;
}
.note:fullscreen .note-modal-body {
  background: var(--card);
  border-radius: 8px;
  padding: 48px 56px;
  width: 100%;
  max-width: 780px;
  height: calc(100vh - 120px);
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  box-shadow: 0 2px 16px rgba(0,0,0,.4);
  margin-left: 210px;
}
.note:fullscreen .note-body {
  flex: 1;
  display: block !important;
}
.note:fullscreen .note-modal-toolbar {
  position: fixed;
  right: 20px;
  top: 50%;
  transform: translateY(-50%);
  width: auto;
  max-width: none;
  margin: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  background: var(--card);
  border-radius: 8px;
  padding: 12px 8px;
  box-shadow: 0 2px 10px rgba(0,0,0,.35);
  z-index: 5;
}
.note:fullscreen .note-modal-toolbar .toolbar-icons {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.note:fullscreen .note-modal-toolbar .close-btn {
  writing-mode: vertical-rl;
  text-orientation: mixed;
}
.note:fullscreen .pin-toggle { display: none; }

.fs-toolbar { display: none; }
.note:fullscreen .fs-toolbar {
  display: flex;
  flex-direction: column;
  flex-wrap: nowrap;
  align-items: stretch;
  gap: 6px;
  position: fixed;
  left: 20px;
  top: 50%;
  transform: translateY(-50%);
  width: 260px;
  max-height: calc(100vh - 60px);
  overflow-y: auto;
  background: var(--card);
  border-radius: 8px;
  padding: 10px;
  margin-bottom: 0;
  box-shadow: 0 2px 10px rgba(0,0,0,.35);
  z-index: 5;
}
.fs-toolbar .fs-btn {
  width: 100%;
  justify-content: flex-start;
  padding: 0 6px;
  background: transparent;
  color: #eee;
  border: none;
  border-radius: 5px;
  height: 28px;
  font-size: 13px;
  cursor: pointer;
  display: flex;
  align-items: center;
}
.fs-toolbar .fs-btn:hover { background: rgba(255,255,255,.08); }
.fs-toolbar select,
.fs-toolbar input[type="number"],
.fs-toolbar input[type="color"] {
  width: 100%;
  background: #2a2a26;
  color: #eee;
  border: 1px solid #444;
  border-radius: 6px;
  padding: 4px 6px;
  font-size: 12px;
  height: 28px;
}
.fs-toolbar input[type="color"] {
  padding: 2px;
  cursor: pointer;
}
.fs-textcolor-btn, .fs-hilite-btn {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 2px;
  width: 100%;
  height: 28px;
  padding: 2px 6px;
  border-radius: 6px;
  cursor: pointer;
  color: #eee;
  background: transparent;
  border: none;
}
.fs-textcolor-btn:hover, .fs-hilite-btn:hover { background: rgba(255,255,255,.08); }
.fs-textcolor-letter { font-weight: 700; font-size: 13px; line-height: 1; }
.fs-textcolor-bar { width: 18px; height: 3px; border-radius: 2px; flex: 0 0 auto; }
.doc-tb-btn.fs-textcolor-btn, .doc-tb-btn.fs-hilite-btn { height: auto; padding: 4px 2px; }

/* Popover de sélection de couleur (palette + personnalisé) */
.swatch-popover {
  position: absolute; z-index: 3000; background: var(--card); border: 1px solid var(--line);
  border-radius: 10px; padding: 10px; box-shadow: 0 6px 20px rgba(0,0,0,.35);
  width: 232px; color: #eee;
}
.swatch-none-btn {
  display: flex; align-items: center; gap: 8px; width: 100%; background: transparent; border: none;
  color: #eee; padding: 6px 4px; border-radius: 6px; cursor: pointer; font-size: 13px; margin-bottom: 6px;
}
.swatch-none-btn:hover { background: rgba(255,255,255,.08); }
.swatch-grid { display: grid; grid-template-columns: repeat(9, 1fr); gap: 6px; margin-bottom: 8px; }
.swatch-dot {
  width: 20px; height: 20px; border-radius: 50%; cursor: pointer; border: 1px solid rgba(255,255,255,.15);
  padding: 0;
}
.swatch-dot:hover { outline: 2px solid var(--accent); outline-offset: 1px; }
.swatch-custom-label { font-size: 11px; letter-spacing: .04em; opacity: .6; margin: 2px 0 6px; }
.swatch-actions { display: flex; gap: 8px; align-items: center; }
.swatch-action-btn {
  width: 24px; height: 24px; border-radius: 50%; border: 1px dashed rgba(255,255,255,.3);
  background: transparent; color: #eee; cursor: pointer; display: flex; align-items: center; justify-content: center;
  font-size: 13px; padding: 0;
}
.swatch-action-btn:hover { background: rgba(255,255,255,.08); }
.fs-sep {
  width: 100%;
  height: 1px;
  background: #444;
  margin: 2px 0;
}
.fs-size-row {
  display: flex;
  align-items: center;
  gap: 4px;
}
.fs-size-row .fs-btn {
  width: 28px;
  flex: 0 0 28px;
  justify-content: center;
}
.fs-size-row .fs-size {
  flex: 1;
  text-align: center;
}


/* Drag & drop */
.note.dragging { opacity: 0.4; }
.note.drop-target, .note-group.drop-target { outline: 2px solid var(--accent); outline-offset: 2px; }

/* Groupe de notes — collapsed */
.note-group {
  background: var(--card);
  border-radius: 10px;
  padding: 12px;
  cursor: pointer;
  position: relative;
  transition: box-shadow .15s;
}
.note-group:hover { box-shadow: 0 2px 12px rgba(0,0,0,.25); }
.group-preview {
  position: relative;
  height: 80px;
  margin-bottom: 8px;
}
.group-mini {
  position: absolute;
  inset: 0;
  background: var(--card-alt, #2e2c2a);
  border-radius: 8px;
  padding: 10px 12px;
  overflow: hidden;
  transform-origin: bottom center;
  box-shadow: 0 1px 4px rgba(0,0,0,.2);
}
.group-mini-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.group-footer {
  font-size: 11px;
  color: var(--ink);
  opacity: .5;
  text-align: right;
}

/* Groupe — expanded */
.note-group.group-expanded {
  cursor: default;
  padding: 14px;
}
.group-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  font-size: 12px;
  color: var(--ink);
  opacity: .6;
}
.group-close-btn {
  border: none;
  background: none;
  color: var(--ink);
  font-size: 12px;
  cursor: pointer;
  padding: 2px 6px;
  opacity: .7;
}
.group-inner-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.group-note-wrapper {
  position: relative;
}
.group-note-wrapper .note-body {
  display: none;
}
.checklist-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}
.chk-box {
  flex: 0 0 16px;
  width: 16px;
  height: 16px;
  margin-top: 3px;
  border: 1.8px solid currentColor;
  border-radius: 3px;
  cursor: pointer;
  position: relative;
  display: inline-block;
}
.chk-box:hover {
  opacity: .8;
}
.checklist-item.checked .chk-box {
  background: currentColor;
}
.checklist-item.checked .chk-box::after {
  content: '';
  position: absolute;
  left: 3px;
  top: -1px;
  width: 4px;
  height: 8px;
  border: solid #000;
  border-width: 0 2px 2px 0;
  transform: rotate(40deg);
}
.checklist-item.checked .chk-text {
  text-decoration: line-through;
  opacity: .6;
}
</style>

<script nonce="<?= $cspNonce ?>">
  (function(){
    const saved = localStorage.getItem('memo-theme');
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const theme = saved || (prefersDark ? 'dark' : 'light');
    document.documentElement.setAttribute('data-theme', theme);
  })();
</script>
</head>
<body>

<div class="app">
  <nav class="sidebar">
    <div class="sidebar-brand">
      <span class="brand-dot"></span>
      <span class="brand-name">Note<span>Keep</span></span>
    </div>
    <button class="side-item active" data-view="notesView" aria-label="Notes">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 3v2a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1V3"/><path d="M8 11h8"/><path d="M8 15h8"/><path d="M8 19h5"/></svg></span><span class="side-label"> Notes</span>
    </button>
    <button class="side-item" data-view="documentView" aria-label="Document">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 13h6"/><path d="M9 17h6"/></svg></span><span class="side-label"> Document</span>
    </button>
    <button class="side-item" data-view="coursesView" aria-label="Liste de courses">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="20" r="1.4" fill="#ffffff" stroke="none"/><circle cx="17" cy="20" r="1.4" fill="#ffffff" stroke="none"/><path d="M3 4h2l2.2 11.2a2 2 0 0 0 2 1.6h7.6a2 2 0 0 0 2-1.6L21 8H6"/></svg></span><span class="side-label"> Liste de courses</span>
    </button>
    <button class="side-item" data-view="trashView" aria-label="Corbeille">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/><path d="M10 11v6"/><path d="M14 11v6"/></svg></span><span class="side-label"> Corbeille</span>
    </button>
    <button class="side-item" id="notifBtn" style="margin-top:auto;position:relative;" title="Notifications" aria-label="Notifications">
      <span class="side-icon" style="position:relative;">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span id="notifBadge" style="display:none;position:absolute;top:-4px;right:-4px;background:#e74c3c;color:#fff;font-size:10px;font-weight:700;min-width:16px;height:16px;border-radius:999px;display:none;align-items:center;justify-content:center;padding:0 3px;line-height:1;"></span>
      </span>
    </button>
    <button class="side-item" id="settingsBtn" style="margin-top:0;" title="Paramètres" aria-label="Paramètres">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg></span>
    </button>
  </nav>

  <div class="content">
    <div class="mobile-topbar" id="mobileTopbar">
      <span class="mobile-topbar-brand"> Note<span>Keep</span></span>
      <button id="settingsBtnMobile" title="Paramètres" aria-label="Paramètres"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/></svg></button>
    </div>
    <header>
      <div class="composer" id="composer">
        <input id="titleInput" type="text" placeholder="Créer une note" aria-label="Titre de la note" autocomplete="off" name="note-title-nofill" data-lpignore="true" data-1p-ignore data-bwignore>
        <hr id="composerHr" style="display:none;border:none;border-top:1px solid var(--line);margin:8px 0;">
        <textarea id="bodyInput" placeholder="Créer une note…" rows="1" style="display:none;" autocomplete="off" name="note-body-nofill" data-lpignore="true" data-1p-ignore data-bwignore></textarea>
      </div>
    </header>

    <main id="main">
      <div id="notesView" class="view active">
        <div class="empty" id="emptyMsg">Aucune note pour l'instant.</div>
        <div id="pinnedSection" style="display:none">
          <div class="section-label">Épinglées</div>
          <div class="grid" id="pinnedGrid"></div>
        </div>
        <div id="othersSection" style="display:none">
          <div class="section-label" id="othersLabel">Notes</div>
          <div class="grid" id="othersGrid"></div>
        </div>
      </div>

      <div id="documentView" class="view">
        <div style="margin-bottom:14px;">
          <button type="button" id="addDocumentBtn" style="display:block;width:100%;text-align:left;background:#130d1c;color:#8a8a85;border:1px solid #241a33;border-radius:12px;padding:16px 20px;font-size:16px;cursor:pointer;font-family:inherit;">
            Créer un document
          </button>
          <input type="file" id="documentFileInput" style="display:none;" multiple>
        </div>
        <hr style="border:none;border-top:1px solid #ffffff;margin:0 0 20px;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
          <div style="font-size:18px;color:var(--ink);">Documents récents</div>
          <div style="display:flex;align-items:center;gap:16px;">
            <button type="button" class="btn" id="docsFilterBtn" style="display:flex;align-items:center;gap:4px;border:none;background:none;color:var(--ink);font-size:14px;">Tous ▾</button>
            <button type="button" id="docsViewToggleBtn" title="Changer l'affichage" style="background:none;border:none;color:var(--ink);cursor:pointer;padding:4px;" aria-label="Changer l'affichage">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="10" width="18" height="4" rx="1"/><rect x="3" y="16" width="18" height="4" rx="1"/></svg>
            </button>
            <button type="button" id="docsSortBtn" title="Trier de A à Z" style="background:none;border:none;color:var(--ink);cursor:pointer;padding:4px;" aria-label="Trier de A à Z">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8h4"/><path d="M3 14h7"/><path d="M3 20h10"/><path d="M17 4v16"/><path d="M13 8l4-4 4 4"/></svg>
            </button>
          </div>
        </div>
        <div class="empty" id="documentsEmptyMsg" style="display:none;">Aucun document pour l'instant.</div>
        <div id="documentsList" style="display:flex;flex-direction:column;gap:8px;"></div>
      </div>

      <div id="coursesView" class="view">
        <div class="lists-bar" id="listsBar" style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:14px;">
          <div id="listTabs" style="display:flex;flex-wrap:wrap;gap:6px;"></div>
          <button class="btn" id="newListBtn" title="Nouveau magasin">+ Magasin</button>
          <button class="btn" id="shareListBtn" style="margin-left:auto;">Partager</button>
        </div>

        <div id="sharePanel" style="display:none;background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:14px;">
          <div style="font-size:13px;color:var(--sub);margin-bottom:8px;">Collaborateurs de <strong id="shareListName"></strong></div>
          <div id="membersList" style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px;"></div>
          <div id="addMemberRow" style="display:flex;gap:8px;">
            <input id="memberInput" type="text" placeholder="Nom d'utilisateur ou email" aria-label="Nom d'utilisateur ou email à inviter" style="flex:1;padding:6px 10px;border-radius:6px;border:1px solid var(--line);background:transparent;color:var(--ink);font-family:inherit;">
            <button class="btn primary" id="addMemberBtn">Inviter</button>
          </div>
          <div id="shareError" style="color:#c0392b;font-size:12px;margin-top:6px;"></div>
        </div>

        <div class="courses-composer">
          <input id="courseInput" type="text" placeholder="Ajouter un article…" aria-label="Ajouter un article">
        </div>
        <ul class="courses-list" id="coursesList"></ul>
        <div id="checkedSection" style="display:none">
          <div class="section-label">Cochés</div>
          <ul class="courses-list" id="checkedList"></ul>
        </div>
        <div class="empty" id="coursesEmpty" style="display:none;margin-top:40px;">Liste de courses vide.</div>
        <div class="courses-footer">
          <span></span>
          <button class="btn" id="clearCheckedBtn">Retirer les articles cochés</button>
        </div>

      </div>

      <div id="trashView" class="view">
        <div class="empty" id="trashEmpty">Corbeille vide.</div>
        <div class="grid" id="trashGrid"></div>
      </div>
    </main>
  </div>
</div>

<script nonce="<?= $cspNonce ?>">
// Promesse résolue une fois la clé E2EE déverrouillée (voir module
// ci-dessous). Un <script type="module"> est TOUJOURS différé, donc il
// s'exécute après le script classique suivant dans le document — le code
// principal doit `await window.e2eeReadyPromise` avant tout chiffrement
// ou déchiffrement, plutôt que de supposer que la clé est déjà là.
window.e2eeReadyPromise = new Promise((resolve) => { window.__e2eeResolve = resolve; });
</script>
<script type="module" nonce="<?= $cspNonce ?>">
// --- Amorçage E2EE ---
// La clé privée déverrouillée au login est conservée en mémoire de module
// dans login.html (window.__e2eeGetUnlockedPrivateKey). Elle n'est jamais
// sérialisée dans sessionStorage/localStorage, ce qui supprime le vecteur
// d'exfiltration XSS via le stockage persistant.
// Si la référence est absente (nouvel onglet, rechargement), on renvoie vers /login.
import { importPublicKey, deriveNotesKey, importPrivateKey, fromB64 } from '/crypto.js';
window.E2EE_PUBLIC_KEY_B64 = document.querySelector('meta[name="e2ee-public-key"]').content;
window.MY_USER_ID = parseInt(document.querySelector('meta[name="e2ee-user-id"]').content, 10);

let publicKeyB64 = document.querySelector('meta[name="e2ee-public-key"]').content;

// Tente la clé en mémoire (connexion fraîche / navigation SPA),
// sinon la récupère depuis localStorage (refresh ou retour sur la PWA).
let privateKey = window.__e2eeGetUnlockedPrivateKey ? window.__e2eeGetUnlockedPrivateKey() : null;

if (!privateKey) {
  const stored = localStorage.getItem('e2ee_priv');
  if (stored) {
    try {
      privateKey = await importPrivateKey(fromB64(stored).buffer);
    } catch(e) {
      localStorage.removeItem('e2ee_priv');
    }
  }
}

// Compte connecté via Google sans mot de passe : aucune clé n'a pu être
// wrappée avec un mot de passe à l'inscription (voir google-oauth.php).
// Si l'E2EE n'a jamais été configuré pour ce compte (publicKeyB64 vide,
// pas de clé locale), on la génère ici, wrappée uniquement avec une
// recovery key affichée une seule fois (voir setup_e2ee_recovery côté
// serveur et wrapPrivateKeyWithRecoveryOnly dans crypto.js).
if (!privateKey && !publicKeyB64) {
  const bootstrapped = await bootstrapGoogleE2ee();
  if (bootstrapped) {
    privateKey = bootstrapped.privateKey;
    publicKeyB64 = bootstrapped.publicKeyB64;
  }
}

async function bootstrapGoogleE2ee() {
  try {
    const { generateIdentityKeyPair, wrapPrivateKeyWithRecoveryOnly, toB64 } = await import('/crypto.js');
    const identity = await generateIdentityKeyPair();
    const wrapped = await wrapPrivateKeyWithRecoveryOnly(identity.privateKeyRaw);

    const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
    const res = await fetch('user/auth.php?action=setup_e2ee_recovery', {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken},
      body: JSON.stringify({
        public_key: identity.publicKeyB64,
        enc_private_key_recovery: wrapped.enc_private_key_recovery,
      }),
    });
    if (!res.ok) {
      console.error('Échec de la configuration E2EE (compte Google).');
      return null;
    }

    localStorage.setItem('e2ee_priv', toB64(identity.privateKeyRaw));
    localStorage.setItem('e2ee_recovery', toB64(wrapped.recoveryKeyBytes));
    showRecoveryKeyOnce(wrapped.recoveryKeyDisplay); // non-bloquant : l'app continue sans attendre

    return { privateKey: identity.privateKey, publicKeyB64: identity.publicKeyB64 };
  } catch (e) {
    console.error('Erreur lors de la génération des clés E2EE:', e);
    return null;
  }
}

function showRecoveryKeyOnce(display) {
  const banner = document.createElement('div');
  banner.style.cssText = 'position:fixed;bottom:16px;right:16px;left:16px;max-width:420px;margin-left:auto;background:#1c1c1c;border-radius:12px;padding:18px 20px;color:#eee;font-family:sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.4);z-index:9999;';
  banner.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:start;gap:10px;">
      <strong style="font-size:14px;">Votre clé de récupération</strong>
      <button id="e2eeRecoveryClose" style="background:none;border:none;color:#888;font-size:18px;cursor:pointer;line-height:1;">×</button>
    </div>
    <p style="font-size:13px;color:#aaa;margin:8px 0;">Nécessaire pour accéder à vos notes depuis un autre appareil.</p>
    <code style="display:block;background:#000;padding:8px;border-radius:6px;font-size:13px;word-break:break-all;margin:8px 0;">${display}</code>
  `;
  document.body.appendChild(banner);
  banner.querySelector('#e2eeRecoveryClose').addEventListener('click', () => banner.remove());
}

if (!privateKey || !publicKeyB64) {
  window.location.href = '/login';
} else {
  const publicKey = await importPublicKey(publicKeyB64);
  window.E2EE_NOTES_KEY = await deriveNotesKey(privateKey, publicKey);
  window.E2EE_PRIVATE_KEY = privateKey;
  window.__e2eeResolve();
}
</script>
<script nonce="<?= $cspNonce ?>">
let notes = [];
let draftId = null;

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]').content;

// Si la session a expiré côté serveur, index.php répond 401 en JSON
// (voir plus haut dans le PHP) plutôt que de rediriger silencieusement.
// On intercepte cette réponse ici pour renvoyer l'utilisateur vers /login
// au lieu de laisser l'appli tourner dans un état incohérent (données
// vides, actions qui échouent sans explication).
let redirectingToLogin = false;
function handleAuthResponse(res){
  if (res.status === 401 && !redirectingToLogin) {
    redirectingToLogin = true;
    window.location.href = '/login';
  }
  return res;
}
function apiFetch(url, options = {}) {
  return fetch(url, options).then(handleAuthResponse);
}
function authFetch(url, options = {}) {
  options.headers = Object.assign({}, options.headers, {'X-CSRF-Token': CSRF_TOKEN});
  return fetch(url, options).then(handleAuthResponse);
}

// Suivi des changements locaux pas encore confirmés par le serveur,
// pour éviter qu'un rafraîchissement (polling) n'écrase une action
// (suppression/restauration/épinglage) avec des données pas encore à jour côté serveur.
const pendingNoteChanges = new Map();

// File d'attente de requêtes réseau PAR NOTE : garantit que les requêtes
// (création, sauvegarde, suppression, épinglage...) pour une même note
// arrivent au serveur DANS L'ORDRE où elles ont été déclenchées côté client.
// Sans ça, une suppression envoyée juste après une création pouvait arriver
// avant l'INSERT côté serveur : la suppression ne trouvait aucune ligne à
// modifier, puis l'INSERT tardif recréait la note "supprimée" quelques
// secondes plus tard (elle réapparaissait après le polling).
const noteRequestQueue = new Map();
function queueNoteRequest(id, fn){
  const prev = noteRequestQueue.get(id) || Promise.resolve();
  const next = prev.then(fn, fn);
  noteRequestQueue.set(id, next);
  next.finally(() => {
    if (noteRequestQueue.get(id) === next) noteRequestQueue.delete(id);
  });
  return next;
}

const titleInput = document.getElementById('titleInput');
const bodyInput = document.getElementById('bodyInput');

// Input caché pour l'ajout de photos depuis la galerie
const noteImageInput = document.createElement('input');
noteImageInput.type = 'file';
noteImageInput.accept = 'image/*';
noteImageInput.style.display = 'none';
document.body.appendChild(noteImageInput);
noteImageInput.addEventListener('change', () => {
  const file = noteImageInput.files && noteImageInput.files[0];
  noteImageInput.value = '';
  if (!file) return;
  resizeImageToDataUrl(file, 1280, 0.75).then(dataUrl => {
    if (noteImageInput._onPick) noteImageInput._onPick(dataUrl);
  }).catch(err => console.error('Erreur lecture image:', err));
});

function resizeImageToDataUrl(file, maxDim, quality){
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => {
      const img = new Image();
      img.onerror = reject;
      img.onload = () => {
        let { width, height } = img;
        if (width > maxDim || height > maxDim) {
          if (width >= height) {
            height = Math.round(height * (maxDim / width));
            width = maxDim;
          } else {
            width = Math.round(width * (maxDim / height));
            height = maxDim;
          }
        }
        const canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, width, height);
        resolve(canvas.toDataURL('image/jpeg', quality));
      };
      img.src = reader.result;
    };
    reader.readAsDataURL(file);
  });
}
const composer = document.getElementById('composer');
const composerHr = document.getElementById('composerHr');

composer.addEventListener('mousedown', (e) => {
  if(e.target !== titleInput && e.target !== bodyInput){
    e.preventDefault(); // évite que le clic dans le vide ne fasse perdre le focus avant qu'on le redonne
    if(bodyInput.style.display === 'none'){
      titleInput.focus();
    } else {
      // choisit le champ le plus proche du point cliqué (au-dessus ou en dessous du séparateur)
      const hrRect = composerHr.getBoundingClientRect();
      (e.clientY < hrRect.top ? titleInput : bodyInput).focus();
    }
  }
});

function resetComposerVisual(){
  if(!titleInput.value.trim() && !bodyInput.value.trim()){
    titleInput.placeholder = 'Créer une note';
    bodyInput.style.display = 'none';
    composerHr.style.display = 'none';
  }
}

titleInput.addEventListener('focus', () => {
  titleInput.placeholder = 'Titre';
  bodyInput.style.display = '';
  composerHr.style.display = '';
});
// Sauvegarde la note quand on quitte le composer (clic ailleurs),
// pas seulement quand on appuie sur Entrée.
composer.addEventListener('focusout', (e) => {
  if(composer.contains(e.relatedTarget)) return; // on reste dans le composer (title <-> body)
  autoSave();
  clearComposer();
  resetComposerVisual();
});

bodyInput.addEventListener('input', () => {
  bodyInput.style.height = 'auto';
  bodyInput.style.height = bodyInput.scrollHeight + 'px';
  scheduleComposerAutoSave();
});
titleInput.addEventListener('input', scheduleComposerAutoSave);

// Sauvegarde différée pendant la frappe : évite de perdre le texte si le
// champ perd le focus de façon "brutale" (changement d'appli mobile,
// verrouillage d'écran, fermeture d'onglet) sans déclencher focusout.
let composerAutoSaveTimer = null;
function scheduleComposerAutoSave(){
  clearTimeout(composerAutoSaveTimer);
  composerAutoSaveTimer = setTimeout(() => { autoSave(); }, 600);
}

function clearComposer(){
  titleInput.value = '';
  bodyInput.value = '';
  bodyInput.style.height = 'auto';
  draftId = null;
}

function saveNoteToServer(n){
  const id = n.id;
  return queueNoteRequest(id, async () => {
    // Vérification faite au moment où la requête part réellement (pas au moment
    // où elle a été programmée) : si la note a été supprimée entre-temps (ex: un
    // debounce de 600ms qui se déclenche après un clic sur "Supprimer"), on
    // annule la sauvegarde plutôt que de recréer la note en base via un INSERT.
    if (n.deleted || pendingNoteChanges.get(id)?.deleted || pendingNoteChanges.get(id)?.permanentlyDeleted) {
      return Promise.resolve();
    }
    await window.e2eeReadyPromise;
    const { encryptNote } = await import('/crypto.js');
    // title/body ne sont JAMAIS envoyés en clair : seul le ciphertext part
    // sur le réseau. Le serveur stocke enc_ciphertext/enc_iv, illisibles
    // sans la clé privée de l'utilisateur.
    const enc = await encryptNote(window.E2EE_NOTES_KEY, {title: n.title, body: n.body});
    const payload = {id: n.id, enc_ciphertext: enc.ciphertext, enc_iv: enc.iv, color: n.color || ''};
    return authFetch('index.php?action=notes_save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(async res => {
      if(!res.ok){
        const err = await res.json().catch(()=>({}));
        console.error('Erreur sauvegarde note:', err);
      }
    }).catch(err => console.error('Erreur réseau notes_save:', err));
  });
}
function deleteNoteFromServer(id){
  return queueNoteRequest(id, () => authFetch('index.php?action=notes_delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  }));
}
async function setDeletedOnServer(id, deleted){
  pendingNoteChanges.set(id, Object.assign({}, pendingNoteChanges.get(id), {deleted}));
  try {
    const res = await queueNoteRequest(id, () => authFetch('index.php?action=notes_set_deleted', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id, deleted})
    }));
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error('Erreur suppression note (serveur):', res.status, err);
      alert("La suppression n'a pas pu être enregistrée sur le serveur. Réessaie.");
      return; // on garde l'entrée dans pendingNoteChanges pour ne pas perdre l'état localement
    }
    // On garde le pending pour deleted=true : le polling ne fera pas réapparaître la note.
    if (!deleted) pendingNoteChanges.delete(id);
  } catch (err) {
    console.error('Erreur réseau notes_set_deleted:', err);
    alert("Impossible de contacter le serveur pour supprimer la note. Vérifie ta connexion.");
  }
}
async function setPinnedOnServer(id, pinned){
  pendingNoteChanges.set(id, Object.assign({}, pendingNoteChanges.get(id), {pinned}));
  try {
    const res = await queueNoteRequest(id, () => authFetch('index.php?action=notes_set_pinned', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id, pinned})
    }));
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error('Erreur épinglage note (serveur):', res.status, err);
      return;
    }
    pendingNoteChanges.delete(id);
  } catch (err) {
    console.error('Erreur réseau notes_set_pinned:', err);
  }
}

async function loadNotes(){
  await window.e2eeReadyPromise;
  const { decryptNote, decryptText } = await import('/crypto.js');
  const res = await apiFetch('index.php?action=notes_list');
  const payload = await res.json();
  const serverNotes = payload.notes ?? payload; // rétrocompat
  window._noteGroups = payload.groups ?? [];
  // Déchiffrement local : le serveur n'a renvoyé que du ciphertext.
  const decrypted = await Promise.all(serverNotes.map(async n => {
    let out = n;
    if (n.enc_ciphertext) {
      try {
        const { title, body } = await decryptNote(window.E2EE_NOTES_KEY, n.enc_ciphertext, n.enc_iv);
        out = Object.assign({}, n, { title, body });
      } catch (err) {
        console.error('Échec déchiffrement note', n.id, err);
        out = Object.assign({}, n, { title: '[Erreur de déchiffrement]', body: '' });
      }
    }
    if (Array.isArray(n.images) && n.images.length) {
      const images = await Promise.all(n.images.map(async im => {
        if (!im.enc_ciphertext) return im; // image pas encore migrée (transition)
        try {
          const data = await decryptText(window.E2EE_NOTES_KEY, im.enc_ciphertext, im.enc_iv);
          return { id: im.id, data };
        } catch (err) {
          console.error('Échec déchiffrement image', im.id, err);
          return { id: im.id, data: '' };
        }
      }));
      out = Object.assign({}, out, { images });
    }
    return out;
  }));
  // On réapplique les changements pas encore confirmés par le serveur
  // (ex: suppression en cours) pour éviter un retour en arrière visuel.
  notes = decrypted
    .filter(n => !(pendingNoteChanges.get(n.id)?.permanentlyDeleted))
    .map(n => pendingNoteChanges.has(n.id) ? Object.assign({}, n, pendingNoteChanges.get(n.id)) : n);
  render();
  await ensurePasswordNote();
}

// Crée une note "Mot de passe" non supprimable pour les comptes qui n'en
// ont pas encore (nouveaux comptes, ou comptes migrés avant l'ajout de
// cette fonctionnalité).
let passwordNoteEnsured = false;
async function ensurePasswordNote(){
  if (passwordNoteEnsured) return;
  if (notes.some(n => n.protected)) { passwordNoteEnsured = true; return; }
  passwordNoteEnsured = true;
  try {
    const { encryptNote } = await import('/crypto.js');
    const id = generateNoteId();
    const enc = await encryptNote(window.E2EE_NOTES_KEY, { title: 'Mot de passe', body: '' });
    const res = await authFetch('index.php?action=notes_save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id, enc_ciphertext: enc.ciphertext, enc_iv: enc.iv, color: '', protected: true})
    });
    if (res.ok) loadNotes();
  } catch(e) {
    console.error('Erreur création note "Mot de passe":', e);
    passwordNoteEnsured = false;
  }
}

// Rafraîchissement automatique des notes (polling)
// pour voir les ajouts/modifs des autres membres sans recharger la page.
setInterval(() => {
  const active = document.activeElement;
  const isEditingNote = active && (
    active === titleInput ||
    active === bodyInput ||
    active.classList?.contains('note-title') ||
    active.classList?.contains('note-body')
  );
  const modalOpen = document.querySelector('.note-overlay');
  if (isEditingNote || modalOpen) return;
  loadNotes();
}, 3000);


function autoSave(){
  const title = titleInput.value.trim();
  const body = bodyInput.value.trim();

  if(!title && !body){
    if(draftId){
      notes = notes.filter(n => n.id !== draftId);
      deleteNoteFromServer(draftId);
      draftId = null;
      render();
    }
    return;
  }

  if(draftId){
    const n = notes.find(n => n.id === draftId);
    if(n){
      n.title = title;
      n.body = body;
      saveNoteToServer(n);
    }
  } else {
    draftId = generateNoteId();
    const n = {
      id: draftId,
      title,
      body,
      pinned: false,
      deleted: false,
      color: '',
      images: []
    };
    notes.unshift(n);
    saveNoteToServer(n);
  }
  render();
}

titleInput.addEventListener('keydown', e => {
  if(e.key === 'Enter'){
    e.preventDefault();
    autoSave();
    clearComposer();
    titleInput.focus();
  }
});
bodyInput.addEventListener('keydown', e => {
  if(e.key === 'Enter' && !e.shiftKey){
    e.preventDefault();
    autoSave();
    clearComposer();
    titleInput.focus();
  }
});

function deleteNote(id){
  const n = notes.find(n => n.id === id);
  if(n && n.protected){
    alert('Cette note ne peut pas être supprimée.');
    return;
  }
  if(n){
    n.deleted = true;
    setDeletedOnServer(id, true);
  }
  render();
}

function restoreNote(id){
  const n = notes.find(n => n.id === id);
  if(n){
    n.deleted = false;
    setDeletedOnServer(id, false);
  }
  render();
}

function permanentDeleteNote(id){
  notes = notes.filter(n => n.id !== id);
  pendingNoteChanges.set(id, {permanentlyDeleted: true});
  deleteNoteFromServer(id).then(async res => {
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      console.error('Erreur suppression définitive (serveur):', res.status, err);
      alert("La suppression n'a pas pu être enregistrée sur le serveur. Réessaie.");
      return; // on garde pendingNoteChanges pour que le polling ne fasse pas réapparaître la note
    }
    pendingNoteChanges.delete(id);
  }).catch(err => {
    console.error('Erreur réseau notes_delete:', err);
    alert("Impossible de contacter le serveur pour supprimer la note. Vérifie ta connexion.");
  });
  render();
}

function togglePin(id){
  const n = notes.find(n => n.id === id);
  if(n){
    n.pinned = !n.pinned;
    setPinnedOnServer(id, n.pinned);
  }
  render();
}

const NOTE_COLORS = [
  {name: 'Défaut', value: ''},
  {name: 'Rouge', value: '#5c2b29'},
  {name: 'Orange', value: '#614a19'},
  {name: 'Jaune', value: '#5c5216'},
  {name: 'Vert', value: '#345920'},
  {name: 'Bleu', value: '#16414f'},
  {name: 'Violet', value: '#42275e'},
  {name: 'Rose', value: '#5c2145'},
  {name: 'Gris', value: '#3c3c3c'},
];

let openColorPopover = null;
function closeColorPopover(){
  if(openColorPopover){
    openColorPopover.remove();
    openColorPopover = null;
    document.removeEventListener('click', closeColorPopover);
  }
}
function openColorPicker(anchorEl, n, cardEl){
  if(openColorPopover){ closeColorPopover(); return; }
  const pop = document.createElement('div');
  pop.style.cssText = `
    position:absolute; z-index:2000; background:var(--card); border:1px solid var(--line);
    border-radius:10px; padding:8px; box-shadow:0 6px 20px rgba(0,0,0,0.2);
    display:grid; grid-template-columns:repeat(3,28px); gap:8px;
  `;
  NOTE_COLORS.forEach(c => {
    const sw = document.createElement('button');
    sw.type = 'button';
    sw.title = c.name;
    sw.style.cssText = `
      width:28px; height:28px; border-radius:50%; cursor:pointer;
      border:2px solid ${n.color === c.value ? 'var(--accent)' : 'var(--line)'};
      background:${c.value || 'var(--card)'};
    `;
    sw.addEventListener('click', (e) => {
      e.stopPropagation();
      n.color = c.value;
      if (c.value) {
        cardEl.style.background = c.value;
        cardEl.style.backgroundImage = 'none';
      } else {
        cardEl.style.background = '';
        cardEl.style.backgroundImage = '';
      }
      n._modified = Date.now();
      saveNoteToServer(n);
      closeColorPopover();
    });
    pop.appendChild(sw);
  });
  document.body.appendChild(pop);
  const rect = anchorEl.getBoundingClientRect();
  pop.style.top = (window.scrollY + rect.bottom + 6) + 'px';
  pop.style.left = (window.scrollX + rect.left) + 'px';
  openColorPopover = pop;
  setTimeout(() => document.addEventListener('click', closeColorPopover), 0);
}

// --- Palette de couleurs texte / surlignage (grille + personnalisé) ---
const SWATCH_HUES = [0, 30, 55, 100, 160, 190, 215, 260, 300];
function swatchGridRows(){
  const rows = [];
  rows.push(Array.from({length: 7}, (_, i) => `hsl(0,0%,${15 + i * 10}%)`));
  [[75, 50], [55, 35], [45, 25], [38, 18], [32, 10]].forEach(([s, l]) => {
    rows.push(SWATCH_HUES.map(h => `hsl(${h},${s}%,${l}%)`));
  });
  return rows;
}
const CUSTOM_SWATCH_KEY = 'nk_custom_colors';
function getCustomSwatches(){
  try { return JSON.parse(localStorage.getItem(CUSTOM_SWATCH_KEY) || '[]'); } catch(e){ return []; }
}
function addCustomSwatch(c){
  const list = getCustomSwatches().filter(x => x !== c);
  list.unshift(c);
  if (list.length > 9) list.length = 9;
  try { localStorage.setItem(CUSTOM_SWATCH_KEY, JSON.stringify(list)); } catch(e){}
}
let openSwatchPopover = null;
function closeSwatchPopoverOnDocClick(e){
  if (openSwatchPopover && !openSwatchPopover.contains(e.target)) closeSwatchPopover();
}
function closeSwatchPopover(){
  if (openSwatchPopover){
    openSwatchPopover.remove();
    openSwatchPopover = null;
    document.removeEventListener('click', closeSwatchPopoverOnDocClick, true);
  }
}
function openSwatchColorPicker(anchorEl, {allowNone = false, onPick}){
  if (openSwatchPopover){ closeSwatchPopover(); return; }
  const pop = document.createElement('div');
  pop.className = 'swatch-popover';
  pop.addEventListener('mousedown', e => e.stopPropagation());
  pop.addEventListener('click', e => e.stopPropagation());

  if (allowNone){
    const noneBtn = document.createElement('button');
    noneBtn.type = 'button';
    noneBtn.className = 'swatch-none-btn';
    noneBtn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l6-6 4 4-6 6-4-4Z"/><path d="M13 9 4 18v2h2l9-9"/><path d="M17 5l2 2"/><line x1="3" y1="21" x2="21" y2="3"/></svg><span>Aucune</span>`;
    noneBtn.addEventListener('click', () => { onPick(null); closeSwatchPopover(); });
    pop.appendChild(noneBtn);
  }

  const grid = document.createElement('div');
  grid.className = 'swatch-grid';
  swatchGridRows().forEach(row => row.forEach(c => {
    const sw = document.createElement('button');
    sw.type = 'button';
    sw.className = 'swatch-dot';
    sw.style.background = c;
    sw.title = c;
    sw.addEventListener('click', () => { onPick(c); closeSwatchPopover(); });
    grid.appendChild(sw);
  }));
  pop.appendChild(grid);

  const label = document.createElement('div');
  label.className = 'swatch-custom-label';
  label.textContent = 'PERSONNALISÉ';
  pop.appendChild(label);

  const customRow = document.createElement('div');
  customRow.className = 'swatch-grid';
  getCustomSwatches().forEach(c => {
    const sw = document.createElement('button');
    sw.type = 'button';
    sw.className = 'swatch-dot';
    sw.style.background = c;
    sw.title = c;
    sw.addEventListener('click', () => { onPick(c); closeSwatchPopover(); });
    customRow.appendChild(sw);
  });
  pop.appendChild(customRow);

  const actions = document.createElement('div');
  actions.className = 'swatch-actions';
  const addBtn = document.createElement('button');
  addBtn.type = 'button';
  addBtn.className = 'swatch-action-btn';
  addBtn.title = 'Ajouter une couleur';
  addBtn.textContent = '+';
  const hiddenInput = document.createElement('input');
  hiddenInput.type = 'color';
  hiddenInput.style.cssText = 'position:absolute;width:0;height:0;opacity:0;pointer-events:none;';
  hiddenInput.addEventListener('input', () => {
    addCustomSwatch(hiddenInput.value);
    onPick(hiddenInput.value);
    closeSwatchPopover();
  });
  addBtn.addEventListener('click', () => hiddenInput.click());
  actions.appendChild(addBtn);
  actions.appendChild(hiddenInput);

  if (window.EyeDropper){
    const eyeBtn = document.createElement('button');
    eyeBtn.type = 'button';
    eyeBtn.className = 'swatch-action-btn';
    eyeBtn.title = 'Pipette';
    eyeBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m2 22 1-4 9.5-9.5"/><path d="M13.5 6.5 17 3l4 4-3.5 3.5"/><path d="m9 13 4 4"/></svg>';
    eyeBtn.addEventListener('click', async () => {
      try {
        const res = await new EyeDropper().open();
        addCustomSwatch(res.sRGBHex);
        onPick(res.sRGBHex);
      } catch(e){}
      closeSwatchPopover();
    });
    actions.appendChild(eyeBtn);
  }
  pop.appendChild(actions);

  document.body.appendChild(pop);
  const rect = anchorEl.getBoundingClientRect();
  pop.style.top = (window.scrollY + rect.bottom + 6) + 'px';
  pop.style.left = (window.scrollX + rect.left) + 'px';
  requestAnimationFrame(() => {
    const pr = pop.getBoundingClientRect();
    if (pr.right > window.innerWidth) {
      pop.style.left = Math.max(4, window.scrollX + window.innerWidth - pr.width - 8) + 'px';
    }
  });
  openSwatchPopover = pop;
  setTimeout(() => document.addEventListener('click', closeSwatchPopoverOnDocClick, true), 0);
}

function shareNote(n){
  const text = [n.title, n.body].filter(Boolean).join('\n\n');
  if (navigator.share) {
    navigator.share({ title: n.title || 'Note', text }).catch(() => {});
  } else if (navigator.clipboard) {
    navigator.clipboard.writeText(text).then(() => {
      alert('Note copiée dans le presse-papiers');
    }).catch(() => {
      alert('Impossible de partager la note');
    });
  } else {
    alert('Le partage n\'est pas supporté sur cet appareil');
  }
}

let _openOverlayCount = 0;
function lockPageScroll() {
  _openOverlayCount++;
  document.body.style.overflow = 'hidden';
}
function unlockPageScroll() {
  _openOverlayCount = Math.max(0, _openOverlayCount - 1);
  if (_openOverlayCount === 0) document.body.style.overflow = '';
}

function noteCard(n){
  const div = document.createElement('div');
  div.className = 'note' + (n.pinned ? ' pinned' : '');
  if (n.color) {
    div.style.background = n.color;
    div.style.backgroundImage = 'none';
  }
  div.innerHTML = `
    <button class="pin-toggle" title="Épingler" aria-label="Épingler la note">${n.pinned ? '★' : '☆'}</button>
    <div class="fs-toolbar">
      <button type="button" class="fs-btn" data-cmd="undo" title="Annuler">↶</button>
      <button type="button" class="fs-btn" data-cmd="redo" title="Rétablir">↷</button>
      <button type="button" class="fs-btn" data-action="print" title="Imprimer"></button>
      <button type="button" class="fs-btn" data-action="spellcheck" title="Orthographe">✓ᴬ</button>
      <button type="button" class="fs-btn" data-cmd="removeFormat" title="Format peintre"></button>
      <span class="fs-sep"></span>
      <select class="fs-zoom" title="Zoom">
        <option value="75">75%</option>
        <option value="100" selected>100%</option>
        <option value="125">125%</option>
        <option value="150">150%</option>
      </select>
      <select class="fs-style" title="Style">
        <option value="p" selected>Texte normal</option>
        <option value="h1">Titre 1</option>
        <option value="h2">Titre 2</option>
        <option value="h3">Titre 3</option>
        <option value="blockquote">Citation</option>
      </select>
      <select class="fs-font" title="Police">
        <option value="'Segoe UI', system-ui, sans-serif" selected>Défaut</option>
        <option value="Arial, sans-serif">Arial</option>
        <option value="Georgia, serif">Georgia</option>
        <option value="'Times New Roman', serif">Times New Roman</option>
        <option value="'Courier New', monospace">Courier New</option>
        <option value="Verdana, sans-serif">Verdana</option>
      </select>
      <span class="fs-sep"></span>
      <div class="fs-size-row">
        <button type="button" class="fs-btn" data-action="size-dec" title="Réduire">−</button>
        <input type="number" class="fs-size" value="15" min="8" max="72" title="Taille">
        <button type="button" class="fs-btn" data-action="size-inc" title="Agrandir">+</button>
      </div>
      <span class="fs-sep"></span>
      <div style="display:flex;gap:4px;width:100%;">
        <button type="button" class="fs-btn" data-cmd="bold" title="Gras" style="width:auto;flex:1;justify-content:center;"><b>G</b></button>
        <button type="button" class="fs-btn" data-cmd="italic" title="Italique" style="width:auto;flex:1;justify-content:center;"><i>I</i></button>
        <button type="button" class="fs-btn" data-cmd="underline" title="Souligner" style="width:auto;flex:1;justify-content:center;"><u>S</u></button>
      </div>
      <button type="button" class="fs-textcolor-btn" title="Couleur du texte" data-color="#e5e5e0">
        <span class="fs-textcolor-letter">A</span><span class="fs-textcolor-bar" style="background:#e5e5e0"></span>
      </button>
      <button type="button" class="fs-hilite-btn" title="Surligner" data-color="#ffff00">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l6-6 4 4-6 6-4-4Z"/><path d="M13 9 4 18v2h2l9-9"/><path d="M17 5l2 2"/></svg>
        <span class="fs-textcolor-bar" style="background:#ffff00"></span>
      </button>
      <button type="button" class="fs-btn" data-action="link" title="Lien"></button>
      <button type="button" class="fs-btn" data-action="image" title="Insérer une image"></button>
      <span class="fs-sep"></span>
      <select class="fs-align" title="Alignement">
        <option value="justifyLeft" selected>Gauche</option>
        <option value="justifyCenter">Centré</option>
        <option value="justifyRight">Droite</option>
        <option value="justifyFull">Justifié</option>
      </select>
      <select class="fs-linespacing" title="Interligne">
        <option value="1">1</option>
        <option value="1.15" selected>1.15</option>
        <option value="1.5">1.5</option>
        <option value="2">2</option>
      </select>
      <button type="button" class="fs-btn" data-action="checklist" title="Liste de contrôle"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="6" height="6" rx="1"/><path d="M4.5 7l1 1 2-2"/><line x1="12" y1="7" x2="21" y2="7"/><rect x="3" y="14" width="6" height="6" rx="1"/><line x1="12" y1="17" x2="21" y2="17"/></svg></button>
      <button type="button" class="fs-btn" data-cmd="insertUnorderedList" title="Liste à puces">•≡</button>
      <button type="button" class="fs-btn" data-cmd="outdent" title="Réduire le retrait">⇤</button>
      <button type="button" class="fs-btn" data-cmd="indent" title="Augmenter le retrait">⇥</button>
      <button type="button" class="fs-btn" data-action="clear" title="Effacer la mise en forme">Tx</button>
      <button type="button" class="fs-btn" data-action="more" title="Plus">⋮</button>
    </div>
    <div class="note-modal-body">
      <div class="note-title" contenteditable="false" spellcheck="false" autocomplete="off" data-lpignore="true" data-1p-ignore data-bwignore>${escapeHtml(n.title)}</div>
      <div class="note-body" contenteditable="false" spellcheck="false" autocomplete="off" data-lpignore="true" data-1p-ignore data-bwignore>${escapeHtml(n.body)}</div>
      <div class="note-images" style="display:${(n.images && n.images.length) ? 'grid' : 'none'};grid-template-columns:repeat(auto-fill,minmax(70px,1fr));gap:6px;margin-top:10px;"></div>
    </div>
    <div class="note-modal-toolbar">
      <div class="toolbar-icons">
        <button type="button" title="Plein écran" aria-label="Plein écran"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M21 8V5a2 2 0 0 0-2-2h-3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/></svg></button>
        <button type="button" title="Couleur" aria-label="Couleur de la note"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22a10 10 0 1 1 0-20 8 8 0 0 1 8 8c0 2-1 3-3 3h-2a1.5 1.5 0 0 0-1 2.6c.3.3.5.7.5 1.1 0 1.3-1.1 2.3-2.5 2.3Z"/><circle cx="7" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="9.5" cy="7.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="14.5" cy="7.5" r="1.2" fill="currentColor" stroke="none"/></svg></button>
        <button type="button" title="Image" aria-label="Ajouter une image"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="M21 16l-5-5-4 4-2-2-5 5"/></svg></button>
        <button type="button" title="Partager" aria-label="Partager la note"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="M8.2 10.7l7.6-4.4M8.2 13.3l7.6 4.4"/></svg></button>
        <button type="button" title="Supprimer" aria-label="Supprimer la note"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/><path d="M10 11v6M14 11v6"/></svg></button>
      </div>
      <button type="button" class="close-btn">Fermer</button>
    </div>
  `;
  div.querySelector('.pin-toggle').onclick = (e) => { e.stopPropagation(); togglePin(n.id); };

  const titleEl2 = div.querySelector('.note-title');
  const bodyEl2 = div.querySelector('.note-body');
  const toolbar = div.querySelector('.fs-toolbar');

  function focusBody() { bodyEl2.focus(); }

  bodyEl2.addEventListener('click', e => {
    const box = e.target.closest('.chk-box');
    if (!box) return;
    e.preventDefault();
    box.closest('.checklist-item')?.classList.toggle('checked');
    scheduleSave();
  });

  // Boutons execCommand simples
  toolbar.querySelectorAll('.fs-btn[data-cmd]').forEach(btn => {
    btn.addEventListener('mousedown', e => e.preventDefault()); // garder le focus
    btn.addEventListener('click', e => {
      e.stopPropagation();
      focusBody();
      document.execCommand(btn.dataset.cmd, false, null);
    });
  });

  // Actions spéciales
  toolbar.querySelectorAll('.fs-btn[data-action]').forEach(btn => {
    btn.addEventListener('mousedown', e => e.preventDefault());
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const action = btn.dataset.action;
      if (action === 'print') {
        window.print();
      } else if (action === 'spellcheck') {
        const on = bodyEl2.spellcheck;
        bodyEl2.spellcheck = !on;
        titleEl2.spellcheck = !on;
        btn.style.opacity = bodyEl2.spellcheck ? '1' : '.5';
      } else if (action === 'link') {
        const url = prompt('Adresse du lien :', 'https://');
        if (url) { focusBody(); document.execCommand('createLink', false, url); }
      } else if (action === 'image') {
        const imgBtn = div.querySelector('button[title="Image"]');
        if (imgBtn) imgBtn.click();
      } else if (action === 'checklist') {
        focusBody();
        document.execCommand('insertHTML', false, '<div class="checklist-item"><span class="chk-box" contenteditable="false"></span><span class="chk-text">&nbsp;</span></div>');
      } else if (action === 'clear') {
        focusBody();
        document.execCommand('removeFormat', false, null);
      } else if (action === 'size-inc' || action === 'size-dec') {
        const sizeInput = toolbar.querySelector('.fs-size');
        let v = parseInt(sizeInput.value, 10) || 15;
        v += action === 'size-inc' ? 1 : -1;
        sizeInput.value = v;
        bodyEl2.style.fontSize = v + 'px';
      } else if (action === 'more') {
        // réservé pour options futures
      }
    });
  });

  const zoomSelect = toolbar.querySelector('.fs-zoom');
  zoomSelect.addEventListener('change', () => {
    div.querySelector('.note-modal-body').style.zoom = (parseInt(zoomSelect.value, 10) / 100);
  });

  const styleSelect = toolbar.querySelector('.fs-style');
  styleSelect.addEventListener('mousedown', e => e.stopPropagation());
  styleSelect.addEventListener('change', () => {
    focusBody();
    document.execCommand('formatBlock', false, styleSelect.value);
  });

  const fontSelect = toolbar.querySelector('.fs-font');
  fontSelect.addEventListener('mousedown', e => e.stopPropagation());
  fontSelect.addEventListener('change', () => {
    bodyEl2.style.fontFamily = fontSelect.value;
    titleEl2.style.fontFamily = fontSelect.value;
  });

  const sizeInput = toolbar.querySelector('.fs-size');
  sizeInput.addEventListener('mousedown', e => e.stopPropagation());
  sizeInput.addEventListener('change', () => {
    bodyEl2.style.fontSize = sizeInput.value + 'px';
  });

  const colorBtn = toolbar.querySelector('.fs-textcolor-btn');
  colorBtn.addEventListener('mousedown', e => e.stopPropagation());
  colorBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openSwatchColorPicker(colorBtn, {
      allowNone: false,
      onPick: (c) => {
        focusBody();
        document.execCommand('foreColor', false, c);
        colorBtn.dataset.color = c;
        colorBtn.querySelector('.fs-textcolor-bar').style.background = c;
      }
    });
  });

  const hiliteBtn = toolbar.querySelector('.fs-hilite-btn');
  hiliteBtn.addEventListener('mousedown', e => e.stopPropagation());
  hiliteBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openSwatchColorPicker(hiliteBtn, {
      allowNone: true,
      onPick: (c) => {
        focusBody();
        document.execCommand('hiliteColor', false, c || 'transparent');
        hiliteBtn.dataset.color = c || '';
        hiliteBtn.querySelector('.fs-textcolor-bar').style.background = c || 'transparent';
      }
    });
  });

  const alignSelect = toolbar.querySelector('.fs-align');
  alignSelect.addEventListener('mousedown', e => e.stopPropagation());
  alignSelect.addEventListener('change', () => {
    focusBody();
    document.execCommand(alignSelect.value, false, null);
  });

  const spacingSelect = toolbar.querySelector('.fs-linespacing');
  spacingSelect.addEventListener('mousedown', e => e.stopPropagation());
  spacingSelect.addEventListener('change', () => {
    bodyEl2.style.lineHeight = spacingSelect.value;
  });

  const fullscreenBtn = div.querySelector('button[title="Plein écran"]');
  if (fullscreenBtn) {
    fullscreenBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!document.fullscreenElement) {
        div.requestFullscreen().catch(err => console.error('Fullscreen error:', err));
      } else {
        document.exitFullscreen();
      }
    });
    document.addEventListener('fullscreenchange', () => {
      const icon = fullscreenBtn.querySelector('svg');
      if (document.fullscreenElement === div) {
        icon.innerHTML = '<path d="M8 3v3a2 2 0 0 1-2 2H3"/><path d="M21 8h-3a2 2 0 0 1-2-2V3"/><path d="M3 16h3a2 2 0 0 1 2 2v3"/><path d="M16 21v-3a2 2 0 0 1 2-2h3"/>';
        document.body.style.overflow = 'hidden';
      } else {
        icon.innerHTML = '<path d="M8 3H5a2 2 0 0 0-2 2v3"/><path d="M21 8V5a2 2 0 0 0-2-2h-3"/><path d="M3 16v3a2 2 0 0 0 2 2h3"/><path d="M16 21h3a2 2 0 0 0 2-2v-3"/>';
        document.body.style.overflow = '';
      }
    });
    div.addEventListener('keydown', e => {
      if (e.key === 'Escape' && document.fullscreenElement === div) {
        e.stopPropagation();
        document.exitFullscreen();
      }
    });
  }

  const colorBtn2 = div.querySelector('button[title="Couleur"]');
  if (colorBtn2) {
    colorBtn2.addEventListener('click', (e) => {
      e.stopPropagation();
      openColorPicker(colorBtn2, n, div);
    });
  }

  const imagesEl = div.querySelector('.note-images');
  const shareBtn = div.querySelector('button[title="Partager"]');
  if (shareBtn) {
    shareBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      shareNote(n);
    });
  }
  const deleteBtn = div.querySelector('button[title="Supprimer"]');
  if (deleteBtn) {
    if (n.protected) {
      deleteBtn.style.display = 'none';
    } else {
      deleteBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        clearTimeout(noteSaveTimer);
        closeModal();
        deleteNote(n.id);
      });
    }
  }
  function renderNoteImages(){
    if(!imagesEl) return;
    imagesEl.innerHTML = '';
    const imgs = n.images || [];
    imagesEl.style.display = imgs.length ? 'grid' : 'none';
    imgs.forEach(im => {
      const wrap = document.createElement('div');
      wrap.style.cssText = 'position:relative;border-radius:6px;overflow:hidden;aspect-ratio:1;background:var(--bg);';
      const img = document.createElement('img');
      img.src = im.data;
      img.style.cssText = 'width:100%;height:100%;object-fit:cover;display:block;cursor:pointer;';
      img.addEventListener('click', (e) => { e.stopPropagation(); window.open(im.data, '_blank'); });
      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.textContent = '×';
      delBtn.title = 'Supprimer la photo';
      delBtn.style.cssText = 'position:absolute;top:2px;right:2px;width:18px;height:18px;border-radius:50%;border:none;background:rgba(0,0,0,0.55);color:#fff;font-size:12px;line-height:1;cursor:pointer;';
      delBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        n.images = (n.images || []).filter(x => x.id !== im.id);
        renderNoteImages();
        authFetch('index.php?action=notes_image_delete', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: n.id, imageId: im.id})
        }).catch(err => console.error('Erreur suppression image:', err));
      });
      wrap.appendChild(img);
      wrap.appendChild(delBtn);
      imagesEl.appendChild(wrap);
    });
  }
  renderNoteImages();

  const imageBtn = div.querySelector('button[title="Image"]');
  if (imageBtn) {
    imageBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!n.id) return;
      noteImageInput.dataset.noteId = n.id;
      noteImageInput._onPick = async (dataUrl) => {
        n.images = n.images || [];
        const tempId = 'pending_' + Date.now();
        n.images.push({id: tempId, data: dataUrl});
        renderNoteImages();
        // Le serveur ne peut plus valider le contenu binaire une fois
        // chiffré (voir notes_image_add côté PHP) : la vérification de
        // format se fait ici, côté client, avant chiffrement.
        if (!/^data:image\/(png|jpe?g|gif|webp);base64,/.test(dataUrl)) {
          n.images = (n.images || []).filter(x => x.id !== tempId);
          renderNoteImages();
          console.error('Format image invalide, envoi annulé.');
          return;
        }
        await window.e2eeReadyPromise;
        const { encryptText } = await import('/crypto.js');
        const enc = await encryptText(window.E2EE_NOTES_KEY, dataUrl);
        authFetch('index.php?action=notes_image_add', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: n.id, enc_ciphertext: enc.ciphertext, enc_iv: enc.iv})
        }).then(async res => {
          const data = await res.json().catch(() => ({}));
          if (res.ok && data.imageId) {
            const item = (n.images || []).find(x => x.id === tempId);
            if (item) item.id = data.imageId;
          } else {
            n.images = (n.images || []).filter(x => x.id !== tempId);
            renderNoteImages();
            console.error('Erreur ajout image:', data);
          }
        }).catch(err => {
          n.images = (n.images || []).filter(x => x.id !== tempId);
          renderNoteImages();
          console.error('Erreur réseau ajout image:', err);
        });
      };
      noteImageInput.click();
    });
  }

  const titleEl = div.querySelector('.note-title');
  const bodyEl = div.querySelector('.note-body');
  const closeBtn = div.querySelector('.close-btn');

  let overlay = null;
  let originalParent = null;
  let originalNext = null;

  function openModal(){
    if(overlay) return;
    const existing = document.querySelectorAll('.note-overlay');
    existing.forEach(() => unlockPageScroll());
    existing.forEach(el => el.remove());
    originalParent = div.parentNode;
    originalNext = div.nextSibling;
    overlay = document.createElement('div');
    overlay.className = 'note-overlay';
    overlay.addEventListener('mousedown', e => {
      if(e.target === overlay) closeModal();
    });
    document.body.appendChild(overlay);
    overlay.appendChild(div);
    div.classList.add('expanded');
    if (!n.protected) titleEl.contentEditable = 'true';
    bodyEl.contentEditable = 'true';
    bodyEl.style.display = '';
    lockPageScroll();
    document.addEventListener('keydown', escHandler);
  }

  function closeModal(){
    if(!overlay) return;
    div.classList.remove('expanded');
    titleEl.contentEditable = 'false';
    bodyEl.contentEditable = 'false';
    if(!n.body) bodyEl.style.display = 'none';
    if(originalNext) originalParent.insertBefore(div, originalNext);
    else originalParent.appendChild(div);
    overlay.remove();
    overlay = null;
    unlockPageScroll();
    document.removeEventListener('keydown', escHandler);
  }

  function escHandler(e){
    if(e.key === 'Escape') closeModal();
  }

  div.addEventListener('click', e => {
    if(e.target.closest('.pin-toggle, .del, .note-modal-toolbar')) return;
    if(div.classList.contains('expanded')) return;
    openModal();
  });
  div.tabIndex = 0;
  div.addEventListener('keydown', e => {
    if(e.key === 'Enter' && !div.classList.contains('expanded') && !e.target.closest('.pin-toggle, .del, .note-modal-toolbar')) {
      e.preventDefault();
      openModal();
      bodyEl.focus();
    }
  });
  closeBtn.addEventListener('click', e => { e.stopPropagation(); closeModal(); });

  let noteSaveTimer = null;
  function scheduleNoteAutoSave(){
    clearTimeout(noteSaveTimer);
    noteSaveTimer = setTimeout(() => {
      n.title = titleEl.textContent.trim();
      n.body = bodyEl.innerText.trim();
      n._modified = Date.now();
      saveNoteToServer(n);
    }, 600);
  }

  titleEl.addEventListener('input', scheduleNoteAutoSave);
  bodyEl.addEventListener('input', scheduleNoteAutoSave);

  titleEl.addEventListener('blur', () => {
    clearTimeout(noteSaveTimer);
    n.title = titleEl.textContent.trim();
    titleEl.style.display = n.title ? '' : 'none';
    n._modified = Date.now();
    saveNoteToServer(n);
  });
  bodyEl.addEventListener('blur', () => {
    clearTimeout(noteSaveTimer);
    n.body = bodyEl.innerText.trim();
    n._modified = Date.now();
    saveNoteToServer(n);
  });
  [titleEl, bodyEl].forEach(el => {
    el.addEventListener('keydown', e => {
      if(e.key === 'Enter' && el === titleEl){
        e.preventDefault();
        bodyEl.focus();
      }
    });
  });

  return div;
}

// Génère un ID de note aléatoire sur 53 bits (précision entière max de
// Number en JS), au lieu de Date.now(). Un ID basé sur l'horodatage était
// prévisible : comme la colonne notes.id est une clé primaire GLOBALE
// (partagée entre tous les utilisateurs, pas d'auto-increment), un
// attaquant authentifié pouvait pré-insérer des notes avec des IDs
// correspondant à des timestamps futurs, provocant une collision de clé
// primaire (donc un échec silencieux) quand une victime crée une note à
// ce moment précis. Un ID aléatoire sur 53 bits rend cette attaque
// impraticable (probabilité de collision négligeable).
function generateNoteId(){
  const buf = new Uint32Array(2);
  crypto.getRandomValues(buf);
  // 21 bits + 32 bits = 53 bits, dans les limites de Number.isSafeInteger.
  return (buf[0] & 0x1FFFFF) * 0x100000000 + buf[1];
}

function escapeHtml(str){
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function trashCard(n){
  const div = document.createElement('div');
  div.className = 'note';
  div.innerHTML = `
    ${n.title ? `<div class="note-title">${escapeHtml(n.title)}</div>` : ''}
    <div class="note-body">${escapeHtml(n.body)}</div>
    <div class="note-footer" style="opacity:1;">
      <button class="del">Supprimer définitivement</button>
      <button class="restore">Restaurer</button>
    </div>
  `;
  div.querySelector('.del').onclick = () => permanentDeleteNote(n.id);
  div.querySelector('.restore').onclick = () => restoreNote(n.id);
  return div;
}

function renderTrash(){
  const trashed = notes.filter(n => n.deleted);
  const trashGrid = document.getElementById('trashGrid');
  const trashEmpty = document.getElementById('trashEmpty');
  trashGrid.innerHTML = '';
  trashEmpty.style.display = trashed.length ? 'none' : 'block';
  trashed.forEach(n => trashGrid.appendChild(trashCard(n)));
}

function textPrompt(message, defaultValue = '', type = 'text'){
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'pwd-overlay';
    overlay.innerHTML = `
      <div class="pwd-modal">
        <div class="pwd-modal-title">${escapeHtml(message)}</div>
        <input type="text" class="pwd-modal-input${type === 'password' ? ' pwd-masked' : ''}" autocomplete="off" name="field-${Math.random().toString(36).slice(2)}" data-lpignore="true" data-1p-ignore data-bwignore />
        <div class="pwd-modal-actions">
          <button type="button" class="btn pwd-cancel">Annuler</button>
          <button type="button" class="btn primary pwd-ok">OK</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);
    const input = overlay.querySelector('.pwd-modal-input');
    input.value = defaultValue;
    input.focus();
    input.select();

    const close = (value) => {
      overlay.remove();
      document.removeEventListener('keydown', onKeydown);
      resolve(value);
    };
    const onKeydown = (e) => {
      if(e.key === 'Enter') close(input.value);
      if(e.key === 'Escape') close(null);
    };

    overlay.querySelector('.pwd-ok').onclick = () => close(input.value);
    overlay.querySelector('.pwd-cancel').onclick = () => close(null);
    overlay.addEventListener('click', (e) => { if(e.target === overlay) close(null); });
    document.addEventListener('keydown', onKeydown);
  });
}

async function openPasswordNote(){
  const pwd = await textPrompt('Confirmez votre mot de passe pour accéder à cette note :', '', 'password');
  if(pwd === null) return;
  if(pwd === ''){ alert('Mot de passe requis.'); return; }
  try {
    const res = await authFetch('user/auth.php?action=verify_password', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({password: pwd})
    });
    if(!res.ok){
      alert('Mot de passe incorrect.');
      return;
    }
  } catch(e){
    alert('Erreur de vérification, réessayez.');
    return;
  }
  const n = notes.find(n => n.protected);
  if(!n){ alert('Note introuvable.'); return; }
  const card = noteCard(n);
  card.dataset.tempCard = '1';
  document.body.appendChild(card);
  card.click();
  const obs = new MutationObserver(() => {
    if(!document.querySelector('.note-overlay') && card.parentNode === document.body){
      card.remove();
      obs.disconnect();
    }
  });
  obs.observe(document.body, {childList: true});
}

// -------------------------------------------------------
// Groupes de notes — drag & drop
// -------------------------------------------------------
let dragNoteId = null;
let dragGroupId = null; // groupe d'origine si la note est dans un groupe

function makeDraggableCard(n){
  const card = noteCard(n);
  card.draggable = true;
  card.dataset.noteId = n.id;
  if(n.group_id) card.dataset.groupId = n.group_id;

  card.addEventListener('dragstart', e => {
    dragNoteId = n.id;
    dragGroupId = n.group_id || null;
    e.dataTransfer.effectAllowed = 'move';
    setTimeout(() => card.classList.add('dragging'), 0);
  });
  card.addEventListener('dragend', () => {
    dragNoteId = null;
    dragGroupId = null;
    card.classList.remove('dragging');
    document.querySelectorAll('.note.drop-target, .note-group.drop-target').forEach(el => el.classList.remove('drop-target'));
  });

  // Drop target : une note ordinaire peut recevoir une autre note
  card.addEventListener('dragover', e => {
    if(dragNoteId && dragNoteId !== n.id) {
      e.preventDefault();
      card.classList.add('drop-target');
    }
  });
  card.addEventListener('dragleave', () => card.classList.remove('drop-target'));
  card.addEventListener('drop', async e => {
    e.preventDefault();
    e.stopPropagation();
    card.classList.remove('drop-target');
    if(!dragNoteId || dragNoteId === n.id) return;
    const droppedNote = notes.find(x => x.id === dragNoteId);
    if(!droppedNote) return;

    // Si la note cible est déjà dans un groupe, ajouter la note déplacée à ce groupe
    if(n.group_id) {
      await moveNoteToGroup(dragNoteId, n.group_id, dragGroupId);
    } else {
      // Créer un nouveau groupe avec les deux notes
      const groupId = generateNoteId();
      await authFetch('index.php?action=notes_group_create', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ group_id: groupId, note_ids: [n.id, dragNoteId], title: '' })
      });
      loadNotes();
    }
  });

  return card;
}

async function moveNoteToGroup(noteId, groupId, oldGroupId) {
  await authFetch('index.php?action=notes_group_set', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ note_id: noteId, group_id: groupId, old_group_id: oldGroupId })
  });
  loadNotes();
}

// Lâcher une note glissée depuis un groupe sur la grille (hors carte/groupe) la retire du groupe.
function makeUngroupDropZone(container) {
  container.addEventListener('dragover', e => {
    if(dragNoteId && dragGroupId) e.preventDefault();
  });
  container.addEventListener('drop', async e => {
    if(!dragNoteId || !dragGroupId) return;
    e.preventDefault();
    await removeNoteFromGroup(dragNoteId, dragGroupId);
  });
}

async function removeNoteFromGroup(noteId, groupId) {
  await authFetch('index.php?action=notes_group_set', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ note_id: noteId, group_id: null, old_group_id: groupId })
  });
  loadNotes();
}

function groupCard(g, groupNotes, startExpanded = false) {
  const div = document.createElement('div');
  div.className = 'note-group';
  div.dataset.groupId = g.id;

  let expanded = startExpanded;

  function renderCollapsed() {
    div.innerHTML = '';
    div.classList.remove('group-expanded');
    expandedGroupId = null;

    // Aperçu empilé : 3 mini-cartes max
    const preview = document.createElement('div');
    preview.className = 'group-preview';
    groupNotes.slice(0, 3).forEach((n, i) => {
      const mini = document.createElement('div');
      mini.className = 'group-mini';
      mini.style.zIndex = 3 - i;
      mini.style.transform = `translateY(${i * 4}px) scale(${1 - i * 0.03})`;
      if(n.color){ mini.style.background = n.color; mini.style.backgroundImage = 'none'; }
      mini.innerHTML = `<div class="group-mini-title">${escapeHtml(n.title || n.body || '…')}</div>`;
      preview.appendChild(mini);
    });
    div.appendChild(preview);

    const footer = document.createElement('div');
    footer.className = 'group-footer';
    footer.innerHTML = `<span>${groupNotes.length} note${groupNotes.length > 1 ? 's' : ''}</span>`;
    div.appendChild(footer);

    div.onclick = (e) => { if(!e.target.closest('button')) { expanded = true; expandedGroupId = g.id; renderExpanded(); } };

    // Drop : ajouter une note au groupe
    div.addEventListener('dragover', e => { if(dragNoteId) { e.preventDefault(); div.classList.add('drop-target'); } });
    div.addEventListener('dragleave', () => div.classList.remove('drop-target'));
    div.addEventListener('drop', async e => {
      e.preventDefault();
      e.stopPropagation();
      div.classList.remove('drop-target');
      if(!dragNoteId) return;
      await moveNoteToGroup(dragNoteId, g.id, dragGroupId);
    });
  }

  function renderExpanded() {
    div.innerHTML = '';
    div.classList.add('group-expanded');
    div.onclick = null;

    const header = document.createElement('div');
    header.className = 'group-header';
    header.innerHTML = `<span>${groupNotes.length} note${groupNotes.length > 1 ? 's' : ''}</span>`;
    const closeBtn = document.createElement('button');
    closeBtn.className = 'group-close-btn';
    closeBtn.textContent = 'Fermer';
    closeBtn.onclick = (e) => { e.stopPropagation(); expanded = false; renderCollapsed(); };
    header.appendChild(closeBtn);
    div.appendChild(header);

    const grid = document.createElement('div');
    grid.className = 'group-inner-grid';
    groupNotes.forEach(n => {
      const wrapper = document.createElement('div');
      wrapper.className = 'group-note-wrapper';

      // Carte mini (non cliquable pour ouvrir modal — on gère ça ici)
      const card = makeDraggableCard(n);

      // Overlay de lecture/édition local : la carte reste dans le DOM du groupe
      card.addEventListener('click', e => {
        if(e.target.closest('.pin-toggle, .note-modal-toolbar, .group-remove-btn')) return;
        if(card.classList.contains('expanded')) return;
        e.stopPropagation();

        // Overlay global mais on n'y déplace PAS la carte
        const noteOverlay = document.createElement('div');
        noteOverlay.className = 'note-overlay';
        const clone = noteCard(n); // carte fraîche dans l'overlay
        clone.classList.add('expanded');
        const cloneTitleEl = clone.querySelector('.note-title');
        const cloneBodyEl = clone.querySelector('.note-body');
        if(!n.protected) cloneTitleEl.contentEditable = 'true';
        cloneBodyEl.contentEditable = 'true';
        cloneBodyEl.style.display = '';

        noteOverlay.appendChild(clone);
        document.body.appendChild(noteOverlay);
        lockPageScroll();

        function closeClone() {
          noteOverlay.remove();
          unlockPageScroll();
          document.removeEventListener('keydown', escClone);
        }
        clone.querySelector('.close-btn').addEventListener('click', e => { e.stopPropagation(); closeClone(); });
        noteOverlay.addEventListener('mousedown', e => { if(e.target === noteOverlay) closeClone(); });
        function escClone(e) { if(e.key === 'Escape') closeClone(); }
        document.addEventListener('keydown', escClone);
      });

      wrapper.appendChild(card);
      grid.appendChild(wrapper);
    });
    div.appendChild(grid);

    // Drop zone pour ajouter dans le groupe ouvert
    div.addEventListener('dragover', e => { if(dragNoteId) { e.preventDefault(); div.classList.add('drop-target'); } });
    div.addEventListener('dragleave', () => div.classList.remove('drop-target'));
    div.addEventListener('drop', async e => {
      e.preventDefault();
      e.stopPropagation();
      div.classList.remove('drop-target');
      if(!dragNoteId) return;
      await moveNoteToGroup(dragNoteId, g.id, dragGroupId);
    });
  }

  renderCollapsed();
  if(startExpanded) renderExpanded();
  return div;
}

let expandedGroupId = null;

function render(){
  const active = notes.filter(n => !n.deleted && !(n.protected && n.body));
  const pinned = active.filter(n => n.pinned && !n.group_id);
  const groups = window._noteGroups || [];

  // Notes appartenant à un groupe (non épinglées dans la grille principale)
  const groupedIds = new Set(active.filter(n => n.group_id).map(n => n.id));
  const others = active.filter(n => !n.pinned && !n.group_id);

  document.getElementById('emptyMsg').style.display = active.length ? 'none' : 'block';

  const pinnedSection = document.getElementById('pinnedSection');
  const pinnedGrid = document.getElementById('pinnedGrid');
  pinnedGrid.innerHTML = '';
  makeUngroupDropZone(pinnedGrid);
  if(pinned.length){
    pinnedSection.style.display = 'block';
    pinned.forEach(n => pinnedGrid.appendChild(makeDraggableCard(n)));
  } else {
    pinnedSection.style.display = 'none';
  }

  const othersSection = document.getElementById('othersSection');
  const othersGrid = document.getElementById('othersGrid');
  const othersLabel = document.getElementById('othersLabel');
  othersGrid.innerHTML = '';
  makeUngroupDropZone(othersGrid);
  if(others.length || groups.length){
    othersSection.style.display = 'block';
    othersLabel.textContent = pinned.length ? 'Autres' : 'Notes';
    // Afficher les groupes
    groups.forEach(g => {
      const groupNotes = active.filter(n => n.group_id === g.id);
      if(groupNotes.length) othersGrid.appendChild(groupCard(g, groupNotes, g.id === expandedGroupId));
    });
    // Notes sans groupe
    others.forEach(n => othersGrid.appendChild(makeDraggableCard(n)));
  } else {
    othersSection.style.display = 'none';
  }

  renderTrash();
}

loadNotes();

// Filet de sécurité : sur mobile, changer d'appli, verrouiller l'écran ou
// fermer l'onglet ne déclenche pas toujours 'blur'/'focusout' à temps.
// On force l'enregistrement immédiat du champ actif quand la page est masquée.
function flushActiveEdit(){
  const active = document.activeElement;
  if(!active) return;
  if(active === titleInput || active === bodyInput ||
     active.classList?.contains('note-title') || active.classList?.contains('note-body')){
    active.blur();
  }
}
document.addEventListener('visibilitychange', () => {
  if(document.hidden) flushActiveEdit();
});
window.addEventListener('pagehide', flushActiveEdit);

// -----------------------------------------------------
// Thème sombre
// -----------------------------------------------------
function isDarkTheme(){
  return document.documentElement.getAttribute('data-theme') === 'dark';
}
function toggleTheme(){
  const next = isDarkTheme() ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  localStorage.setItem('memo-theme', next);
}

// -----------------------------------------------------
// Documents
// -----------------------------------------------------
function htmlToPlainText(html) {
  const d = document.createElement('div');
  d.innerHTML = html || '';
  d.querySelectorAll('li').forEach(li => { li.textContent = '• ' + li.textContent; });
  d.querySelectorAll('div, p, br, li').forEach(el => { el.insertAdjacentText('afterend', '\n'); });
  return (d.textContent || d.innerText || '').replace(/[ \t]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim();
}

function formatDocDate(dateStr) {
  if (!dateStr) return '';
  const d = new Date(dateStr.replace(' ', 'T'));
  if (isNaN(d.getTime())) return '';
  return d.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' }) + ' ' + d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' });
}

function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' o';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' Ko';
  return (bytes / (1024 * 1024)).toFixed(1) + ' Mo';
}

function fileIconFor(mime) {
  if ((mime || '').startsWith('image/')) return '️';
  if (mime === 'application/pdf') return '';
  if ((mime || '').includes('word')) return '';
  if ((mime || '').includes('sheet') || (mime || '').includes('excel')) return '';
  return '';
}

async function loadDocuments() {
  const listEl = document.getElementById('documentsList');
  const emptyEl = document.getElementById('documentsEmptyMsg');
  try {
    const [filesRes, textRes] = await Promise.all([
      apiFetch('index.php?action=documents_list'),
      apiFetch('index.php?action=text_documents_list'),
    ]);
    let files = (await filesRes.json()).documents || [];
    let textDocs = (await textRes.json()).documents || [];
    if (docsSearchQuery) {
      textDocs = textDocs.filter(d => (d.title || 'Sans titre').toLowerCase().includes(docsSearchQuery) || (d.content || '').toLowerCase().includes(docsSearchQuery));
      files = files.filter(d => (d.filename || '').toLowerCase().includes(docsSearchQuery));
    }
    if (docsSortAZ) {
      textDocs = textDocs.slice().sort((a, b) => (a.title || 'Sans titre').localeCompare(b.title || 'Sans titre'));
    }
    listEl.innerHTML = '';
    listEl.style.cssText = docsViewMode === 'list'
      ? 'display:flex;flex-direction:column;gap:8px;'
      : 'display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:20px;';
    emptyEl.style.display = (files.length || textDocs.length) ? 'none' : 'block';

    if (docsViewMode === 'list') {
      textDocs.forEach(d => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--card);border-radius:8px;cursor:pointer;';
        row.innerHTML = `
          <span style="font-size:20px;"></span>
          <div style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(d.title || 'Sans titre')}</div>
          <div style="font-size:12px;color:#999;flex-shrink:0;white-space:nowrap;">${formatDocDate(d.updated_at)}</div>
        `;
        row.addEventListener('click', () => openTextDocumentEditor(d));
        listEl.appendChild(row);
      });
      files.forEach(d => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--card);border-radius:8px;';
        row.innerHTML = `
          <span style="font-size:20px;">${fileIconFor(d.mime_type)}</span>
          <div style="flex:1;min-width:0;">
            <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(d.filename)}</div>
            <div style="font-size:12px;color:#999;">${formatFileSize(d.size)}</div>
          </div>
          <button type="button" class="btn" data-dl="${d.id}" title="Télécharger">⬇</button>
        `;
        row.querySelector('[data-dl]').addEventListener('click', () => {
          window.open('index.php?action=documents_download&id=' + d.id, '_blank');
        });
        listEl.appendChild(row);
      });
      return;
    }

    textDocs.forEach(d => {
      const card = document.createElement('div');
      card.style.cssText = 'display:flex;flex-direction:column;align-items:center;cursor:pointer;';
      card.innerHTML = `
        <div style="width:100%;aspect-ratio:794/1123;background:#ffffff;border-radius:2px;box-shadow:0 1px 4px rgba(0,0,0,0.5);overflow:hidden;position:relative;">
          <div style="position:absolute;inset:0;padding:10% 12%;font-size:6px;line-height:1.4;color:#333;overflow:hidden;white-space:pre-wrap;word-break:break-word;font-family:'Iowan Old Style', Georgia, serif;">${escapeHtml(htmlToPlainText(d.content).slice(0, 600))}</div>
        </div>
        <div style="margin-top:8px;font-size:13px;text-align:center;width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink);">${escapeHtml(d.title || 'Sans titre')}</div>
      `;
      card.addEventListener('click', () => openTextDocumentEditor(d));
      listEl.appendChild(card);
    });

    files.forEach(d => {
      const card = document.createElement('div');
      card.style.cssText = 'display:flex;flex-direction:column;align-items:center;';
      card.innerHTML = `
        <div style="width:100%;aspect-ratio:794/1123;background:#ffffff;border-radius:2px;box-shadow:0 1px 4px rgba(0,0,0,0.5);overflow:hidden;position:relative;display:flex;align-items:center;justify-content:center;">
          <span style="font-size:40px;">${fileIconFor(d.mime_type)}</span>
          <button type="button" class="btn" data-dl="${d.id}" title="Télécharger" style="position:absolute;top:6px;right:6px;padding:2px 6px;font-size:10px;line-height:1;">⬇</button>
        </div>
        <div style="margin-top:8px;font-size:13px;text-align:center;width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink);">${escapeHtml(d.filename)}</div>
      `;
      card.querySelector('[data-dl]').addEventListener('click', () => {
        window.open('index.php?action=documents_download&id=' + d.id, '_blank');
      });
      listEl.appendChild(card);
    });
  } catch (err) {
    console.error('Échec chargement documents', err);
  }
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result.split(',')[1]);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

async function uploadDocuments(files) {
  for (const file of files) {
    if (file.size > 15 * 1024 * 1024) {
      alert(`"${file.name}" dépasse la taille maximale (15 Mo)`);
      continue;
    }
    try {
      const b64 = await fileToBase64(file);
      await authFetch('index.php?action=documents_add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ filename: file.name, mime_type: file.type || 'application/octet-stream', data: b64 })
      });
    } catch (err) {
      console.error('Échec envoi document', file.name, err);
      alert(`Échec de l'envoi de "${file.name}"`);
    }
  }
  loadDocuments();
}

let docsViewMode = 'grid';
let docsSortAZ = false;
let docsSearchQuery = '';

const docsViewToggleBtn = document.getElementById('docsViewToggleBtn');
if (docsViewToggleBtn) {
  docsViewToggleBtn.addEventListener('click', () => {
    docsViewMode = docsViewMode === 'grid' ? 'list' : 'grid';
    loadDocuments();
  });
}
const docsSortBtn = document.getElementById('docsSortBtn');
if (docsSortBtn) {
  docsSortBtn.addEventListener('click', () => {
    docsSortAZ = !docsSortAZ;
    docsSortBtn.style.color = docsSortAZ ? 'var(--accent)' : 'var(--ink)';
    loadDocuments();
  });
}

const addDocumentBtn = document.getElementById('addDocumentBtn');
const documentFileInput = document.getElementById('documentFileInput');
if (addDocumentBtn) {
  addDocumentBtn.addEventListener('click', async () => {
    try {
      const res = await authFetch('index.php?action=text_documents_create', { method: 'POST' });
      const payload = await res.json();
      openTextDocumentEditor({ id: payload.id, title: '', content: '' });
      loadDocuments();
    } catch (err) {
      console.error('Échec création document', err);
    }
  });
}

function openTextDocumentEditor(doc) {
  document.querySelectorAll('.note-overlay, .doc-fullpage').forEach(() => unlockPageScroll());
  document.querySelectorAll('.note-overlay, .doc-fullpage').forEach(el => el.remove());

  const page = document.createElement('div');
  page.className = 'doc-fullpage';
  page.style.cssText = 'position:fixed;inset:0;background:#525659;z-index:1000;display:flex;flex-direction:column;';
  page.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid rgba(255,255,255,0.1);background:var(--card);flex-shrink:0;">
      <button type="button" class="btn doc-close-btn" title="Retour">← Retour</button>
      <input type="text" class="doc-title-input" placeholder="Sans titre" value="${escapeHtml(doc.title || '')}" autocomplete="off" data-lpignore="true" data-1p-ignore data-bwignore style="flex:1;border:none;outline:none;background:transparent;color:var(--ink);font-family:'Iowan Old Style', Georgia, serif;font-size:18px;font-weight:bold;">
    </div>
    <div style="flex:1;display:flex;overflow:hidden;">
      <div class="doc-toolbar" style="width:160px;flex-shrink:0;background:var(--card);border-right:1px solid rgba(255,255,255,0.1);display:flex;flex-direction:column;align-items:center;gap:4px;padding:10px 6px;overflow-y:auto;">
        <button type="button" class="doc-tb-btn" data-action="search" title="Rechercher"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></button>
        <button type="button" class="doc-tb-btn" data-cmd="undo" title="Annuler"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M9 14 4 9l5-5"/><path d="M4 9h11a5 5 0 0 1 0 10h-1"/></svg></button>
        <button type="button" class="doc-tb-btn" data-cmd="redo" title="Rétablir"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M15 14l5-5-5-5"/><path d="M20 9H9a5 5 0 0 0 0 10h1"/></svg></button>
        <button type="button" class="doc-tb-btn" data-action="print" title="Imprimer"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M6 9V2h12v7"/><rect x="6" y="14" width="12" height="8"/><path d="M6 18H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2h-2"/></svg></button>
        <button type="button" class="doc-tb-btn" data-action="spellcheck" title="Orthographe">✓ᴬ</button>
        <button type="button" class="doc-tb-btn" data-cmd="removeFormat" title="Format peintre"></button>
        <div class="doc-tb-sep"></div>
        <select class="doc-tb-select" data-action="zoom" title="Zoom" style="width:100%;">
          <option value="75">75%</option>
          <option value="100" selected>100%</option>
          <option value="125">125%</option>
          <option value="150">150%</option>
        </select>
        <select class="doc-tb-select" data-cmd="formatBlock" title="Style" style="width:100%;">
          <option value="p" selected>Normal</option>
          <option value="h1">Titre 1</option>
          <option value="h2">Titre 2</option>
          <option value="h3">Titre 3</option>
          <option value="blockquote">Citation</option>
        </select>
        <select class="doc-tb-select" data-action="font" title="Police" style="width:100%;">
          <option value="'Iowan Old Style', Georgia, serif" selected>Défaut</option>
          <option value="Arial, sans-serif">Arial</option>
          <option value="Georgia, serif">Georgia</option>
          <option value="'Times New Roman', serif">Times</option>
          <option value="'Courier New', monospace">Courier</option>
          <option value="Verdana, sans-serif">Verdana</option>
        </select>
        <div style="display:flex;align-items:center;gap:2px;width:100%;">
          <button type="button" class="doc-tb-btn" data-action="size-dec" title="Réduire" style="flex:1;">−</button>
          <input type="number" class="doc-tb-size" value="15" min="8" max="72" style="width:32px;background:#2a2a26;color:#eee;border:1px solid #444;border-radius:4px;font-size:11px;text-align:center;">
          <button type="button" class="doc-tb-btn" data-action="size-inc" title="Agrandir" style="flex:1;">+</button>
        </div>
        <div class="doc-tb-sep"></div>
        <div style="display:flex;gap:4px;">
          <button type="button" class="doc-tb-btn" data-cmd="bold" title="Gras"><b>G</b></button>
          <button type="button" class="doc-tb-btn" data-cmd="italic" title="Italique"><i>I</i></button>
          <button type="button" class="doc-tb-btn" data-cmd="underline" title="Souligner"><u>S</u></button>
        </div>
        <button type="button" class="doc-tb-btn fs-textcolor-btn" data-action="color" title="Couleur du texte" data-color="#1a1a1a">
          <span class="fs-textcolor-letter">A</span><span class="fs-textcolor-bar" style="background:#1a1a1a"></span>
        </button>
        <button type="button" class="doc-tb-btn fs-hilite-btn" data-action="hilite" title="Surligner" data-color="#ffff00">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l6-6 4 4-6 6-4-4Z"/><path d="M13 9 4 18v2h2l9-9"/><path d="M17 5l2 2"/></svg>
          <span class="fs-textcolor-bar" style="background:#ffff00"></span>
        </button>
        <button type="button" class="doc-tb-btn" data-action="link" title="Lien"></button>
        <button type="button" class="doc-tb-btn" data-action="image" title="Image"></button>
        <div class="doc-tb-sep"></div>
        <select class="doc-tb-select" data-action="align" title="Alignement" style="width:100%;">
          <option value="justifyLeft" selected>Gauche</option>
          <option value="justifyCenter">Centré</option>
          <option value="justifyRight">Droite</option>
          <option value="justifyFull">Justifié</option>
        </select>
        <select class="doc-tb-select" data-action="linespacing" title="Interligne" style="width:100%;">
          <option value="1">1</option>
          <option value="1.15" selected>1.15</option>
          <option value="1.5">1.5</option>
          <option value="2">2</option>
        </select>
        <button type="button" class="doc-tb-btn" data-action="checklist" title="Liste de contrôle"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="6" height="6" rx="1"/><path d="M4.5 7l1 1 2-2"/><line x1="12" y1="7" x2="21" y2="7"/><rect x="3" y="14" width="6" height="6" rx="1"/><line x1="12" y1="17" x2="21" y2="17"/></svg></button>
        <button type="button" class="doc-tb-btn" data-cmd="insertUnorderedList" title="Liste à puces">•≡</button>
      </div>
      <div style="flex:1;overflow-y:auto;padding:0;">
        <div class="doc-a4-sheet" style="width:100%;max-width:100%;min-height:100%;margin:0;background:#000000;box-shadow:none;transform-origin:top center;">
          <div class="doc-body-editable" contenteditable="true" spellcheck="false" data-lpignore="true" data-1p-ignore data-bwignore style="padding:56px 5vw;min-height:100%;color:#ffffff;font-family:'Iowan Old Style', Georgia, serif;font-size:19px;line-height:1.6;word-break:break-word;outline:none;box-sizing:border-box;"></div>
        </div>
      </div>
    </div>
  `;
  const titleEl = page.querySelector('.doc-title-input');
  const bodyEl = page.querySelector('.doc-body-editable');
  const sheetEl = page.querySelector('.doc-a4-sheet');
  const closeBtn = page.querySelector('.doc-close-btn');
  let initialContent = doc.content || '';
  if (/^\s*&lt;/.test(initialContent)) {
    const decoder = document.createElement('textarea');
    decoder.innerHTML = initialContent;
    initialContent = decoder.value;
  }
  bodyEl.innerHTML = initialContent;

  const toolbar = page.querySelector('.doc-toolbar');
  function focusBody() { bodyEl.focus(); }
  bodyEl.addEventListener('click', e => {
    const box = e.target.closest('.chk-box');
    if (!box) return;
    e.preventDefault();
    box.closest('.checklist-item')?.classList.toggle('checked');
    scheduleSave();
  });
  toolbar.querySelectorAll('.doc-tb-btn[data-cmd]').forEach(btn => {
    btn.addEventListener('mousedown', e => e.preventDefault());
    btn.addEventListener('click', () => { focusBody(); document.execCommand(btn.dataset.cmd, false, null); scheduleSave(); });
  });
  toolbar.querySelectorAll('.doc-tb-btn[data-action]').forEach(btn => {
    btn.addEventListener('mousedown', e => e.preventDefault());
    btn.addEventListener('click', () => {
      const action = btn.dataset.action;
      if (action === 'print') { window.print(); }
      else if (action === 'spellcheck') { bodyEl.spellcheck = !bodyEl.spellcheck; btn.style.opacity = bodyEl.spellcheck ? '1' : '.5'; }
      else if (action === 'link') { const url = prompt('Adresse du lien :', 'https://'); if (url) { focusBody(); document.execCommand('createLink', false, url); scheduleSave(); } }
      else if (action === 'image') { docImageInput.click(); }
      else if (action === 'checklist') { focusBody(); document.execCommand('insertHTML', false, '<div class="checklist-item"><span class="chk-box" contenteditable="false"></span><span class="chk-text">&nbsp;</span></div>'); scheduleSave(); }
      else if (action === 'size-inc' || action === 'size-dec') {
        const sizeInput = toolbar.querySelector('.doc-tb-size');
        let v = parseInt(sizeInput.value, 10) || 15;
        v += action === 'size-inc' ? 1 : -1;
        sizeInput.value = v;
        bodyEl.style.fontSize = v + 'px';
      }
    });
  });
  toolbar.querySelector('[data-action="zoom"]').addEventListener('change', (e) => {
    sheetEl.style.transform = `scale(${parseInt(e.target.value, 10) / 100})`;
  });
  toolbar.querySelector('[data-cmd="formatBlock"]').addEventListener('mousedown', e => e.stopPropagation());
  toolbar.querySelector('[data-cmd="formatBlock"]').addEventListener('change', (e) => { focusBody(); document.execCommand('formatBlock', false, e.target.value); scheduleSave(); });
  toolbar.querySelector('[data-action="font"]').addEventListener('mousedown', e => e.stopPropagation());
  toolbar.querySelector('[data-action="font"]').addEventListener('change', (e) => { bodyEl.style.fontFamily = e.target.value; });
  toolbar.querySelector('.doc-tb-size').addEventListener('mousedown', e => e.stopPropagation());
  toolbar.querySelector('.doc-tb-size').addEventListener('change', (e) => { bodyEl.style.fontSize = e.target.value + 'px'; });
  const docColorBtn = toolbar.querySelector('[data-action="color"]');
  docColorBtn.addEventListener('mousedown', e => e.stopPropagation());
  docColorBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openSwatchColorPicker(docColorBtn, {
      allowNone: false,
      onPick: (c) => {
        focusBody();
        document.execCommand('foreColor', false, c);
        docColorBtn.dataset.color = c;
        docColorBtn.querySelector('.fs-textcolor-bar').style.background = c;
        scheduleSave();
      }
    });
  });
  const docHiliteBtn = toolbar.querySelector('[data-action="hilite"]');
  docHiliteBtn.addEventListener('mousedown', e => e.stopPropagation());
  docHiliteBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    openSwatchColorPicker(docHiliteBtn, {
      allowNone: true,
      onPick: (c) => {
        focusBody();
        document.execCommand('hiliteColor', false, c || 'transparent');
        docHiliteBtn.dataset.color = c || '';
        docHiliteBtn.querySelector('.fs-textcolor-bar').style.background = c || 'transparent';
        scheduleSave();
      }
    });
  });
  toolbar.querySelector('[data-action="align"]').addEventListener('mousedown', e => e.stopPropagation());
  toolbar.querySelector('[data-action="align"]').addEventListener('change', (e) => { focusBody(); document.execCommand(e.target.value, false, null); scheduleSave(); });
  toolbar.querySelector('[data-action="linespacing"]').addEventListener('mousedown', e => e.stopPropagation());
  toolbar.querySelector('[data-action="linespacing"]').addEventListener('change', (e) => { bodyEl.style.lineHeight = e.target.value; });

  const docImageInput = document.createElement('input');
  docImageInput.type = 'file';
  docImageInput.accept = 'image/*';
  docImageInput.style.display = 'none';
  document.body.appendChild(docImageInput);
  docImageInput.addEventListener('change', () => {
    const file = docImageInput.files && docImageInput.files[0];
    docImageInput.value = '';
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => { focusBody(); document.execCommand('insertImage', false, reader.result); scheduleSave(); };
    reader.readAsDataURL(file);
  });

  let saveTimer = null;
  function scheduleSave() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(async () => {
      await authFetch('index.php?action=text_documents_save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ id: doc.id, title: titleEl.value.trim(), content: bodyEl.innerHTML })
      });
      loadDocuments();
    }, 600);
  }
  titleEl.addEventListener('input', scheduleSave);
  bodyEl.addEventListener('input', scheduleSave);
  titleEl.addEventListener('keydown', e => { if(e.key === 'Enter'){ e.preventDefault(); bodyEl.focus(); } });

  function close() {
    clearTimeout(saveTimer);
    docImageInput.remove();
    authFetch('index.php?action=text_documents_save', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ id: doc.id, title: titleEl.value.trim(), content: bodyEl.innerHTML })
    }).then(loadDocuments);
    page.remove();
    unlockPageScroll();
    document.removeEventListener('keydown', escHandler);
  }
  function escHandler(e) { if(e.key === 'Escape') close(); }

  closeBtn.addEventListener('click', close);
  document.addEventListener('keydown', escHandler);
  document.body.appendChild(page);
  lockPageScroll();
  titleEl.focus();
}

// -----------------------------------------------------
// Onglets
// -----------------------------------------------------
function activateView(view){
  document.querySelectorAll('.side-item').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const btn = document.querySelector(`.side-item[data-view="${view}"]`);
  if(!btn) return;
  btn.classList.add('active');
  document.getElementById(view).classList.add('active');
  localStorage.setItem('memo-view', view);
  composer.style.display = view === 'notesView' ? '' : 'none';
  document.body.classList.toggle('doc-view-active', view === 'documentView');
  if(view === 'coursesView') loadLists();
  if(view === 'trashView') loadCourseTrash(); // notes trash only now
  if(view === 'documentView') loadDocuments();
}

document.querySelectorAll('.side-item[data-view]').forEach(btn => {
  btn.addEventListener('click', () => activateView(btn.dataset.view));
});

// -----------------------------------------------------
// --- Notifications ---
let notifDropdown = null;
let notifData = [];

function closeNotifDropdown() {
  if (notifDropdown) { notifDropdown.remove(); notifDropdown = null; }
}
document.addEventListener('click', (e) => {
  if (notifDropdown && !notifDropdown.contains(e.target) && !e.target.closest('#notifBtn')) {
    closeNotifDropdown();
  }
});

function updateNotifBadge() {
  const badge = document.getElementById('notifBadge');
  if (!badge) return;
  const unread = notifData.filter(n => !n.is_read).length;
  if (unread > 0) {
    badge.textContent = unread > 9 ? '9+' : unread;
    badge.style.display = 'flex';
  } else {
    badge.style.display = 'none';
  }
}

async function fetchNotifications() {
  try {
    const res = await apiFetch('index.php?action=notifications_list');
    if (!res.ok) return;
    notifData = await res.json();
    updateNotifBadge();
  } catch(e) { /* silencieux */ }
}

function timeAgo(dateStr) {
  const diff = Math.floor((Date.now() - new Date(dateStr)) / 1000);
  if (diff < 60) return 'À l\'instant';
  if (diff < 3600) return `Il y a ${Math.floor(diff/60)} min`;
  if (diff < 86400) return `Il y a ${Math.floor(diff/3600)} h`;
  return `Il y a ${Math.floor(diff/86400)} j`;
}

function notifLabel(n) {
  if (n.type === 'list_invite') {
    const actions = !n.is_read ? `
      <div style="display:flex;gap:6px;margin-top:8px;">
        <button data-notif-id="${n.id}" data-accept="1" style="flex:1;padding:5px 0;border:none;border-radius:5px;background:var(--accent);color:#fff;font-size:12px;cursor:pointer;font-family:inherit;">Accepter</button>
        <button data-notif-id="${n.id}" data-accept="0" style="flex:1;padding:5px 0;border:none;border-radius:5px;background:var(--line);color:var(--ink);font-size:12px;cursor:pointer;font-family:inherit;">Refuser</button>
      </div>` : '';
    return `<b>${escapeHtml(n.payload.invited_by)}</b> vous a ajouté à la liste <b>${escapeHtml(n.payload.list_name)}</b>${actions}`;
  }
  return 'Nouvelle notification';
}

function openNotifDropdown(anchorEl) {
  if (notifDropdown) { closeNotifDropdown(); return; }
  const rect = anchorEl.getBoundingClientRect();
  const menu = document.createElement('div');
  const margin = 10;
  const menuWidth = Math.min(280, window.innerWidth - margin * 2);
  let left = rect.left;
  if (left + menuWidth + margin > window.innerWidth) {
    left = window.innerWidth - menuWidth - margin;
  }
  if (left < margin) left = margin;
  menu.style.cssText = `position:fixed;bottom:${window.innerHeight - rect.top + 6}px;left:${left}px;background:var(--card);border:1px solid var(--line);border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,0.15);z-index:1000;overflow:hidden;width:${menuWidth}px;max-width:calc(100vw - ${margin * 2}px);max-height:70vh;overflow-y:auto;`;

  if (notifData.length === 0) {
    menu.innerHTML = `<div style="padding:16px;font-size:13px;color:var(--ink);opacity:0.6;text-align:center;">Aucune notification</div>`;
  } else {
    const unreadIds = notifData.filter(n => !n.is_read).map(n => n.id);
    let html = '';
    notifData.forEach(n => {
      const bg = n.is_read ? '' : 'background:var(--bg);';
      html += `<div data-notif-row="${n.id}" style="padding:10px 14px;border-bottom:1px solid var(--line);${bg}position:relative;">
        <button data-notif-delete="${n.id}" title="Supprimer" aria-label="Supprimer la notification" style="position:absolute;top:8px;right:8px;border:none;background:none;color:var(--ink);opacity:0.45;font-size:14px;line-height:1;cursor:pointer;padding:2px 4px;">✕</button>
        <div style="font-size:13px;color:var(--ink);line-height:1.4;padding-right:18px;">${notifLabel(n)}</div>
        <div style="font-size:11px;color:var(--ink);opacity:0.5;margin-top:3px;">${timeAgo(n.created_at)}</div>
      </div>`;
    });
    html += `<div style="display:flex;">`;
    if (unreadIds.length > 0) {
      html += `<button id="notifMarkRead" style="flex:1;display:block;padding:9px 14px;border:none;background:none;color:var(--accent);font-size:12px;cursor:pointer;font-family:inherit;">Tout marquer comme lu</button>`;
    }
    html += `<button id="notifDeleteAll" style="flex:1;display:block;padding:9px 14px;border:none;background:none;color:var(--ink);opacity:0.6;font-size:12px;cursor:pointer;font-family:inherit;">Tout effacer</button>`;
    html += `</div>`;
    menu.innerHTML = html;
    if (unreadIds.length > 0) {
      menu.querySelector('#notifMarkRead').onclick = async () => {
        await authFetch('index.php?action=notifications_read', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ids: unreadIds})
        });
        notifData.forEach(n => n.is_read = true);
        updateNotifBadge();
        closeNotifDropdown();
      };
    }
    menu.querySelector('#notifDeleteAll').onclick = async (e) => {
      e.stopPropagation();
      await authFetch('index.php?action=notifications_delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ids: []})
      });
      notifData = [];
      updateNotifBadge();
      closeNotifDropdown();
    };
  }

  document.body.appendChild(menu);
  notifDropdown = menu;

  // Bouton supprimer (par notification)
  menu.querySelectorAll('[data-notif-delete]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const notifId = parseInt(btn.dataset.notifDelete);
      btn.disabled = true;
      const res = await authFetch('index.php?action=notifications_delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ids: [notifId]})
      });
      if (res.ok) {
        notifData = notifData.filter(n => n.id !== notifId);
        updateNotifBadge();
        openNotifDropdownRefresh(anchorEl);
      }
    });
  });

  // Boutons accepter / refuser
  menu.querySelectorAll('[data-notif-id]').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      const notifId = parseInt(btn.dataset.notifId);
      const accept  = btn.dataset.accept === '1';
      btn.closest('div[style]').querySelectorAll('button[data-notif-id]').forEach(b => b.disabled = true);
      const res = await authFetch('index.php?action=notifications_respond', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({notif_id: notifId, accept})
      });
      if (res.ok) {
        const notif = notifData.find(n => n.id === notifId);
        if (notif) notif.is_read = true;
        updateNotifBadge();
        closeNotifDropdown();
        if (accept && notif) {
          // Invalide le cache pour forcer un rechargement propre avec la vraie clé
          const listId = notif.payload?.list_id;
          if (listId) {
            localStorage.removeItem(`courses-cache-${listId}`);
            listKeyCache.delete(listId);
          }
          if (typeof loadLists === 'function') loadLists();
        }
      }
    });
  });
}

// Ferme puis rouvre le dropdown pour rafraîchir son contenu après une suppression
function openNotifDropdownRefresh(anchorEl) {
  closeNotifDropdown();
  openNotifDropdown(anchorEl);
}

document.getElementById('notifBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  openNotifDropdown(e.currentTarget);
});

// Polling toutes les 30 secondes
fetchNotifications();
setInterval(fetchNotifications, 30000);

// Menu paramètres (thème / changer de compte / déconnexion)
// -----------------------------------------------------
let settingsMenu = null;
function closeSettingsMenu(){
  if(settingsMenu){ settingsMenu.remove(); settingsMenu = null; }
}
document.addEventListener('click', (e) => {
  if(settingsMenu && !settingsMenu.contains(e.target) && !e.target.closest('#settingsBtn') && !e.target.closest('#settingsBtnMobile')){
    closeSettingsMenu();
  }
});

function openSettingsMenu(anchorEl, placement){
  if(settingsMenu){ closeSettingsMenu(); return; }
  const rect = anchorEl.getBoundingClientRect();
  const menu = document.createElement('div');
  const posStyle = placement === 'below-left'
    ? `top:${rect.bottom + 6}px;right:${window.innerWidth - rect.right}px;`
    : `bottom:${window.innerHeight - rect.top + 6}px;left:${rect.left}px;`;
  menu.style.cssText = `position:fixed;${posStyle}background:var(--card);border:1px solid var(--line);border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,0.15);z-index:1000;overflow:hidden;min-width:${rect.width < 160 ? 160 : rect.width}px;`;
  menu.innerHTML = `
    <div class="ctx-item" data-action="theme" style="display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;padding:8px 14px;color:var(--ink);font-family:inherit;font-size:13px;cursor:pointer;">
      <span class="theme-label">${isDarkTheme() ? 'Thème sombre' : 'Thème clair'}</span>
      <span class="theme-switch" style="position:relative;width:34px;height:18px;border-radius:999px;background:${isDarkTheme() ? 'var(--accent)' : 'var(--line)'};flex-shrink:0;">
        <span style="position:absolute;top:2px;left:${isDarkTheme() ? '18px' : '2px'};width:14px;height:14px;border-radius:50%;background:#fff;transition:left 0.15s ease;"></span>
      </span>
    </div>
    <button class="ctx-item" data-action="password-note" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:var(--ink);font-family:inherit;font-size:13px;">Mot de passe</button>
    <button class="ctx-item" data-action="logout" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:#c0392b;font-family:inherit;font-size:13px;">Déconnexion</button>
  `;
  menu.querySelectorAll('.ctx-item').forEach(btn => {
    btn.addEventListener('mouseenter', () => btn.style.background = 'var(--bg)');
    btn.addEventListener('mouseleave', () => btn.style.background = 'none');
    btn.addEventListener('click', async (ev) => {
      ev.stopPropagation();
      const action = btn.dataset.action;
      if(action === 'theme'){
        toggleTheme();
        const sw = btn.querySelector('.theme-switch');
        const dot = sw.querySelector('span');
        const label = btn.querySelector('.theme-label');
        sw.style.background = isDarkTheme() ? 'var(--accent)' : 'var(--line)';
        dot.style.left = isDarkTheme() ? '18px' : '2px';
        if (label) label.textContent = isDarkTheme() ? 'Thème sombre' : 'Thème clair';
        return;
      }
      closeSettingsMenu();
      if(action === 'password-note'){
        openPasswordNote();
        return;
      }
      if(action === 'logout'){
        await authFetch('user/auth.php?action=logout', {method: 'POST'});
        localStorage.removeItem('e2ee_priv');
        window.location.href = '/login';
      }
    });
  });
  document.body.appendChild(menu);
  settingsMenu = menu;
}

document.getElementById('settingsBtn').addEventListener('click', (e) => {
  e.stopPropagation();
  openSettingsMenu(e.currentTarget);
});
document.getElementById('settingsBtnMobile').addEventListener('click', (e) => {
  e.stopPropagation();
  openSettingsMenu(e.currentTarget, 'below-left');
});

const savedView = localStorage.getItem('memo-view');
if(savedView){
  activateView(savedView);
}

// -----------------------------------------------------
// Liste de courses (persistée en base SQLite via index.php)
// -----------------------------------------------------
const courseInput = document.getElementById('courseInput');
const coursesList = document.getElementById('coursesList');
const checkedSection = document.getElementById('checkedSection');
const checkedList = document.getElementById('checkedList');
const coursesEmpty = document.getElementById('coursesEmpty');
const clearCheckedBtn = document.getElementById('clearCheckedBtn');
const listTabs = document.getElementById('listTabs');
const newListBtn = document.getElementById('newListBtn');
const shareListBtn = document.getElementById('shareListBtn');
const sharePanel = document.getElementById('sharePanel');
const shareListName = document.getElementById('shareListName');
const membersList = document.getElementById('membersList');
const memberInput = document.getElementById('memberInput');
const addMemberBtn = document.getElementById('addMemberBtn');
const shareError = document.getElementById('shareError');

let lists = [];
let currentListId = null;
const listKeyCache = new Map(); // list_id -> CryptoKey (clé AES-GCM de la liste)

function currentList(){
  return lists.find(l => l.id === currentListId);
}

// Récupère (et met en cache) la clé de liste déchiffrée pour l'utilisateur
// courant. La clé est stockée wrappée côté serveur (ECDH), illisible sans
// la clé privée de l'utilisateur (voir crypto.js: unwrapListKey).
async function getListKey(listId){
  if (listKeyCache.has(listId)) return listKeyCache.get(listId);
  await window.e2eeReadyPromise;
  const { unwrapListKey, importPublicKey, createListKey } = await import('/crypto.js');
  const res = await apiFetch(`index.php?action=lists_get_key&list_id=${listId}`);
  if (res.status === 404) {
    // Clé absente : soit liste pré-E2EE (migration à la volée si owner),
    // soit invitation en attente (clé pas encore wrappée pour cet utilisateur).
    // On vérifie si on est owner avant de générer une nouvelle clé,
    // pour ne pas écraser la clé partagée avec une clé incompatible.
    const listsRes = await apiFetch(`index.php?action=lists_list`);
    const lists = listsRes.ok ? await listsRes.json() : [];
    const myList = lists.find(l => l.id === listId);
    if (!myList || !myList.is_owner) {
      // Membre invité : la clé n'est pas encore disponible (owner doit la wrapper).
      throw new Error('Clé de liste non disponible, réessayez dans un instant.');
    }
    // Owner : migration à la volée (liste créée avant le E2EE).
    const myPublicKey = await importPublicKey(window.E2EE_PUBLIC_KEY_B64);
    const { listKey, wrappedForOwner } = await createListKey(window.E2EE_PRIVATE_KEY, myPublicKey);
    const storeRes = await authFetch('index.php?action=lists_store_key', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({list_id: listId, user_id: window.MY_USER_ID, wrapped_key: wrappedForOwner})
    });
    if (!storeRes.ok) throw new Error('Impossible de créer la clé de liste');
    listKeyCache.set(listId, listKey);
    return listKey;
  }
  if (!res.ok) throw new Error('Clé de liste introuvable');
  const data = await res.json();
  console.debug('[getListKey] data reçu:', JSON.stringify({ciphertext_len: data.ciphertext?.length, iv: data.iv, sender_pub_len: data.sender_public_key?.length}));
  let senderPublicKey;
  try {
    senderPublicKey = await importPublicKey(data.sender_public_key);
    console.debug('[getListKey] importPublicKey OK');
  } catch(e) {
    console.error('[getListKey] importPublicKey FAILED:', e);
    throw e;
  }
  let key;
  try {
    key = await unwrapListKey(
      { ciphertext: data.ciphertext, iv: data.iv },
      window.E2EE_PRIVATE_KEY,
      senderPublicKey
    );
    console.debug('[getListKey] unwrapListKey OK');
  } catch(e) {
    console.error('[getListKey] unwrapListKey FAILED:', e);
    throw e;
  }
  listKeyCache.set(listId, key);
  return key;
}

const MY_USERNAME = document.querySelector('meta[name="my-username"]').content;

// Enregistre une notification chiffrée pour une liste (ex: "X a ajouté Y").
// Chiffrée avec la même clé de liste que les articles : le serveur ne voit
// jamais le texte en clair. Best-effort : une erreur ici ne doit jamais
// bloquer l'action principale (ajout d'article, invitation, etc.).
async function logActivity(listId, text){
  try {
    const { encryptItemLabel } = await import('/crypto.js');
    const listKey = await getListKey(listId);
    const enc = await encryptItemLabel(listKey, text);
    await authFetch('index.php?action=activity_add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({list_id: listId, enc_ciphertext: enc.ciphertext, enc_iv: enc.iv})
    });
  } catch(e) {
    console.error('Erreur notification liste:', e);
  }
}

async function loadActivity(listId){
  const feed = document.getElementById('activityFeed');
  if(!feed) return;
  feed.innerHTML = '<div style="font-size:12px;opacity:0.6;">Chargement…</div>';
  try {
    const { decryptItemLabel } = await import('/crypto.js');
    const listKey = await getListKey(listId);
    const res = await apiFetch(`index.php?action=activity_list&list_id=${listId}`);
    if(!res.ok){ feed.innerHTML = ''; return; }
    const rows = await res.json();
    if(!rows.length){ feed.innerHTML = '<div style="font-size:12px;opacity:0.6;">Aucune activité récente.</div>'; return; }
    feed.innerHTML = '';
    for(const row of rows){
      let text;
      try {
        text = await decryptItemLabel(listKey, row.enc_ciphertext, row.enc_iv);
      } catch(e) { text = '(notification illisible)'; }
      const item = document.createElement('div');
      item.style.cssText = 'font-size:12px;padding:4px 0;border-bottom:1px solid var(--line);';
      const time = new Date(row.created_at.replace(' ', 'T')).toLocaleString('fr-FR', {day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit'});
      item.innerHTML = `<span>${escapeHtml(text)}</span><span style="opacity:0.5;margin-left:6px;">${time}</span>`;
      feed.appendChild(item);
    }
  } catch(e) {
    console.error('Erreur chargement activité:', e);
    feed.innerHTML = '<div style="font-size:12px;opacity:0.6;">Erreur de chargement.</div>';
  }
}

async function loadLists(){
  const res = await apiFetch('index.php?action=lists_list');
  lists = await res.json();
  if(!lists.length){
    listTabs.innerHTML = '';
    currentListId = null;
    renderCourses([]);
    return;
  }
  const saved = parseInt(localStorage.getItem('memo-list-id'), 10);
  currentListId = lists.some(l => l.id === saved) ? saved : lists[0].id;
  renderListTabs();
  loadCourses();
}

function renderListTabs(){
  listTabs.innerHTML = '';
  lists.forEach(l => {
    const btn = document.createElement('button');
    btn.className = 'btn' + (l.id === currentListId ? ' primary' : '');
    btn.textContent = l.name;
    const icon = document.createElement('span');
    icon.style.cssText = 'display:inline-flex;align-items:center;margin-left:5px;vertical-align:middle;opacity:0.85;';
    icon.innerHTML = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`;
    btn.appendChild(icon);
    btn.onclick = () => selectList(l.id);
    btn.oncontextmenu = (e) => {
      e.preventDefault();
      if(!l.is_owner) return;
      showListContextMenu(e.pageX, e.pageY, l);
    };
    btn.ondblclick = async (e) => {
      e.preventDefault();
      if(!l.is_owner) return;
      const name = await textPrompt('Renommer le magasin :', l.name);
      if(name && name.trim()) renameList(l.id, name.trim());
    };
    listTabs.appendChild(btn);
  });
}

function selectList(id){
  currentListId = id;
  localStorage.setItem('memo-list-id', id);
  sharePanel.style.display = 'none';
  renderListTabs();
  loadCourses();
}

newListBtn.addEventListener('click', async () => {
  const name = await textPrompt('Nom du magasin :');
  if(!name || !name.trim()) return;
  await window.e2eeReadyPromise;
  const { createListKey, importPublicKey } = await import('/crypto.js');
  const myPublicKey = await importPublicKey(window.E2EE_PUBLIC_KEY_B64);
  const { listKey, wrappedForOwner } = await createListKey(window.E2EE_PRIVATE_KEY, myPublicKey);
  const res = await authFetch('index.php?action=lists_add', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: name.trim(), wrapped_key: wrappedForOwner})
  });
  const data = await res.json();
  if(!res.ok){ alert(data.error || 'Erreur'); return; }
  listKeyCache.set(data.id, listKey);
  lists.push(data);
  selectList(data.id);
});

async function deleteList(id){
  await authFetch('index.php?action=lists_delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
  lists = lists.filter(l => l.id !== id);
  if(!lists.length){
    currentListId = null;
    listTabs.innerHTML = '';
    renderCourses([]);
    return;
  }
  selectList(lists[0].id);
}

let listCtxMenu = null;
function closeListContextMenu(){
  if(listCtxMenu){ listCtxMenu.remove(); listCtxMenu = null; }
}
document.addEventListener('click', closeListContextMenu);

function showListContextMenu(x, y, l){
  closeListContextMenu();
  const menu = document.createElement('div');
  menu.style.cssText = `position:absolute;top:${y}px;left:${x}px;background:var(--card);border:1px solid var(--line);border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,0.15);z-index:1000;overflow:hidden;min-width:140px;`;
  menu.innerHTML = `
    <button class="ctx-item" data-action="rename" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:var(--ink);font-family:inherit;font-size:13px;">Renommer</button>
    <button class="ctx-item" data-action="delete" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:#c0392b;font-family:inherit;font-size:13px;">Supprimer</button>
  `;
  menu.querySelectorAll('.ctx-item').forEach(btn => {
    btn.addEventListener('mouseenter', () => btn.style.background = 'var(--bg)');
    btn.addEventListener('mouseleave', () => btn.style.background = 'none');
    btn.addEventListener('click', async (e) => {
      e.stopPropagation();
      closeListContextMenu();
      if(btn.dataset.action === 'rename'){
        const name = await textPrompt('Renommer le magasin :', l.name);
        if(name && name.trim()) renameList(l.id, name.trim());
      } else if(btn.dataset.action === 'delete'){
        deleteList(l.id);
      }
    });
  });
  document.body.appendChild(menu);
  listCtxMenu = menu;
}

async function renameList(id, name){
  await authFetch('index.php?action=lists_rename', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id, name})
  });
  const l = lists.find(x => x.id === id);
  if(l) l.name = name;
  renderListTabs();
}

shareListBtn.addEventListener('click', () => {
  if(!currentListId) return;
  sharePanel.style.display = sharePanel.style.display === 'none' ? 'block' : 'none';
  if(sharePanel.style.display === 'block'){ loadMembers(); loadActivity(currentListId); }
});

async function loadMembers(){
  shareError.textContent = '';
  const l = currentList();
  shareListName.textContent = l ? l.name : '';
  const res = await apiFetch(`index.php?action=lists_members&list_id=${currentListId}`);
  const data = await res.json();
  if(!res.ok){ shareError.textContent = data.error || 'Erreur'; return; }
  membersList.innerHTML = '';
  const ownerRow = document.createElement('div');
  ownerRow.style.fontSize = '13px';
  ownerRow.textContent = `${data.owner.username} (vous)`;
  membersList.appendChild(ownerRow);
  data.members.forEach(m => {
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;justify-content:space-between;align-items:center;font-size:13px;';
    const canRemove = l.is_owner;
    row.innerHTML = `<span>${escapeHtml(m.username)}</span>`;
    if(canRemove){
      const rm = document.createElement('button');
      rm.className = 'btn';
      rm.style.fontSize = '11px';
      rm.style.padding = '3px 8px';
      rm.textContent = 'Retirer';
      rm.onclick = () => removeMember(m.id);
      row.appendChild(rm);
    }
    membersList.appendChild(row);
  });
  const addMemberRow = document.getElementById('addMemberRow');
  addMemberRow.style.display = 'flex';
}

addMemberBtn.addEventListener('click', async () => {
  const identifier = memberInput.value.trim();
  if(!identifier) return;
  shareError.textContent = '';
  const res = await authFetch('index.php?action=lists_add_member', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({list_id: currentListId, identifier})
  });
  const data = await res.json();
  if(!res.ok){ shareError.textContent = data.error || 'Erreur'; return; }
  try {
    await window.e2eeReadyPromise;
    const { wrapListKeyForMember, importPublicKey } = await import('/crypto.js');
    const listKey = await getListKey(currentListId);
    const listKeyRaw = await crypto.subtle.exportKey('raw', listKey);
    console.debug('[addMember] listKeyRaw byteLength:', listKeyRaw.byteLength);
    const memberPublicKey = await importPublicKey(data.public_key);
    const wrapped = await wrapListKeyForMember(listKeyRaw, window.E2EE_PRIVATE_KEY, memberPublicKey);
    await authFetch('index.php?action=lists_store_key', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({list_id: currentListId, user_id: data.id, wrapped_key: wrapped})
    });
  } catch(e) {
    console.error('Erreur partage de la clé de liste:', e);
    shareError.textContent = 'Membre ajouté mais impossible de partager la clé de chiffrement.';
  }
  memberInput.value = '';
  loadMembers();
  logActivity(currentListId, `${MY_USERNAME} a ajouté ${identifier} à la liste`);
});
memberInput.addEventListener('keydown', e => { if(e.key === 'Enter') addMemberBtn.click(); });

async function removeMember(userId){
  await authFetch('index.php?action=lists_remove_member', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({list_id: currentListId, user_id: userId})
  });
  loadMembers();
}

async function decryptCourseItems(listId, items){
  const { decryptItemLabel } = await import('/crypto.js');
  let listKey;
  try {
    listKey = await getListKey(listId);
  } catch(e) {
    // Clé pas encore disponible (invitation en attente de wrap par l'owner).
    console.warn('Clé de liste indisponible:', e.message);
    return items.map(it => ({ id: it.id, checked: it.checked, label: 'ߔࠅn attente de synchronisation…', enc_label_ciphertext: it.enc_label_ciphertext, enc_label_iv: it.enc_label_iv }));
  }
  const out = [];
  for (const it of items) {
    let label = '(indéchiffrable)';
    try {
      if (it.enc_label_ciphertext && it.enc_label_iv) {
        label = await decryptItemLabel(listKey, it.enc_label_ciphertext, it.enc_label_iv);
      }
    } catch(e) { console.error('Erreur déchiffrement article:', e); }
    out.push({ id: it.id, checked: it.checked, label, enc_label_ciphertext: it.enc_label_ciphertext, enc_label_iv: it.enc_label_iv });
  }
  return out;
}

async function loadCourses(){
  if(!currentListId) return;
  const listId = currentListId;
  // Affiche immédiatement la dernière version connue (perçu instantané),
  // pendant que la version à jour est récupérée en arrière-plan.
  const cacheKey = `courses-cache-${listId}`;
  const cached = localStorage.getItem(cacheKey);
  if(cached){
    try { renderCourses(JSON.parse(cached)); } catch(e) {}
  }
  const res = await apiFetch(`index.php?action=list&list_id=${listId}`);
  const rawItems = await res.json();
  if (listId !== currentListId) return; // l'utilisateur a changé de liste entre-temps
  let items;
  try {
    items = await decryptCourseItems(listId, rawItems);
  } catch(e) {
    console.error('Erreur déchiffrement liste:', e);
    return;
  }
  if (listId !== currentListId) return;
  renderCourses(items);
  localStorage.setItem(cacheKey, JSON.stringify(items));
}

// Rafraîchissement automatique de la liste de courses (polling)
// pour voir les ajouts/modifs des autres membres sans recharger la page.
setInterval(() => {
  if (!currentListId) return;
  // On évite de rafraîchir pendant que l'utilisateur tape dans un champ
  // (édition d'un article, ajout d'un nouvel article, etc.)
  const active = document.activeElement;
  const isEditingCourse = active && (active === courseInput || active.classList?.contains('course-label'));
  if (isEditingCourse) return;
  loadCourses();
}, 3000);


function renderCourses(items){
  const unchecked = items.filter(i => !i.checked);
  const checked = items.filter(i => i.checked);

  coursesList.innerHTML = '';
  checkedList.innerHTML = '';
  coursesEmpty.style.display = items.length ? 'none' : 'block';

  unchecked.forEach(item => coursesList.appendChild(courseItem(item)));

  if(checked.length){
    checkedSection.style.display = 'block';
    checked.forEach(item => checkedList.appendChild(courseItem(item)));
  } else {
    checkedSection.style.display = 'none';
  }
  clearCheckedBtn.style.display = checked.length ? '' : 'none';
}

function courseItem(item){
  const li = document.createElement('li');
  li.className = 'course-item' + (item.checked ? ' checked' : '');
  li.innerHTML = `
    <button class="course-check" aria-label="Marquer comme acheté"></button>
    <span class="course-label" contenteditable="true" spellcheck="false">${escapeHtml(item.label)}</span>
    <button class="course-del">Supprimer</button>
  `;
  li.querySelector('.course-check').onclick = () => toggleCourse(item.id);
  li.querySelector('.course-del').onclick = () => deleteCourse(item.id);
  const label = li.querySelector('.course-label');

  async function saveEditSilent(newLabel){
    item.label = newLabel;
    try {
      const { encryptItemLabel } = await import('/crypto.js');
      const listKey = await getListKey(currentListId);
      const enc = await encryptItemLabel(listKey, newLabel);
      await authFetch('index.php?action=edit', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: item.id, enc_label_ciphertext: enc.ciphertext, enc_label_iv: enc.iv})
      });
    } catch(err) {
      console.error('Erreur édition article:', err);
    }
  }

  label.addEventListener('keydown', e => {
    if(e.key === 'Enter'){
      e.preventDefault();
      e.stopPropagation();
      const newLabel = label.textContent.trim();
      label.textContent = newLabel || item.label;
      if(newLabel && newLabel !== item.label){
        saveEditSilent(newLabel);
      }
      insertDraftAfter(li);
    }
  });
  label.addEventListener('blur', () => {
    // Nettoie les <br>/<div> résiduels que certains navigateurs insèrent
    // dans le contenteditable avant que preventDefault ne s'applique.
    const newLabel = label.textContent.trim();
    label.textContent = newLabel || item.label;
    if(!newLabel){
      return;
    }
    if(newLabel !== item.label){
      saveEditSilent(newLabel);
    }
  });
  return li;
}

function draftCourseItem(){
  const li = document.createElement('li');
  li.className = 'course-item';
  li.innerHTML = `
    <button class="course-check" disabled aria-label="Article acheté"></button>
    <span class="course-label" contenteditable="true" spellcheck="false"></span>
    <button class="course-del">Supprimer</button>
  `;
  const label = li.querySelector('.course-label');
  li.querySelector('.course-del').onclick = () => li.remove();
  let committed = false;

  async function commit(){
    if(committed) return;
    const value = label.textContent.trim();
    if(!value){
      li.remove();
      return;
    }
    committed = true;
    try {
      const { encryptItemLabel } = await import('/crypto.js');
      const listKey = await getListKey(currentListId);
      const enc = await encryptItemLabel(listKey, value);
      const res = await authFetch('index.php?action=add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({enc_label_ciphertext: enc.ciphertext, enc_label_iv: enc.iv, list_id: currentListId})
      });
      if(!res.ok){
        const err = await res.json().catch(()=>({}));
        console.error('Erreur ajout article:', res.status, err);
        committed = false;
        return;
      }
      const data = await res.json();
      const newLi = courseItem({id: data.id, label: value, checked: 0});
      li.replaceWith(newLi);
      coursesEmpty.style.display = 'none';
    } catch(e) {
      console.error('Erreur chiffrement/ajout article:', e);
      committed = false;
    }
  }

  label.addEventListener('keydown', e => {
    if(e.key === 'Enter'){
      e.preventDefault();
      e.stopPropagation();
      const value = label.textContent.trim();
      if(!value){ return; }
      label.blur();
      insertDraftAfter(li);
    }
  });
  label.addEventListener('blur', () => { commit(); });
  return { li, label };
}

function insertDraftAfter(li){
  const { li: draftLi, label } = draftCourseItem();
  li.after(draftLi);
  label.focus();
}

async function addCourse(){
  const label = courseInput.value.trim();
  if(!label) return;
  try {
    const { encryptItemLabel } = await import('/crypto.js');
    const listKey = await getListKey(currentListId);
    const enc = await encryptItemLabel(listKey, label);
    const res = await authFetch('index.php?action=add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({enc_label_ciphertext: enc.ciphertext, enc_label_iv: enc.iv, list_id: currentListId})
    });
    if(!res.ok){
      const err = await res.json().catch(()=>({}));
      console.error('Erreur ajout article:', res.status, err);
      alert(err.error || 'Erreur lors de l\'ajout');
      return;
    }
    courseInput.value = '';
    loadCourses();
    logActivity(currentListId, `${MY_USERNAME} a ajouté « ${label} »`);
  } catch(e) {
    console.error('Erreur chiffrement/ajout article:', e);
    alert('Impossible d\'ajouter l\'article (erreur de chiffrement).');
  }
}

async function toggleCourse(id){
  await authFetch('index.php?action=toggle', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
  loadCourses();
}

async function editCourse(id, label){
  const { encryptItemLabel } = await import('/crypto.js');
  const listKey = await getListKey(currentListId);
  const enc = await encryptItemLabel(listKey, label);
  await authFetch('index.php?action=edit', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id, enc_label_ciphertext: enc.ciphertext, enc_label_iv: enc.iv})
  });
  loadCourses();
}

async function deleteCourse(id){
  await authFetch('index.php?action=permanent_delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
  loadCourses();
}

async function loadCourseTrash(){
  if(!currentListId) return;
  const listId = currentListId;
  const res = await apiFetch(`index.php?action=trash_list&list_id=${listId}`);
  const rawItems = await res.json();
  if (listId !== currentListId) return;
  let items;
  try {
    items = await decryptCourseItems(listId, rawItems);
  } catch(e) {
    console.error('Erreur déchiffrement corbeille courses:', e);
    return;
  }
  if (listId !== currentListId) return;
  renderCourseTrash(items);
}

function renderCourseTrash(items){
  const courseTrashList = document.getElementById('courseTrashList');
  const courseTrashSection = document.getElementById('courseTrashSection');
  courseTrashList.innerHTML = '';
  if (courseTrashSection) courseTrashSection.style.display = items.length ? 'block' : 'none';
  items.forEach(item => {
    const li = document.createElement('li');
    li.className = 'course-item';
    li.innerHTML = `
      <span class="course-label">${escapeHtml(item.label)}</span>
      <button class="btn restore">Restaurer</button>
      <button class="course-del">Supprimer définitivement</button>
    `;
    li.querySelector('.restore').onclick = () => restoreCourse(item.id);
    li.querySelector('.course-del').onclick = () => permanentDeleteCourse(item.id);
    courseTrashList.appendChild(li);
  });
}

async function restoreCourse(id){
  await authFetch('index.php?action=restore', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
  loadCourseTrash();
  loadCourses();
}

async function permanentDeleteCourse(id){
  await authFetch('index.php?action=permanent_delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
  loadCourseTrash();
}

courseInput.addEventListener('keydown', e => {
  if(e.key === 'Enter') addCourse();
});
clearCheckedBtn.addEventListener('click', async () => {
  await authFetch('index.php?action=clear_checked', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({list_id: currentListId})
  });
  loadCourses();
});
</script>
<script nonce="<?= $cspNonce ?>">
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js');
}
</script>
<script nonce="<?= $cspNonce ?>">
// Supprime le "watermark" du navigateur à l'impression (titre de la page
// dans l'en-tête, affiché par Chrome/Firefox en plus de la date/heure).
// La date/heure elle-même ne peut être retirée que via les réglages
// d'impression du navigateur (case "En-têtes et pieds de page").
(function(){
  let savedTitle = '';
  window.addEventListener('beforeprint', () => {
    savedTitle = document.title;
    document.title = '';
  });
  window.addEventListener('afterprint', () => {
    document.title = savedTitle;
  });
})();
</script>
</body>
</html>
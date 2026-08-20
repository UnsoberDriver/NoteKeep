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
if (!isset($_SESSION['user_id'])) {
    header('Location: login.html');
    exit;
}
require __DIR__ . '/config.php';

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

$userId = $_SESSION['user_id'];

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
            $stmt = $pdo->prepare("INSERT INTO shopping_lists (owner_id, name) VALUES (:uid, :name)");
            $stmt->execute([':uid' => $userId, ':name' => $name]);
            echo json_encode(['id' => $pdo->lastInsertId(), 'name' => $name, 'owner_id' => $userId, 'is_owner' => true, 'owner_name' => $_SESSION['username']]);
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
            $u = $pdo->prepare("SELECT id, username FROM users WHERE username = :i OR email = :i");
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
            echo json_encode(['id' => $target['id'], 'username' => $target['username']]);
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

        // --- Articles ---
        if ($action === 'list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $listId = (int)($_GET['list_id'] ?? 0);
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT id, label, checked FROM courses WHERE list_id = :lid ORDER BY checked ASC, id ASC");
            $stmt->execute([':lid' => $listId]);
            echo json_encode($stmt->fetchAll(PDO::FETCH_ASSOC));
            exit;
        }

        if ($action === 'add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $listId = (int)($data['list_id'] ?? 0);
            $label = trim($data['label'] ?? '');
            if ($label === '') {
                http_response_code(400);
                echo json_encode(['error' => 'label requis']);
                exit;
            }
            if (!hasListAccess($pdo, $listId, $userId)) {
                http_response_code(403);
                echo json_encode(['error' => 'Accès refusé']);
                exit;
            }
            $stmt = $pdo->prepare("INSERT INTO courses (list_id, user_id, label) VALUES (:lid, :uid, :label)");
            $stmt->execute([':lid' => $listId, ':uid' => $userId, ':label' => $label]);
            echo json_encode(['id' => $pdo->lastInsertId(), 'label' => $label, 'checked' => 0]);
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
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'delete' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $stmt = $pdo->prepare("DELETE c FROM courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'edit' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $label = trim($data['label'] ?? '');
            if ($label === '') {
                http_response_code(400);
                echo json_encode(['error' => 'label requis']);
                exit;
            }
            $stmt = $pdo->prepare("UPDATE courses c JOIN shopping_lists l ON l.id = c.list_id
                LEFT JOIN shopping_list_members m ON m.list_id = l.id AND m.user_id = :uid
                SET c.label = :label
                WHERE c.id = :id AND (l.owner_id = :uid OR m.user_id = :uid)");
            $stmt->execute([':label' => $label, ':id' => $id, ':uid' => $userId]);
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
            $stmt = $pdo->prepare("DELETE FROM courses WHERE checked = 1 AND list_id = :lid");
            $stmt->execute([':lid' => $listId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        // --- Notes ---
        if ($action === 'notes_list' && $_SERVER['REQUEST_METHOD'] === 'GET') {
            $stmt = $pdo->prepare("SELECT id, title, body, pinned, deleted, color, images FROM notes WHERE user_id = :uid ORDER BY id DESC");
            $stmt->execute([':uid' => $userId]);
            $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($rows as &$r) {
                $r['pinned'] = (bool)$r['pinned'];
                $r['deleted'] = (bool)$r['deleted'];
                $r['id'] = (int)$r['id'];
                $decoded = json_decode($r['images'] ?: '[]', true);
                $r['images'] = is_array($decoded) ? $decoded : [];
            }
            echo json_encode($rows);
            exit;
        }

        if ($action === 'notes_save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $title = trim($data['title'] ?? '');
            $body = trim($data['body'] ?? '');
            $color = trim($data['color'] ?? '');
            if (!preg_match('/^[a-zA-Z0-9#]{0,20}$/', $color)) {
                $color = '';
            }
            if ($id <= 0) {
                http_response_code(400);
                echo json_encode(['error' => 'id requis']);
                exit;
            }
            $stmt = $pdo->prepare("SELECT id FROM notes WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            if ($stmt->fetch()) {
                $stmt = $pdo->prepare("UPDATE notes SET title = :title, body = :body, color = :color WHERE id = :id AND user_id = :uid");
                $stmt->execute([':title' => $title, ':body' => $body, ':color' => $color, ':id' => $id, ':uid' => $userId]);
            } else {
                $stmt = $pdo->prepare("INSERT INTO notes (id, user_id, title, body, color) VALUES (:id, :uid, :title, :body, :color)");
                $stmt->execute([':id' => $id, ':uid' => $userId, ':title' => $title, ':body' => $body, ':color' => $color]);
            }
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_image_add' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $imgData = $data['data'] ?? '';
            if ($id <= 0 || $imgData === '') {
                http_response_code(400);
                echo json_encode(['error' => 'paramètres manquants']);
                exit;
            }
            if (!preg_match('/^data:image\/(png|jpe?g|gif|webp);base64,[A-Za-z0-9+\/=]+$/', $imgData)) {
                http_response_code(400);
                echo json_encode(['error' => 'format image invalide']);
                exit;
            }
            if (strlen($imgData) > 6 * 1024 * 1024) {
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
            $imgId = uniqid('img_', true);
            $images[] = ['id' => $imgId, 'data' => $imgData];
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
            $stmt = $pdo->prepare("DELETE FROM notes WHERE id = :id AND user_id = :uid");
            $stmt->execute([':id' => $id, ':uid' => $userId]);
            echo json_encode(['ok' => true]);
            exit;
        }

        if ($action === 'notes_set_deleted' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            $data = json_decode(file_get_contents('php://input'), true);
            $id = (int)($data['id'] ?? 0);
            $deleted = !empty($data['deleted']) ? 1 : 0;
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
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
<title>NoteKeep</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>%F0%9F%92%A1</text></svg>">
<meta name="csrf-token" content="<?= htmlspecialchars(csrfToken()) ?>">
<link rel="stylesheet" href="style.css?v=2">
<style>
.mobile-topbar{ display: none; }
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
</style>
<script>
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
      <span class="brand-dot">💡</span>
      <span class="brand-name">Note<span>Keep</span></span>
    </div>
    <button class="side-item active" data-view="notesView">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 3v2a1 1 0 0 0 1 1h4a1 1 0 0 0 1-1V3"/><path d="M8 11h8"/><path d="M8 15h8"/><path d="M8 19h5"/></svg></span><span class="side-label"> Notes</span>
    </button>
    <button class="side-item" data-view="coursesView">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="20" r="1.4" fill="#ffffff" stroke="none"/><circle cx="17" cy="20" r="1.4" fill="#ffffff" stroke="none"/><path d="M3 4h2l2.2 11.2a2 2 0 0 0 2 1.6h7.6a2 2 0 0 0 2-1.6L21 8H6"/></svg></span><span class="side-label"> Liste de courses</span>
    </button>
    <button class="side-item" data-view="trashView">
      <span class="side-icon"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/><path d="M10 11v6"/><path d="M14 11v6"/></svg></span><span class="side-label"> Corbeille</span>
    </button>
    <button class="side-item" id="settingsBtn" style="margin-top:auto;" title="Paramètres">
      <span class="side-icon">⚙️</span>
    </button>
  </nav>

  <div class="content">
    <div class="mobile-topbar" id="mobileTopbar">
      <span class="mobile-topbar-brand">💡</span>
      <button id="settingsBtnMobile" title="Paramètres">⚙️</button>
    </div>
    <header>
      <div class="composer" id="composer">
        <input id="titleInput" type="text" placeholder="Créer une note">
        <hr id="composerHr" style="display:none;border:none;border-top:1px solid var(--line);margin:8px 0;">
        <textarea id="bodyInput" placeholder="Créer une note…" rows="1" style="display:none;"></textarea>
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
            <input id="memberInput" type="text" placeholder="Nom d'utilisateur ou email" style="flex:1;padding:6px 10px;border-radius:6px;border:1px solid var(--line);background:transparent;color:var(--ink);font-family:inherit;">
            <button class="btn primary" id="addMemberBtn">Inviter</button>
          </div>
          <div id="shareError" style="color:#c0392b;font-size:12px;margin-top:6px;"></div>
        </div>

        <div class="courses-composer">
          <input id="courseInput" type="text" placeholder="Ajouter un article…">
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

<script>
let notes = [];
let draftId = null;

const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]').content;
function authFetch(url, options = {}) {
  options.headers = Object.assign({}, options.headers, {'X-CSRF-Token': CSRF_TOKEN});
  return fetch(url, options);
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
  authFetch('index.php?action=notes_save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: n.id, title: n.title, body: n.body, color: n.color || ''})
  }).then(async res => {
    if(!res.ok){
      const err = await res.json().catch(()=>({}));
      console.error('Erreur sauvegarde note:', err);
    }
  }).catch(err => console.error('Erreur réseau notes_save:', err));
}
function deleteNoteFromServer(id){
  authFetch('index.php?action=notes_delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
}
function setDeletedOnServer(id, deleted){
  authFetch('index.php?action=notes_set_deleted', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id, deleted})
  });
}
function setPinnedOnServer(id, pinned){
  authFetch('index.php?action=notes_set_pinned', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id, pinned})
  });
}

async function loadNotes(){
  const res = await fetch('index.php?action=notes_list');
  notes = await res.json();
  render();
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
    draftId = Date.now();
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
  deleteNoteFromServer(id);
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

function noteCard(n){
  const div = document.createElement('div');
  div.className = 'note' + (n.pinned ? ' pinned' : '');
  if (n.color) {
    div.style.background = n.color;
    div.style.backgroundImage = 'none';
  }
  div.innerHTML = `
    <button class="pin-toggle" title="Épingler">${n.pinned ? '★' : '☆'}</button>
    <div class="note-modal-body">
      <div class="note-title" contenteditable="true" spellcheck="false" style="${n.title ? '' : 'display:none;'}">${escapeHtml(n.title)}</div>
      <div class="note-body" contenteditable="true" spellcheck="false">${escapeHtml(n.body)}</div>
      <div class="note-images" style="display:${(n.images && n.images.length) ? 'grid' : 'none'};grid-template-columns:repeat(auto-fill,minmax(70px,1fr));gap:6px;margin-top:10px;"></div>
    </div>
    <div class="note-modal-toolbar">
      <div class="toolbar-icons">
        <button type="button" title="Couleur"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22a10 10 0 1 1 0-20 8 8 0 0 1 8 8c0 2-1 3-3 3h-2a1.5 1.5 0 0 0-1 2.6c.3.3.5.7.5 1.1 0 1.3-1.1 2.3-2.5 2.3Z"/><circle cx="7" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="9.5" cy="7.5" r="1.2" fill="currentColor" stroke="none"/><circle cx="14.5" cy="7.5" r="1.2" fill="currentColor" stroke="none"/></svg></button>
        <button type="button" title="Image"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="8.5" cy="9.5" r="1.5"/><path d="M21 16l-5-5-4 4-2-2-5 5"/></svg></button>
        <button type="button" title="Partager"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="2.5"/><circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="19" r="2.5"/><path d="M8.2 10.7l7.6-4.4M8.2 13.3l7.6 4.4"/></svg></button>
        <button type="button" title="Supprimer"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16"/><path d="M9 7V4h6v3"/><path d="M6 7l1 13a2 2 0 0 0 2 2h6a2 2 0 0 0 2-2l1-13"/><path d="M10 11v6M14 11v6"/></svg></button>
      </div>
      <button type="button" class="close-btn">Fermer</button>
    </div>
  `;
  div.querySelector('.pin-toggle').onclick = (e) => { e.stopPropagation(); togglePin(n.id); };

  const colorBtn = div.querySelector('button[title="Couleur"]');
  if (colorBtn) {
    colorBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      openColorPicker(colorBtn, n, div);
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
    deleteBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      deleteNote(n.id);
    });
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
      noteImageInput._onPick = (dataUrl) => {
        n.images = n.images || [];
        const tempId = 'pending_' + Date.now();
        n.images.push({id: tempId, data: dataUrl});
        renderNoteImages();
        authFetch('index.php?action=notes_image_add', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: n.id, data: dataUrl})
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
    document.querySelectorAll('.note-overlay').forEach(el => el.remove());
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
    document.addEventListener('keydown', escHandler);
  }

  function closeModal(){
    if(!overlay) return;
    div.classList.remove('expanded');
    if(originalNext) originalParent.insertBefore(div, originalNext);
    else originalParent.appendChild(div);
    overlay.remove();
    overlay = null;
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

function render(){
  const active = notes.filter(n => !n.deleted);
  const pinned = active.filter(n => n.pinned);
  const others = active.filter(n => !n.pinned);

  document.getElementById('emptyMsg').style.display = active.length ? 'none' : 'block';

  const pinnedSection = document.getElementById('pinnedSection');
  const pinnedGrid = document.getElementById('pinnedGrid');
  pinnedGrid.innerHTML = '';
  if(pinned.length){
    pinnedSection.style.display = 'block';
    pinned.forEach(n => pinnedGrid.appendChild(noteCard(n)));
  } else {
    pinnedSection.style.display = 'none';
  }

  const othersSection = document.getElementById('othersSection');
  const othersGrid = document.getElementById('othersGrid');
  const othersLabel = document.getElementById('othersLabel');
  othersGrid.innerHTML = '';
  if(others.length){
    othersSection.style.display = 'block';
    othersLabel.textContent = pinned.length ? 'Autres' : 'Notes';
    others.forEach(n => othersGrid.appendChild(noteCard(n)));
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
  if(view === 'coursesView') loadLists();
}

document.querySelectorAll('.side-item[data-view]').forEach(btn => {
  btn.addEventListener('click', () => activateView(btn.dataset.view));
});

// -----------------------------------------------------
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

function openSettingsMenu(anchorEl){
  if(settingsMenu){ closeSettingsMenu(); return; }
  const rect = anchorEl.getBoundingClientRect();
  const menu = document.createElement('div');
  menu.style.cssText = `position:fixed;bottom:${window.innerHeight - rect.top + 6}px;left:${rect.left}px;background:var(--card);border:1px solid var(--line);border-radius:8px;box-shadow:0 4px 14px rgba(0,0,0,0.15);z-index:1000;overflow:hidden;min-width:${rect.width}px;`;
  menu.innerHTML = `
    <div class="ctx-item" data-action="theme" style="display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;padding:8px 14px;color:var(--ink);font-family:inherit;font-size:13px;cursor:pointer;">
      <span>Thème sombre</span>
      <span class="theme-switch" style="position:relative;width:34px;height:18px;border-radius:999px;background:${isDarkTheme() ? 'var(--accent)' : 'var(--line)'};flex-shrink:0;">
        <span style="position:absolute;top:2px;left:${isDarkTheme() ? '18px' : '2px'};width:14px;height:14px;border-radius:50%;background:#fff;transition:left 0.15s ease;"></span>
      </span>
    </div>
    <button class="ctx-item" data-action="switch" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:var(--ink);font-family:inherit;font-size:13px;">Changer de compte</button>
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
        sw.style.background = isDarkTheme() ? 'var(--accent)' : 'var(--line)';
        dot.style.left = isDarkTheme() ? '18px' : '2px';
        return;
      }
      closeSettingsMenu();
      if(action === 'switch' || action === 'logout'){
        await authFetch('auth.php?action=logout', {method: 'POST'});
        window.location.href = 'login.html';
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
  openSettingsMenu(e.currentTarget);
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

function currentList(){
  return lists.find(l => l.id === currentListId);
}

async function loadLists(){
  const res = await fetch('index.php?action=lists_list');
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
    btn.textContent = l.name + (l.is_owner ? '' : ' 👥');
    btn.onclick = () => selectList(l.id);
    btn.oncontextmenu = (e) => {
      e.preventDefault();
      if(!l.is_owner) return;
      showListContextMenu(e.pageX, e.pageY, l);
    };
    btn.ondblclick = (e) => {
      e.preventDefault();
      if(!l.is_owner) return;
      const name = prompt('Renommer le magasin :', l.name);
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
  const name = prompt('Nom du magasin :');
  if(!name || !name.trim()) return;
  const res = await authFetch('index.php?action=lists_add', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: name.trim()})
  });
  const data = await res.json();
  if(!res.ok){ alert(data.error || 'Erreur'); return; }
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
    <button class="ctx-item" data-action="rename" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:var(--ink);font-family:inherit;font-size:13px;">✏️ Renommer</button>
    <button class="ctx-item" data-action="delete" style="display:block;width:100%;text-align:left;padding:8px 14px;border:none;background:none;color:#c0392b;font-family:inherit;font-size:13px;">🗑️ Supprimer</button>
  `;
  menu.querySelectorAll('.ctx-item').forEach(btn => {
    btn.addEventListener('mouseenter', () => btn.style.background = 'var(--bg)');
    btn.addEventListener('mouseleave', () => btn.style.background = 'none');
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      closeListContextMenu();
      if(btn.dataset.action === 'rename'){
        const name = prompt('Renommer le magasin :', l.name);
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
  if(sharePanel.style.display === 'block') loadMembers();
});

async function loadMembers(){
  shareError.textContent = '';
  const l = currentList();
  shareListName.textContent = l ? l.name : '';
  const res = await fetch(`index.php?action=lists_members&list_id=${currentListId}`);
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
  memberInput.value = '';
  loadMembers();
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

async function loadCourses(){
  if(!currentListId) return;
  const res = await fetch(`index.php?action=list&list_id=${currentListId}`);
  const items = await res.json();
  renderCourses(items);
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
    <button class="course-check"></button>
    <span class="course-label" contenteditable="true" spellcheck="false">${escapeHtml(item.label)}</span>
    <button class="course-del">Supprimer</button>
  `;
  li.querySelector('.course-check').onclick = () => toggleCourse(item.id);
  li.querySelector('.course-del').onclick = () => deleteCourse(item.id);
  const label = li.querySelector('.course-label');

  function saveEditSilent(newLabel){
    item.label = newLabel;
    authFetch('index.php?action=edit', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({id: item.id, label: newLabel})
    }).catch(err => console.error('Erreur édition article:', err));
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
    <button class="course-check" disabled></button>
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
    const res = await authFetch('index.php?action=add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({label: value, list_id: currentListId})
    });
    if(!res.ok){
      const err = await res.json().catch(()=>({}));
      console.error('Erreur ajout article:', res.status, err);
      committed = false;
      return;
    }
    const data = await res.json();
    const newLi = courseItem({id: data.id, label: data.label, checked: 0});
    li.replaceWith(newLi);
    coursesEmpty.style.display = 'none';
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
  const res = await authFetch('index.php?action=add', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({label, list_id: currentListId})
  });
  if(!res.ok){
    const err = await res.json().catch(()=>({}));
    console.error('Erreur ajout article:', res.status, err);
    return;
  }
  courseInput.value = '';
  loadCourses();
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
  await authFetch('index.php?action=edit', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id, label})
  });
  loadCourses();
}

async function deleteCourse(id){
  await authFetch('index.php?action=delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id})
  });
  loadCourses();
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
</body>
</html>
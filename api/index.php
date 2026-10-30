<?php
// pkrtrckr API — a thin, zero-knowledge store.
// The browser derives two keys from the passphrase: an auth key (sent here, stored as a
// password_hash) and an encryption key (never leaves the browser). Everything stored
// below is ciphertext the server cannot read.

declare(strict_types=1);

$CFG = require __DIR__ . '/config.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function out(array $data, int $code = 200): never {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}
function fail(string $msg, int $code = 400): never { out(['error' => $msg], $code); }

// ---- request guards -------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') fail('POST only', 405);
// CSRF: browsers won't send this custom header cross-site without a CORS preflight we never allow.
if (($_SERVER['HTTP_X_PKR'] ?? '') !== '1') fail('Bad request', 400);
$raw = file_get_contents('php://input', false, null, 0, 6 * 1024 * 1024);
$in = json_decode($raw ?: '{}', true);
if (!is_array($in)) fail('Bad JSON');
$action = (string)($_GET['a'] ?? '');

// ---- db ------------------------------------------------------------------
function db(): PDO {
    static $pdo = null;
    global $CFG;
    if ($pdo === null) {
        try {
            $pdo = new PDO($CFG['db_dsn'], $CFG['db_user'], $CFG['db_pass'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (Throwable $e) {
            fail('Database unavailable', 503);
        }
    }
    return $pdo;
}
function q(string $sql, array $p = []): PDOStatement { $s = db()->prepare($sql); $s->execute($p); return $s; }

// ---- session -------------------------------------------------------------
$secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
session_name($secure ? '__Host-pkr' : 'pkr');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $secure, 'httponly' => true, 'samesite' => 'Strict']);
ini_set('session.use_strict_mode', '1');
ini_set('session.gc_maxlifetime', (string)$CFG['idle_timeout']);
session_start();

function uid(): int {
    global $CFG;
    $id = (int)($_SESSION['uid'] ?? 0);
    $last = (int)($_SESSION['seen'] ?? 0);
    if (!$id || time() - $last > $CFG['idle_timeout']) {
        $_SESSION = [];
        fail('Signed out', 401);
    }
    $_SESSION['seen'] = time();
    return $id;
}
function sign_in(int $id): void {
    session_regenerate_id(true);
    $_SESSION['uid'] = $id;
    $_SESSION['seen'] = time();
}

// ---- validation ----------------------------------------------------------
function username(array $in): string {
    $u = strtolower(trim((string)($in['username'] ?? '')));
    if (!preg_match('/^[a-z0-9._-]{3,32}$/', $u)) fail('Name must be 3–32 characters: letters, numbers, dot, dash or underscore.');
    return $u;
}
function b64(mixed $v, int $min, int $max): string {
    $v = (string)$v;
    if (strlen($v) < $min || strlen($v) > $max || !preg_match('#^[A-Za-z0-9+/]+=*$#', $v)) fail('Bad payload');
    return $v;
}
function hexkey(mixed $v): string {
    $v = (string)$v;
    if (!preg_match('/^[0-9a-f]{64}$/', $v)) fail('Bad payload');
    return $v;
}
function ip_tag(): string {
    global $CFG;
    return substr(hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? '', $CFG['secret']), 0, 32);
}
function attempts(string $kind, int $window): int {
    return (int)q('SELECT COUNT(*) FROM attempts WHERE kind = ? AND ip = ? AND ts > ?', [$kind, ip_tag(), time() - $window])->fetchColumn();
}
function record_attempt(string $kind): void {
    q('INSERT INTO attempts (kind, ip, ts) VALUES (?, ?, ?)', [$kind, ip_tag(), time()]);
    if (random_int(1, 50) === 1) q('DELETE FROM attempts WHERE ts < ?', [time() - 86400]);
}

// ---- actions -------------------------------------------------------------
switch ($action) {

case 'prelogin': {
    // Returns the KDF salt. Unknown names get a stable decoy so names can't be probed.
    $u = username($in);
    $row = q('SELECT salt, kdf_iter FROM users WHERE username = ?', [$u])->fetch();
    if ($row) out(['salt' => $row['salt'], 'iter' => (int)$row['kdf_iter']]);
    $fake = base64_encode(substr(hash_hmac('sha256', 'salt:' . $u, $CFG['secret'], true), 0, 16));
    out(['salt' => $fake, 'iter' => (int)$CFG['kdf_iter']]);
}

case 'signup': {
    $u = username($in);
    $salt = b64($in['salt'] ?? '', 24, 64);
    $auth = hexkey($in['auth'] ?? '');
    $iter = (int)($in['iter'] ?? 0);
    if ($iter < 100000 || $iter > 5000000) fail('Bad payload');
    if (attempts('signup', 3600) >= $CFG['max_signups_per_ip_per_hour']) fail('Too many sign-ups from this network. Try again later.', 429);
    if (q('SELECT 1 FROM users WHERE username = ?', [$u])->fetchColumn()) fail('That name is taken.', 409);
    record_attempt('signup');
    try {
        q('INSERT INTO users (username, salt, kdf_iter, auth_hash, created_at) VALUES (?, ?, ?, ?, ?)',
          [$u, $salt, $iter, password_hash($auth, PASSWORD_DEFAULT), time()]);
    } catch (PDOException $e) {
        fail('That name is taken.', 409);
    }
    sign_in((int)db()->lastInsertId());
    out(['ok' => true]);
}

case 'login': {
    $u = username($in);
    $auth = hexkey($in['auth'] ?? '');
    if (attempts('login', 900) >= $CFG['max_login_failures_per_ip']) fail('Too many attempts. Wait 15 minutes and try again.', 429);
    $row = q('SELECT id, auth_hash, failed_logins, locked_until FROM users WHERE username = ?', [$u])->fetch();
    if ($row && (int)$row['locked_until'] > time()) fail('Too many attempts. Wait 15 minutes and try again.', 429);
    $ok = $row && password_verify($auth, $row['auth_hash']);
    if (!$row) password_verify($auth, '$2y$10$tMiEjSuS.s9KTUF8yrbyhuL7eMxqWBLkeF0dwHEpk2F1YCFU.Dw5W'); // even out timing
    if (!$ok) {
        record_attempt('login');
        if ($row) {
            $f = (int)$row['failed_logins'] + 1;
            $lock = $f >= $CFG['max_failures_per_account'] ? time() + $CFG['lock_seconds'] : 0;
            q('UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?', [$lock ? 0 : $f, $lock, $row['id']]);
        }
        fail('Wrong name or passphrase.', 401);
    }
    q('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE id = ?', [$row['id']]);
    if (password_needs_rehash($row['auth_hash'], PASSWORD_DEFAULT)) {
        q('UPDATE users SET auth_hash = ? WHERE id = ?', [password_hash($auth, PASSWORD_DEFAULT), $row['id']]);
    }
    sign_in((int)$row['id']);
    out(['ok' => true]);
}

case 'logout': {
    $_SESSION = [];
    session_destroy();
    out(['ok' => true]);
}

case 'ping': {
    uid();
    out(['ok' => true]);
}

case 'data': {
    $id = uid();
    $u = q('SELECT prefs_iv, prefs_ct FROM users WHERE id = ?', [$id])->fetch();
    $rows = q('SELECT id, iv, ct FROM entries WHERE user_id = ? ORDER BY id', [$id])->fetchAll();
    foreach ($rows as &$r) $r['id'] = (int)$r['id'];
    out([
        'prefs' => ($u && $u['prefs_ct']) ? ['iv' => $u['prefs_iv'], 'ct' => $u['prefs_ct']] : null,
        'entries' => $rows,
    ]);
}

case 'save': {
    $id = uid();
    $iv = b64($in['iv'] ?? '', 16, 24);
    $ct = b64($in['ct'] ?? '', 16, 8000);
    $eid = (int)($in['id'] ?? 0);
    if ($eid) {
        $s = q('UPDATE entries SET iv = ?, ct = ?, updated_at = ? WHERE id = ? AND user_id = ?', [$iv, $ct, time(), $eid, $id]);
        if (!q('SELECT 1 FROM entries WHERE id = ? AND user_id = ?', [$eid, $id])->fetchColumn()) fail('Not found', 404);
        out(['id' => $eid]);
    }
    $n = (int)q('SELECT COUNT(*) FROM entries WHERE user_id = ?', [$id])->fetchColumn();
    if ($n >= 50000) fail('Session limit reached.');
    q('INSERT INTO entries (user_id, iv, ct, created_at, updated_at) VALUES (?, ?, ?, ?, ?)', [$id, $iv, $ct, time(), time()]);
    out(['id' => (int)db()->lastInsertId()]);
}

case 'import': {
    $id = uid();
    $items = $in['items'] ?? null;
    if (!is_array($items) || count($items) > 5000) fail('Import up to 5000 sessions at a time.');
    $n = (int)q('SELECT COUNT(*) FROM entries WHERE user_id = ?', [$id])->fetchColumn();
    if ($n + count($items) > 50000) fail('Session limit reached.');
    $ids = [];
    db()->beginTransaction();
    $st = db()->prepare('INSERT INTO entries (user_id, iv, ct, created_at, updated_at) VALUES (?, ?, ?, ?, ?)');
    foreach ($items as $it) {
        if (!is_array($it)) { db()->rollBack(); fail('Bad payload'); }
        $st->execute([$id, b64($it['iv'] ?? '', 16, 24), b64($it['ct'] ?? '', 16, 8000), time(), time()]);
        $ids[] = (int)db()->lastInsertId();
    }
    db()->commit();
    out(['ids' => $ids]);
}

case 'delete': {
    $id = uid();
    q('DELETE FROM entries WHERE id = ? AND user_id = ?', [(int)($in['id'] ?? 0), $id]);
    out(['ok' => true]);
}

case 'prefs': {
    $id = uid();
    q('UPDATE users SET prefs_iv = ?, prefs_ct = ? WHERE id = ?', [b64($in['iv'] ?? '', 16, 24), b64($in['ct'] ?? '', 16, 400000), $id]);
    out(['ok' => true]);
}

case 'delete_account': {
    $id = uid();
    $auth = hexkey($in['auth'] ?? '');
    $row = q('SELECT auth_hash FROM users WHERE id = ?', [$id])->fetch();
    if (!$row || !password_verify($auth, $row['auth_hash'])) fail('Wrong passphrase.', 401);
    q('DELETE FROM entries WHERE user_id = ?', [$id]);
    q('DELETE FROM users WHERE id = ?', [$id]);
    $_SESSION = [];
    session_destroy();
    out(['ok' => true]);
}

default:
    fail('Unknown action', 404);
}

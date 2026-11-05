<?php
// pkrtrckr API — a thin, zero-knowledge store.
// The browser derives two keys from the passphrase: an auth key (sent here, stored as a
// password_hash) and an encryption key (never leaves the browser). Everything stored
// below is ciphertext the server cannot read.

declare(strict_types=1);

$CFG = require __DIR__ . '/config.php';
date_default_timezone_set($CFG['timezone'] ?? 'Europe/Amsterdam');

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
    track($id);
    return $id;
}
function sign_in(int $id): void {
    session_regenerate_id(true);
    $_SESSION['uid'] = $id;
    $_SESSION['seen'] = time();
    track($id, true);
}

// Usage metadata for the admin dashboard: last seen, login count, and one row per active day.
// Only dates and counts — session contents are encrypted and unreadable here.
// Wrapped so a missing migration can never break the app.
function track(int $id, bool $login = false): void {
    try {
        $now = time();
        if ($login) {
            q('UPDATE users SET last_login_at = ?, last_seen_at = ?, login_count = login_count + 1 WHERE id = ?', [$now, $now, $id]);
        } elseif ($now - (int)($_SESSION['tracked'] ?? 0) > 300) {
            q('UPDATE users SET last_seen_at = ? WHERE id = ?', [$now, $id]);
        } else {
            return;
        }
        $_SESSION['tracked'] = $now;
        $day = (int)date('Ymd', $now);
        if ((int)($_SESSION['act_day'] ?? 0) !== $day) {
            try { q('INSERT INTO activity (user_id, day) VALUES (?, ?)', [$id, $day]); } catch (PDOException $e) { /* already counted today */ }
            $_SESSION['act_day'] = $day;
        }
    } catch (Throwable $e) {
        // tracking is best-effort
    }
}
function is_admin(int $id): bool {
    global $CFG;
    $admins = array_map('strtolower', (array)($CFG['admin_users'] ?? []));
    if (!$admins) return false;
    $name = q('SELECT username FROM users WHERE id = ?', [$id])->fetchColumn();
    return $name !== false && in_array($name, $admins, true);
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
        'admin' => is_admin($id),
    ]);
}

case 'save': {
    $id = uid();
    $iv = b64($in['iv'] ?? '', 16, 24);
    $ct = b64($in['ct'] ?? '', 16, 16000);
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
        $st->execute([$id, b64($it['iv'] ?? '', 16, 24), b64($it['ct'] ?? '', 16, 16000), time(), time()]);
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
    try { q('DELETE FROM activity WHERE user_id = ?', [$id]); } catch (PDOException $e) { /* table not migrated yet */ }
    q('DELETE FROM users WHERE id = ?', [$id]);
    $_SESSION = [];
    session_destroy();
    out(['ok' => true]);
}

case 'admin_stats': {
    $id = uid();
    if (!is_admin($id)) fail('Not found', 404);
    try {
        $c = fn(string $sql, array $p = []): int => (int)q($sql, $p)->fetchColumn();
        $today = strtotime('today');
        $since = fn(int $days): int => strtotime('-' . ($days - 1) . ' days', $today);
        $dayInt = fn(int $ts): int => (int)date('Ymd', $ts);
        $t = [
            'users'              => $c('SELECT COUNT(*) FROM users'),
            'users_with_entries' => $c('SELECT COUNT(DISTINCT user_id) FROM entries'),
            'entries'            => $c('SELECT COUNT(*) FROM entries'),
        ];
        foreach ([1, 7, 30] as $d) {
            $t["signups_$d"] = $c('SELECT COUNT(*) FROM users WHERE created_at >= ?', [$since($d)]);
            $t["active_$d"]  = $c('SELECT COUNT(DISTINCT user_id) FROM activity WHERE day >= ?', [$dayInt($since($d))]);
            $t["entries_$d"] = $c('SELECT COUNT(*) FROM entries WHERE created_at >= ?', [$since($d)]);
        }
        // Daily series for the last 90 days (bucketed in PHP so the SQL stays portable).
        $from = $since(90);
        $days = [];
        for ($ts = $from; $ts <= $today; $ts = strtotime('+1 day', $ts)) $days[date('Y-m-d', $ts)] = ['signups' => 0, 'active' => 0, 'entries' => 0];
        foreach (q('SELECT created_at FROM users WHERE created_at >= ?', [$from])->fetchAll(PDO::FETCH_COLUMN) as $ts) { $k = date('Y-m-d', (int)$ts); if (isset($days[$k])) $days[$k]['signups']++; }
        foreach (q('SELECT created_at FROM entries WHERE created_at >= ?', [$from])->fetchAll(PDO::FETCH_COLUMN) as $ts) { $k = date('Y-m-d', (int)$ts); if (isset($days[$k])) $days[$k]['entries']++; }
        foreach (q('SELECT day, COUNT(*) AS n FROM activity WHERE day >= ? GROUP BY day', [$dayInt($from)])->fetchAll() as $r) {
            $k = substr((string)$r['day'], 0, 4) . '-' . substr((string)$r['day'], 4, 2) . '-' . substr((string)$r['day'], 6, 2);
            if (isset($days[$k])) $days[$k]['active'] = (int)$r['n'];
        }
        $series = [];
        foreach ($days as $k => $v) $series[] = ['d' => $k] + $v;
        $users = q('SELECT u.username, u.created_at, u.last_seen_at, u.login_count,
                      (SELECT COUNT(*) FROM entries e WHERE e.user_id = u.id) AS entries,
                      (SELECT COUNT(*) FROM activity a WHERE a.user_id = u.id) AS active_days
                    FROM users u ORDER BY u.last_seen_at DESC, u.id DESC LIMIT 1000')->fetchAll();
        foreach ($users as &$u) foreach (['created_at', 'last_seen_at', 'login_count', 'entries', 'active_days'] as $k) $u[$k] = (int)$u[$k];
        out(['generated' => time(), 'tz' => date_default_timezone_get(), 'totals' => $t, 'series' => $series, 'users' => $users]);
    } catch (PDOException $e) {
        fail('Dashboard tables are missing. Run migrations/001-admin-dashboard.sql in phpMyAdmin.', 500);
    }
}

default:
    fail('Unknown action', 404);
}

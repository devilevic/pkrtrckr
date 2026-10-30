<?php
// pkrtrckr configuration template.
// Copy this file to config.php (same folder) and fill in your real values.
// config.php is listed in .gitignore so your password never ends up on GitHub,
// and api/.htaccess blocks both files from the web.

return [
    // cPanel > MySQL Databases. Names are usually prefixed with your cPanel user, e.g. "cpuser_pkrtrckr".
    'db_dsn'  => 'mysql:host=localhost;dbname=CPANELUSER_pkrtrckr;charset=utf8mb4',
    'db_user' => 'CPANELUSER_pkrtrckr',
    'db_pass' => 'CHANGE-ME',

    // A long random string, used to make decoy salts for unknown usernames and to hash IPs.
    // Generate one at a terminal with:  openssl rand -hex 32
    // Keep it stable once people have signed up.
    'secret'  => 'CHANGE-ME-TO-64-RANDOM-HEX-CHARACTERS',

    // Sign out after this many seconds without activity.
    'idle_timeout' => 15 * 60,

    // Brute-force limits.
    'max_login_failures_per_ip'   => 10,   // per 15 minutes
    'max_failures_per_account'    => 8,    // then the account is locked for lock_seconds
    'lock_seconds'                => 15 * 60,
    'max_signups_per_ip_per_hour' => 5,

    // PBKDF2 iterations used for NEW accounts (existing accounts keep theirs).
    'kdf_iter' => 600000,
];

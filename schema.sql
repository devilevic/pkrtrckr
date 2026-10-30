-- pkrtrckr database schema (MySQL / MariaDB)
-- Import this once in cPanel > phpMyAdmin > (your database) > Import.
-- The server only ever stores ciphertext: every session and every dropdown list
-- is encrypted in the browser with a key derived from the user's passphrase.

CREATE TABLE IF NOT EXISTS users (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(32)  NOT NULL,
  salt          VARCHAR(64)  NOT NULL,          -- KDF salt (base64), not secret
  kdf_iter      INT UNSIGNED NOT NULL,
  auth_hash     VARCHAR(255) NOT NULL,          -- password_hash() of the client-derived auth key
  prefs_iv      VARCHAR(32)  NULL,              -- encrypted settings + dropdown lists
  prefs_ct      MEDIUMTEXT   NULL,
  failed_logins INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until  INT UNSIGNED NOT NULL DEFAULT 0,
  created_at    INT UNSIGNED NOT NULL,
  UNIQUE KEY uq_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS entries (
  id         INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id    INT UNSIGNED NOT NULL,
  iv         VARCHAR(32)  NOT NULL,
  ct         TEXT         NOT NULL,             -- AES-256-GCM ciphertext (base64)
  created_at INT UNSIGNED NOT NULL,
  updated_at INT UNSIGNED NOT NULL,
  KEY idx_user (user_id),
  CONSTRAINT fk_entries_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS attempts (
  id    INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  kind  VARCHAR(16)  NOT NULL,                  -- 'login' or 'signup'
  ip    VARCHAR(64)  NOT NULL,                  -- hashed IP, never the raw address
  ts    INT UNSIGNED NOT NULL,
  KEY idx_kind_ip_ts (kind, ip, ts)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

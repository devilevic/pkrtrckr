-- pkrtrckr migration 001: usage metadata for the admin dashboard.
-- Run ONCE in cPanel > phpMyAdmin > (your database) > SQL tab.
-- Stores only dates and counts. Session contents stay encrypted.

ALTER TABLE users
  ADD COLUMN last_login_at INT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN last_seen_at  INT UNSIGNED NOT NULL DEFAULT 0,
  ADD COLUMN login_count   INT UNSIGNED NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS activity (
  user_id INT UNSIGNED NOT NULL,
  day     INT UNSIGNED NOT NULL,              -- YYYYMMDD in the server's timezone
  PRIMARY KEY (user_id, day),
  KEY idx_day (day),
  CONSTRAINT fk_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Best guess for existing accounts: last seen = when they last saved a session, or sign-up time.
UPDATE users u SET last_seen_at = GREATEST(u.created_at,
  COALESCE((SELECT MAX(e.updated_at) FROM entries e WHERE e.user_id = u.id), 0));

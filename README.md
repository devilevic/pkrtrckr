# pkrtrckr — setup on Namecheap

Plain HTML/JS front end + one PHP file + MySQL. No build step and no Composer packages.
Needs PHP 8.1 or newer (cPanel > Select PHP Version).

## 1. Domain and SSL
1. Point pkrtrckr.com at your hosting and add it in cPanel (Domains) with its own folder, e.g. `pkrtrckr.com/`.
2. cPanel > SSL/TLS Status > Run AutoSSL so https works. The app needs HTTPS: browsers only allow the encryption API on secure pages.

## 2. Database
1. cPanel > MySQL Databases: create a database (e.g. `pkrtrckr`) and a user with a strong password. Add the user to the database with **ALL PRIVILEGES**.
2. cPanel > phpMyAdmin: select the database > Import > choose `schema.sql` > Go.

## 3. Configure
Copy `api/config.example.php` to `api/config.php` and fill it in
(`config.php` is git-ignored, so the password never goes to GitHub):
- `db_dsn`, `db_user`, `db_pass` — the full prefixed names cPanel shows (e.g. `cpuser_pkrtrckr`).
- `secret` — a long random string (at a terminal: `openssl rand -hex 32`). Keep it stable.

## 4. Upload
Upload everything **except** `schema.sql` and `README.md` into the domain's folder (File Manager > Upload the zip > Extract).
Make sure the hidden `.htaccess` files are there (root and `api/`).

Check: `https://pkrtrckr.com/api/config.php` must show *403 Forbidden*.

## How the encryption works
- On sign-up the browser makes a random salt and runs PBKDF2-SHA256 (600,000 rounds) on the passphrase, then HKDF splits the result into two keys:
  - an **auth key**, sent to the server and stored only as a bcrypt hash;
  - an **encryption key**, which never leaves the browser.
- Every session, and the dropdown lists and settings, are encrypted with AES-256-GCM before upload. The database holds only ciphertext — the host, or anyone who gets a copy of the database, can't read results, locations, games or stakes.
- Stats, filters and charts are computed on the device after decrypting.
- No passphrase reset is possible by design. Users should keep a CSV export (Settings > Export CSV).
- Brute-force limits: 10 failed logins per IP per 15 min; an account locks for 15 min after 8 failures. Sign-ups are limited to 5 per IP per hour.
- Sessions sign out after 15 minutes of inactivity.

## Files
```
index.html            app shell
manifest.webmanifest  "Add to Home Screen" support
assets/app.js         app + crypto
assets/app.css        styles (dark/light follow the phone setting)
assets/icon*.{svg,png}
api/index.php         the API (prelogin, signup, login, logout, data, save, import, delete, prefs, delete_account)
api/config.php        database credentials (git-ignored, blocked from the web)
api/config.example.php  template for config.php
.htaccess             HTTPS redirect, security headers, CSP
schema.sql            database tables — import once, don't upload
```

## Updating later
When you change `app.js` or `app.css`, bump `?v=1` to `?v=2` in `index.html` so phones load the new version.

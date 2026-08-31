# Security Notes — Cyber Terrafor Professional v11.1.0

- Network assessment is scope-controlled.
- The administration dashboard binds to localhost by default.
- Admin passwords are stored as PBKDF2-HMAC-SHA256 hashes with per-user salts.
- Dashboard sessions use random tokens and HttpOnly/SameSite cookies.
- Ransomware Guard is detection/alerting oriented and does not attempt to disable, decrypt or destroy attacker processes.
- Quarantine moves flagged files to a local quarantine directory rather than deleting them.
- Reports may contain sensitive target information; protect the `reports/` directory.
- Before exposing the admin dashboard beyond localhost, place it behind a trusted TLS reverse proxy and network access control.

## Infrastructure adapter security boundary (v11.1.0)

Provider adapters are deliberately read-only. The panel never turns stored SSH credentials into arbitrary command execution. Provider tokens should be least-privilege, scoped to the authorized account/site, and rotated periodically. cPanel endpoints must use HTTPS.

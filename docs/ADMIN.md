# Cyber Terrafor Professional v7.2 — Local Administration Panel

Start the dashboard with:

`./cyber-terrafor admin`

The first launch creates an administrator account. No packaged administrator password is shipped.

## Control-plane capabilities

- Authenticated administrator login
- Mandatory HTTPS site registration
- Explicit hostname/IP/CIDR/wildcard scope validation
- Per-site connector token issuance and one-time display
- Immediate connector token rotation/revocation
- Enable/disable connector integration
- Encrypted infrastructure credential vault
- Hosting/DNS/SSH/SFTP/database credential storage
- Audit log for administrative and connector events
- Connector status, heartbeat and event API
- Local security-operations dashboard

## Vault security

The vault uses a random 256-bit master key. That key is wrapped by a password-derived PBKDF2-HMAC-SHA256 key and the individual site records are encrypted with AES-256-GCM. The administrator password is not stored in the session; only the unwrapped vault key is held in process memory while the session is active. Existing secrets are never rendered back to the browser.

## Connector API

The connector exposes only non-command operations:

- `GET /api/v1/site/status`
- `POST /api/v1/site/heartbeat`
- `POST /api/v1/site/event`

Every request requires the site's bearer token. Disabled sites are rejected and tokens are stored only as SHA-256 hashes in the control-plane configuration.

Example:

```bash
python3 site_connector.py --panel http://127.0.0.1:8787 --site-id SITE_ID --token CONNECTOR_TOKEN heartbeat
```

The control plane intentionally does **not** expose arbitrary remote shell/SSH execution. Provider-specific operational adapters can be added under a separate, explicitly authorized integration layer.

## Deployment

The server binds to `127.0.0.1` by default. For remote administration, place it behind a trusted TLS reverse proxy/VPN and network ACL. Do not expose the development HTTP server directly to the public Internet.

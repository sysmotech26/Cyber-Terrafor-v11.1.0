# Cyber Terrafor Professional v11.0.0 — Enterprise Upgrade

This release adds an enterprise intelligence/control layer on top of the v10 assessment engines.

## New capabilities

- Enterprise asset inventory with safe DNS-based discovery and criticality scoring
- Vulnerability correlation with CVSS v4 / EPSS fields and importable vulnerability catalogs
- Dynamic risk model: severity + confidence + CVSS v4 + EPSS + exposure + asset criticality + business impact
- Finding-to-asset correlation in a local SQLite data store
- Secret detection for source/configuration trees with fingerprints rather than secret disclosure
- Docker/Compose configuration security checks
- Evidence sealing with SHA-256 artifacts and Ed25519 signatures when `cryptography` is available
- Compliance matrix generation for NIST CSF, CIS, ISO 27001, PCI DSS and OWASP-oriented controls
- Local role/permission model for future multi-user control-plane expansion
- Scheduled-job registry for continuous monitoring orchestration
- Enterprise Security Center dashboard metrics

## CLI

```bash
./cyber-terrafor enterprise-center
./cyber-terrafor enterprise-assets --target https://example.com --criticality 80
./cyber-terrafor enterprise-risk --target https://example.com
./cyber-terrafor enterprise-compliance --target https://example.com
./cyber-terrafor secret-scan ./project
./cyber-terrafor container-audit ./project
./cyber-terrafor evidence-seal
./cyber-terrafor vuln-feed-import ./vulnerability-feed.json
./cyber-terrafor schedule https://example.com enterprise-deep-analysis "daily"
```

## Important scope

The upgrade remains defensive and authorization-first. It does not add credential attacks, persistence, destructive exploitation, arbitrary remote shell execution, or ransomware deployment. CVE/EPSS data is only as current as the imported feed; an offline catalog is intentionally not presented as a complete vulnerability database.


## Enterprise Authentication Upgrade

The control plane now uses a first-run administrator setup instead of a packaged/default password. On a fresh installation, open the local admin URL and create an administrator username and password (minimum 14 characters).

Authentication controls include:
- PBKDF2-HMAC-SHA256 password hashing with per-account salt
- first-run setup with no generated/default credential file
- temporary lockout after repeated failed logins
- hashed session identifiers stored server-side
- HttpOnly + SameSite session cookies
- idle renewal with an 8-hour absolute session lifetime
- CSRF protection for state-changing browser requests
- role model (`super_admin`, `security_admin`, `analyst`, `auditor`, `viewer`) ready for multi-user expansion
- password-change workflow that re-wraps the encrypted infrastructure vault and revokes active sessions
- MFA-ready authentication boundary (MFA provider integration remains a deployment choice)

### First Run

1. Start `./cyber-terrafor admin-panel` (or the existing admin-panel command).
2. Visit the displayed local URL.
3. Create your own administrator credentials at `/setup`.
4. Sign in at `/login`.
5. Use **Security** in the control panel to rotate the administrator password.

The system does not ship with `admin/admin123`, and it does not print a bootstrap password into the source tree.

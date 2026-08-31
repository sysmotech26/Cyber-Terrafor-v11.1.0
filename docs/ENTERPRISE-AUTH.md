# Cyber Terrafor Professional — Enterprise IAM & MFA

## Identity & Access

The control plane supports multiple local users with role-based access:

- `super_admin`: full administration and user lifecycle management
- `security_admin`: security operations, assessments, vault and audit access
- `analyst`: assessments, file security and reports
- `auditor`: reports and audit evidence
- `viewer`: dashboard and reports

User credentials are stored as salted PBKDF2-HMAC-SHA256 password hashes. Production passwords are never stored in source code.

## TOTP MFA

Users can open **MFA** after signing in. The enrollment screen provides a Base32 secret and standards-compatible `otpauth://` URI. Add it to a compatible authenticator and verify a current 6-digit code.

`super_admin` and `security_admin` are policy-required MFA roles. A newly created account receives an enrollment session so it can enroll TOTP; once enabled, future logins require the code.

## Connector API scopes

Connector tokens are scoped to explicit API capabilities:

- `status`
- `heartbeat`
- `event`

Requests outside the connector's assigned scope are rejected.

## Important deployment note

The distribution package intentionally contains no administrator password, no populated `state/admin.json`, and no evidence-signing private key. The evidence signing key is generated locally when evidence sealing is first used and must be backed up securely by the operator.

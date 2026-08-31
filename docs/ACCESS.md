# Cyber Terrafor Enterprise — Access & Delivery

## Access model
Cyber Terrafor is a local/Linux-oriented assessment toolkit. The current package does **not** claim to provide a built-in enterprise user-account, RBAC, SSO, or SaaS authentication system.

Enterprise access should therefore be controlled through:

- OS user permissions
- Private repository permissions
- Secure file transfer
- Authorized operator accounts
- Customer-specific deployment directories
- Contractual access restrictions
- Secret/key management outside source control

## Buyer delivery checklist
- [ ] Executed acquisition agreement
- [ ] Confirmed buyer identity/contact
- [ ] Confirmed transferred source-code scope
- [ ] Confirmed IP assignment scope
- [ ] Confirmed third-party/open-source exclusions
- [ ] Source package checksum recorded
- [ ] Secure delivery channel selected
- [ ] Access credentials/keys delivered separately when applicable
- [ ] Buyer confirms receipt
- [ ] Buyer completes installation test

## Recommended production practice
Do not put passwords, API keys, private tokens, customer credentials, or signing keys inside this repository. Use environment variables or an approved secrets manager.

## Integrity
Record a SHA-256 checksum for the final delivered archive. The checksum is an integrity identifier, not proof of ownership or legal title.

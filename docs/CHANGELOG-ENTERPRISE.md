# Cyber Terrafor Enterprise Changelog

## 10.0.0 — Deep Web Pentest & Unified Assessment Upgrade

- Added Safe Active Web Pentest Engine.
- Added bounded same-origin crawler and endpoint/form discovery.
- Added authentication/session security observations.
- Added API/OpenAPI/Swagger/GraphQL surface discovery.
- Added safe HTTP method validation.
- Added per-request scope re-validation for discovered URLs.
- Integrated deep web pentesting into Enterprise Deep Analysis.
- Added `deep-web-pentest` CLI and admin-panel module.
- Added Deep Web and Enterprise assessment profiles.
- Added regression tests for parser, scope gating and non-destructive controls.
- Bumped product version to 10.0.0.

# Cyber Terrafor Enterprise Bundle — Change Log

## 7.2.0 Enterprise Packaging
- Added enterprise acquisition documentation.
- Added commercial license template.
- Added usage and deployment guide.
- Added access and secure-delivery guidance.
- Added enterprise notes and limitations.
- Added synthetic demo result package.
- Added buyer due-diligence checklist.
- Standardized package-facing version label to 7.2.0.
- Preserved the existing defensive assessment implementation rather than introducing new offensive capabilities.

## 11.0.0 — Enterprise Exposure & Risk Intelligence Upgrade

- Added enterprise asset inventory with safe DNS discovery and asset criticality.
- Added vulnerability catalog import and CVSS v4 / EPSS-aware risk correlation.
- Added finding-to-asset persistence in a local SQLite enterprise database.
- Added secret detection and Docker/Compose configuration security checks.
- Added evidence sealing with SHA-256 artifact hashes and Ed25519 signatures when available.
- Added compliance matrix generation and scheduled-job registry.
- Added Enterprise Security Center metrics.
- Removed the packaged fixed administrator password; first-run credentials are generated locally and written to a mode-600 bootstrap file.
- Preserved scope enforcement and non-destructive assessment boundaries.

## v11.0.0 Enterprise Auth Expansion
- Multi-user RBAC with role-isolated route enforcement
- TOTP MFA enrollment, verification, reset and policy enforcement
- User lifecycle administration restricted to super administrators
- Scoped connector API permissions
- No packaged admin credentials or evidence private key

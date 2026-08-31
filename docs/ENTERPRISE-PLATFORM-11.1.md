# Cyber Terrafor Professional 11.1 Enterprise Platform Upgrade

## New capability layers
- Vulnerability Management lifecycle: feed import, lookup, remediation queue, owner/SLA status, verification.
- Asset / Attack Surface Management: safe DNS-based snapshot and change detection.
- Risk intelligence data model: vulnerability CVSS v4 + EPSS fields can be correlated by the existing risk engine.
- Evidence-aware verification: remediation can be closed by a later verification event with an evidence hash.
- Cloud posture export audit: offline JSON inventory/configuration auditing; no provider write actions.
- Threat intelligence store: IOC import and lookup for supplied feeds.
- Enterprise Security Center counters and overdue remediation visibility.
- Existing scope gates, safe-active assessment, IAM/MFA, vault and defensive monitoring remain intact.

## Explicit limitations
This release does not claim to be a complete commercial replacement for a full VM/ASM/SIEM/EDR product. Live CVE/EPSS/IOC feeds, provider SDK credentials, endpoint agents, SIEM connectors and production HA infrastructure are deployment integrations rather than fabricated offline data.

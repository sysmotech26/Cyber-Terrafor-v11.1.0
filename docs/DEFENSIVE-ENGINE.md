# Defensive Protection Engine

## Anti-Malware Defense

`malware-scan` computes SHA-256, file entropy and identifies common executable and ransomware-related indicators. It is intentionally evidence-based and does not claim to be a full commercial malware signature engine.

`malware-scan <file> --quarantine` moves a flagged file into `state/quarantine/` instead of deleting it.

## Anti-Ransomware Guard

1. `baseline <directory>` creates a SHA-256 file-integrity baseline.
2. `ransomware-guard <directory> --once` compares the current state to the baseline.
3. Without `--once`, the guard continuously monitors the directory at the requested interval.

Signals include bursts of file additions/changes, suspicious ransomware-like extensions, ransom-note-like filenames and high-entropy changes.

The guard is a defensive detection and containment aid. It does not decrypt files, terminate attacker processes, or perform destructive counter-actions.

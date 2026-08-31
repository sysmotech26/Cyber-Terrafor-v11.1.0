# Cyber Terrafor Enterprise — Usage Guide

## Authorized-use requirement
Run Cyber Terrafor only against assets you own or have explicit permission to assess. Define the assessment boundary before network actions.

## 1. Installation — Linux
```bash
cd Cyber-Terrafor-Professional-v7.2
chmod +x install.sh cyber_terrafor
./install.sh
./cyber_terrafor --help
```

Python 3 is required. The project currently uses the Python standard library; Nmap is optional and should be installed separately when Nmap functionality is required.

## 2. Installation — Termux
```bash
cd Cyber-Terrafor-Professional-v7.2
chmod +x install-termux.sh cyber_terrafor
./install-termux.sh
./cyber_terrafor --help
```

## 3. URL-first assessment
For a single authorized website:
```bash
./cyber_terrafor
```
Then choose an assessment module and provide the authorized URL.

## 4. Persistent scope
Create a scope file from `scope.txt.example`:
```text
example.com
*.example.com
192.168.1.0/24
```

Then:
```bash
./cyber_terrafor --scope scope.txt adaptive-analysis https://example.com
./cyber_terrafor --scope scope.txt deep-audit https://example.com
./cyber_terrafor --scope scope.txt module-health
```

## 5. Useful modules
```bash
./cyber_terrafor --scope scope.txt tech-fingerprint https://example.com
./cyber_terrafor --scope scope.txt headers https://example.com
./cyber_terrafor --scope scope.txt tls example.com
./cyber_terrafor --scope scope.txt dns example.com
./cyber_terrafor --scope scope.txt api-audit https://example.com
./cyber_terrafor --scope scope.txt cookie-audit https://example.com
./cyber_terrafor --scope scope.txt cors-audit https://example.com
./cyber_terrafor --scope scope.txt adaptive-analysis https://example.com
./cyber_terrafor --scope scope.txt deep-audit https://example.com
```

## 6. Reports
Generated reports are stored under:
```text
reports/
```

Use:
```bash
./cyber_terrafor reports-list
./cyber_terrafor html-report
./cyber_terrafor article-summary --target https://example.com
```

## 7. Recommended enterprise workflow
1. Obtain written authorization.
2. Define in-scope assets and exclusions.
3. Validate scope with `scope-check`.
4. Start with low-impact discovery/adaptive analysis.
5. Review evidence and confidence.
6. Verify important findings manually.
7. Run risk scoring.
8. Generate the report.
9. Retain evidence according to the customer's retention policy.
10. Deliver remediation priorities to the authorized stakeholder.
## Recommended launcher

From the project root, start Cyber Terrafor with:

```bash
chmod +x cyber-terrafor
./cyber-terrafor
```

Running `python3 cyber-terrafor.py` from the project root is not supported because the main Python entry point is under `src/cyber_terrafor.py`.

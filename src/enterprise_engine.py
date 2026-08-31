"""Cyber Terrafor Enterprise Security Engine.

Defensive, evidence-first extensions for authorized assessments.  The module
avoids exploitation and destructive actions; it focuses on posture, exposure,
configuration, evidence integrity, and control mapping.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

VERSION = "11.0.0-enterprise"


def _stamp():
    return datetime.now(timezone.utc).isoformat()


def _finding(finding_fn, severity, title, evidence, remediation, module,
             confidence="high", verification="OBSERVED", location=None, impact=None,
             references=None, control_tags=None):
    f = finding_fn(severity, title, evidence, remediation, module, confidence,
                   verification, location, impact)
    if references:
        f["references"] = references
    if control_tags:
        f["control_tags"] = control_tags
    return f


def tls_posture(host, port, scope, finding_fn):
    """Collect certificate metadata even when trust validation fails.

    Strict verification is always attempted first.  If it fails, the fallback
    context is used only for metadata collection and the report explicitly
    records that the chain was not trusted.
    """
    result = {
        "host": host, "port": port, "verification": "NOT_RUN",
        "certificate": {}, "protocols": {}, "errors": [], "findings": []
    }
    raw_cert = None
    strict_error = None

    try:
        with socket.create_connection((host, port), timeout=8) as raw:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                result["verification"] = "VALIDATED"
                result["tls_version"] = s.version()
                result["cipher"] = s.cipher()
                raw_cert = s.getpeercert(binary_form=True)
                cert = s.getpeercert()
                result["certificate"] = _cert_meta(cert, raw_cert)
    except Exception as exc:
        strict_error = str(exc)
        result["verification"] = "FAILED"
        result["errors"].append({"stage": "strict_verification", "error": strict_error})

    if raw_cert is None:
        try:
            with socket.create_connection((host, port), timeout=8) as raw:
                ctx = ssl._create_unverified_context()
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    raw_cert = s.getpeercert(binary_form=True)
                    cert = s.getpeercert()
                    result["tls_version"] = s.version()
                    result["cipher"] = s.cipher()
                    result["certificate"] = _cert_meta(cert, raw_cert)
                    result["fallback_metadata_collection"] = True
        except Exception as exc:
            result["errors"].append({"stage": "metadata_fallback", "error": str(exc)})

    if strict_error:
        result["findings"].append(_finding(
            finding_fn, "low", "TLS certificate trust validation failed",
            strict_error,
            "Verify the complete server certificate chain and the scanner trust store. "
            "Do not treat this observation alone as proof of a vulnerable TLS service.",
            "TLS / Certificate Intelligence", "high", "OBSERVED", None, None,
            ["CWE-295"], ["NIST-CSF:PR.DS-2", "CIS-4:4.8"]
        ))

    cert = result.get("certificate", {})
    days = cert.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            result["findings"].append(_finding(
                finding_fn, "high", "TLS certificate expired", str(cert.get("not_after")),
                "Renew and deploy a currently valid certificate.",
                "TLS / Certificate Intelligence", "high", "OBSERVED", None, None,
                ["CWE-298"], ["NIST-CSF:PR.DS-2"]
            ))
        elif days < 30:
            result["findings"].append(_finding(
                finding_fn, "medium", "TLS certificate expires soon", f"{days} days remaining",
                "Schedule certificate renewal before expiry.",
                "TLS / Certificate Intelligence", "high", "OBSERVED", None, None,
                ["NIST-CSF:PR.DS-2"], ["CIS-4:4.8"]
            ))

    # Safe protocol probes.  No downgrade is accepted as a successful posture.
    for label, version in (("TLSv1.0", getattr(ssl, "TLSVersion", object()).TLSv1 if hasattr(ssl, "TLSVersion") else None),
                           ("TLSv1.1", getattr(ssl, "TLSVersion", object()).TLSv1_1 if hasattr(ssl, "TLSVersion") else None),
                           ("TLSv1.2", getattr(ssl, "TLSVersion", object()).TLSv1_2 if hasattr(ssl, "TLSVersion") else None),
                           ("TLSv1.3", getattr(ssl, "TLSVersion", object()).TLSv1_3 if hasattr(ssl, "TLSVersion") else None)):
        if version is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version
            with socket.create_connection((host, port), timeout=4) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    result["protocols"][label] = {"supported": True, "negotiated": s.version()}
        except Exception:
            result["protocols"][label] = {"supported": False}

    if result["protocols"].get("TLSv1.0", {}).get("supported") or result["protocols"].get("TLSv1.1", {}).get("supported"):
        result["findings"].append(_finding(
            finding_fn, "medium", "Legacy TLS protocol accepted",
            ", ".join(k for k,v in result["protocols"].items() if v.get("supported") and k in ("TLSv1.0", "TLSv1.1")),
            "Disable TLS 1.0 and TLS 1.1 and require modern protocol versions.",
            "TLS / Protocol Security", "high", "OBSERVED", None, None,
            ["CWE-326"], ["NIST-CSF:PR.DS-2", "CIS-4:4.8"]
        ))
    return result


def _cert_meta(cert, raw):
    out = {}
    if not cert and raw:
        out["fingerprint_sha256"] = hashlib.sha256(raw).hexdigest()
        # Python's unverified socket intentionally returns an empty parsed cert.
        # cryptography lets us inspect the DER certificate without trusting it.
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.x509.oid import NameOID
            obj = x509.load_der_x509_certificate(raw, default_backend())
            def name_map(name):
                result = {}
                for attr in name:
                    result.setdefault(attr.oid.dotted_string, []).append(attr.value)
                    if attr.oid == NameOID.COMMON_NAME:
                        result.setdefault("common_name", []).append(attr.value)
                return result
            out["subject"] = name_map(obj.subject)
            out["issuer"] = name_map(obj.issuer)
            try:
                san = obj.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                out["san"] = san.get_values_for_type(x509.DNSName)
            except Exception:
                out["san"] = []
            out["not_before"] = obj.not_valid_before_utc.isoformat() if hasattr(obj, "not_valid_before_utc") else obj.not_valid_before.isoformat()
            out["not_after"] = obj.not_valid_after_utc.isoformat() if hasattr(obj, "not_valid_after_utc") else obj.not_valid_after.isoformat()
            out["serial"] = format(obj.serial_number, "X")
            out["days_until_expiry"] = (obj.not_valid_after_utc - datetime.now(timezone.utc)).days if hasattr(obj, "not_valid_after_utc") else (obj.not_valid_after - datetime.utcnow()).days
        except Exception as exc:
            out["metadata_parse_error"] = str(exc)
        return out
    def flat(value):
        if isinstance(value, tuple):
            return {k: v for item in value for k, v in item}
        return value
    out["subject"] = flat(cert.get("subject"))
    out["issuer"] = flat(cert.get("issuer"))
    out["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    out["not_before"] = cert.get("notBefore")
    out["not_after"] = cert.get("notAfter")
    out["serial"] = cert.get("serialNumber")
    if raw:
        out["fingerprint_sha256"] = hashlib.sha256(raw).hexdigest()
    if cert.get("notAfter"):
        try:
            dt = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            out["days_until_expiry"] = (dt - datetime.utcnow()).days
        except Exception:
            pass
    return out


def web_posture(url, response, body, finding_fn):
    headers = {k.lower(): v for k, v in response.headers.items()}
    text = body.decode("utf-8", "replace")
    findings = []
    parsed = urllib.parse.urlparse(response.geturl())
    https = parsed.scheme == "https"

    if https and "strict-transport-security" not in headers:
        findings.append(_finding(finding_fn, "medium", "HSTS not advertised",
            "Strict-Transport-Security header is absent", "Deploy HSTS after validating HTTPS coverage.",
            "Web Security Posture", "high", "OBSERVED", None, None,
            ["CWE-319"], ["NIST-CSF:PR.DS-2", "CIS-4:4.8"]))

    csp = headers.get("content-security-policy", "")
    if not csp:
        findings.append(_finding(finding_fn, "low", "Content Security Policy not advertised",
            "Content-Security-Policy header is absent", "Define and enforce a CSP appropriate to the application.",
            "Web Security Posture", "high", "OBSERVED", None, None,
            ["CWE-693"], ["NIST-CSF:PR.PT-3", "CIS-4:4.1"]))
    elif "unsafe-inline" in csp.lower() or "unsafe-eval" in csp.lower():
        findings.append(_finding(finding_fn, "low", "CSP contains unsafe execution directives",
            csp[:1000], "Remove unsafe-inline/unsafe-eval where application architecture permits.",
            "Web Security Posture", "medium", "OBSERVED", "Content-Security-Policy", None,
            ["CWE-693"], ["NIST-CSF:PR.PT-3"]))

    if "server" in headers and re.search(r"\b(?:apache|nginx|iis|php|express|tomcat)[/ ]?[0-9.]*\b", headers["server"], re.I):
        findings.append(_finding(finding_fn, "low", "Server technology disclosure",
            headers["server"], "Minimize unnecessary version disclosure in response headers.",
            "Information Exposure", "high", "OBSERVED", "Server", None,
            ["CWE-200"], ["NIST-CSF:PR.DS-5"]))

    if https and re.search(r"(?:src|href)=[\"']http://", text, re.I):
        findings.append(_finding(finding_fn, "medium", "Mixed-content references detected",
            "HTTP resource references were found in an HTTPS document", "Load active resources over HTTPS and remove insecure dependencies.",
            "Web Security Posture", "high", "OBSERVED", None, None,
            ["CWE-319"], ["NIST-CSF:PR.DS-2"]))

    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", text, re.I | re.S)
    password_forms = [x for x in forms if re.search(r'type=[\"\']password', x, re.I)]
    if password_forms and not https:
        findings.append(_finding(finding_fn, "high", "Credential form served without HTTPS",
            f"{len(password_forms)} password form(s) observed over HTTP", "Serve credential collection only over HTTPS.",
            "Authentication Security", "high", "OBSERVED", None, None,
            ["CWE-319"], ["NIST-CSF:PR.DS-2"]))

    cache = headers.get("cache-control", "")
    if password_forms and not re.search(r"no-store", cache, re.I):
        findings.append(_finding(finding_fn, "low", "Authentication response lacks no-store cache directive",
            cache or "Cache-Control absent", "Use appropriate no-store directives for sensitive authenticated responses.",
            "Authentication Security", "medium", "OBSERVED", "Cache-Control", None,
            ["CWE-525"], ["NIST-CSF:PR.DS-5"]))

    return {
        "url": url, "final_url": response.geturl(), "status": response.status,
        "headers": headers, "content_length": len(body), "https": https,
        "password_forms": len(password_forms), "findings": findings
    }


def security_txt(url, fetch_fn, scope, finding_fn):
    base = urllib.parse.urlparse(url)
    u = urllib.parse.urlunparse((base.scheme, base.netloc, "/.well-known/security.txt", "", "", ""))
    result = {"url": u, "status": None, "fields": {}, "findings": []}
    try:
        r, body = fetch_fn(u, timeout=5, max_bytes=50000)
        text = body.decode("utf-8", "replace")
        result["status"] = r.status
        for line in text.splitlines():
            if ":" in line and not line.lstrip().startswith("#"):
                k, v = line.split(":", 1)
                result["fields"].setdefault(k.strip().lower(), []).append(v.strip())
        if r.status != 200:
            result["findings"].append(_finding(finding_fn, "info", "security.txt not published",
                f"HTTP {r.status} for {u}", "Consider publishing a valid security.txt contact policy.",
                "Security Governance", "high", "OBSERVED", u, None,
                ["RFC 9116"], ["NIST-CSF:ID.AM-2"]))
        elif not result["fields"].get("contact"):
            result["findings"].append(_finding(finding_fn, "low", "security.txt has no Contact field",
                text[:2000], "Publish a security contact in accordance with RFC 9116.",
                "Security Governance", "high", "OBSERVED", u, None,
                ["RFC 9116"], ["NIST-CSF:ID.RA-1"]))
    except Exception as exc:
        result["error"] = str(exc)
    return result


def compliance_map(findings):
    mapping = {
        "TLS / Certificate Intelligence": ["NIST CSF PR.DS-2", "CIS Control 4"],
        "TLS / Protocol Security": ["NIST CSF PR.DS-2", "CIS Control 4"],
        "Web Security Posture": ["NIST CSF PR.PT-3", "CIS Control 16"],
        "Authentication Security": ["NIST CSF PR.AC-1", "CIS Control 6"],
        "Information Exposure": ["NIST CSF PR.DS-5", "CIS Control 3"],
        "Security Governance": ["NIST CSF ID.RA-1", "ISO/IEC 27001 Annex A"],
        "API Security": ["OWASP API Security Top 10", "NIST CSF PR.AC-4"],
        "Cloud Security": ["CIS Controls", "NIST CSF PR.DS-2"],
    }
    rows = []
    for f in findings:
        module = f.get("module", "General")
        tags = f.get("control_tags") or mapping.get(module, [])
        rows.append({"finding": f.get("title"), "severity": f.get("severity"), "controls": tags})
    return rows


def evidence_manifest(report_paths, output_path):
    entries = []
    for path in report_paths:
        p = Path(path)
        if not p.is_file():
            continue
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        entries.append({"file": p.name, "sha256": h.hexdigest(), "size": p.stat().st_size})
    manifest = {"tool": "Cyber Terrafor", "engine": VERSION, "timestamp": _stamp(), "algorithm": "SHA-256", "artifacts": entries}
    Path(output_path).write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def executive_posture(target, reports, risk_fn):
    findings = []
    for d in reports:
        findings.extend(d.get("findings", []))
    score, level, meta = risk_fn(findings)
    counts = {s: sum(1 for f in findings if str(f.get("severity", "")).lower() == s) for s in ("critical", "high", "medium", "low", "info")}
    priorities = sorted(findings, key=lambda f: {"critical":5,"high":4,"medium":3,"low":2,"info":1}.get(str(f.get("severity")).lower(), 0), reverse=True)[:10]
    return {
        "target": target, "generated_at": _stamp(), "risk_score": score, "risk_level": level,
        "finding_counts": counts, "top_priorities": [{"severity":f.get("severity"), "title":f.get("title"), "remediation":f.get("remediation")} for f in priorities],
        "compliance_alignment": compliance_map(findings), "limitations": [
            "Automated observations require analyst validation before being treated as confirmed vulnerabilities.",
            "Compliance mappings indicate alignment opportunities; they do not constitute certification or compliance attestation."
        ],
        "evidence_model": "Observation → evidence → confidence → remediation → control mapping"
    }

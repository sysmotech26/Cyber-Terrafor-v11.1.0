#!/usr/bin/env python3
"""Cyber Terrafor Professional Enterprise Upgrade Engine.

Local, scope-aware enterprise capabilities built from the existing assessment
reports. No exploitation, credential attacks, persistence, or destructive
network actions are performed here.
"""
from __future__ import annotations
import base64, hashlib, json, os, re, socket, sqlite3, ssl, time, urllib.parse, urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

VERSION = "11.0.0"
ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / "state"
REPORTS = ROOT / "reports"
STATE.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
DB = STATE / "enterprise.db"
KEY_DIR = STATE / "evidence_keys"
KEY_DIR.mkdir(exist_ok=True)

SEVERITY = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.0}
CONFIDENCE = {"confirmed": 1.0, "high": .9, "medium": .7, "low": .45, "unknown": .3}

# A deliberately small offline catalog. Production deployments can import a
# current JSON feed using `vuln-feed-import`; the engine never pretends an
# offline catalog is complete.
VULN_CATALOG = [
    {"id":"CWE-319","name":"Cleartext Transmission of Sensitive Information","cvss_v4":8.7,"epss":0.25,"cwe":"CWE-319"},
    {"id":"CWE-295","name":"Improper Certificate Validation","cvss_v4":7.5,"epss":0.18,"cwe":"CWE-295"},
    {"id":"CWE-200","name":"Exposure of Sensitive Information to an Unauthorized Actor","cvss_v4":5.3,"epss":0.08,"cwe":"CWE-200"},
    {"id":"CWE-693","name":"Protection Mechanism Failure","cvss_v4":5.3,"epss":0.06,"cwe":"CWE-693"},
    {"id":"CWE-326","name":"Inadequate Encryption Strength","cvss_v4":6.5,"epss":0.11,"cwe":"CWE-326"},
    {"id":"CWE-525","name":"Use of Web Browser Cache Containing Sensitive Information","cvss_v4":4.3,"epss":0.03,"cwe":"CWE-525"},
]

ROLE_PERMISSIONS = {
    "super_admin":{"*"},
    "security_admin":{"assets:read","assets:write","findings:read","findings:write","scans:run","reports:read","reports:write","evidence:seal","compliance:read","compliance:write"},
    "analyst":{"assets:read","findings:read","findings:write","scans:run","reports:read","evidence:seal","compliance:read"},
    "auditor":{"assets:read","findings:read","reports:read","evidence:read","compliance:read"},
    "viewer":{"assets:read","findings:read","reports:read"},
}

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("Private Key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic Secret Assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|token|password|passwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("Bearer Token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}")),
]


def stamp(): return datetime.now(timezone.utc).isoformat()

def _json(path, default):
    try: return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception: return default

def init_db():
    con=sqlite3.connect(DB); con.executescript('''
    CREATE TABLE IF NOT EXISTS assets(id TEXT PRIMARY KEY, target TEXT, kind TEXT, hostname TEXT, ip TEXT, criticality INTEGER DEFAULT 50, first_seen TEXT, last_seen TEXT, metadata TEXT);
    CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, asset_id TEXT, title TEXT, severity TEXT, confidence TEXT, cve TEXT, cwe TEXT, cvss4 REAL, epss REAL, exposure REAL, business_impact REAL, status TEXT DEFAULT 'open', remediation TEXT, first_seen TEXT, last_seen TEXT, metadata TEXT);
    CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, role TEXT, enabled INTEGER DEFAULT 1, created_at TEXT);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, actor TEXT, action TEXT, object_id TEXT, details TEXT);
    CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, target TEXT, module TEXT, schedule TEXT, enabled INTEGER DEFAULT 1, last_run TEXT, next_run TEXT, metadata TEXT);
    '''); con.commit(); con.close()
init_db()


def audit(actor, action, object_id="", details=None):
    con=sqlite3.connect(DB); con.execute("INSERT INTO audit(timestamp,actor,action,object_id,details) VALUES(?,?,?,?,?)",(stamp(),actor,action,object_id,json.dumps(details or {},ensure_ascii=False))); con.commit(); con.close()


def upsert_asset(target, kind="web", criticality=50, metadata=None):
    target=str(target).strip(); p=urllib.parse.urlparse(target if "://" in target else "//"+target)
    host=p.hostname or target; ip=""
    try: ip=socket.gethostbyname(host)
    except Exception: pass
    aid=hashlib.sha256(f"{kind}|{host}|{ip}".encode()).hexdigest()[:24]; now=stamp()
    con=sqlite3.connect(DB); con.execute("""INSERT INTO assets(id,target,kind,hostname,ip,criticality,first_seen,last_seen,metadata) VALUES(?,?,?,?,?,?,?,?,?)
    ON CONFLICT(id) DO UPDATE SET target=excluded.target,ip=excluded.ip,criticality=excluded.criticality,last_seen=excluded.last_seen,metadata=excluded.metadata""",(aid,target,kind,host,ip,int(criticality),now,now,json.dumps(metadata or {},ensure_ascii=False))); con.commit(); con.close(); audit("system","asset_upsert",aid,{"target":target}); return aid


def asset_inventory(target=None, criticality=50):
    rows=[]
    if target:
        aid=upsert_asset(target, "web", criticality)
        rows.append({"id":aid,"target":target})
        # Safe DNS aliases commonly exposed by web estates; only resolution is performed.
        base=urllib.parse.urlparse(target if "://" in target else "//"+target).hostname
        if base:
            for prefix in ("www","api","app","dev","staging","mail"):
                h=f"{prefix}.{base}"
                try:
                    ip=socket.gethostbyname(h); rows.append({"id":upsert_asset(h,"dns",criticality-5,{"source":"safe_dns_discovery"}),"target":h,"ip":ip})
                except Exception: pass
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row; dbrows=[dict(x) for x in con.execute("SELECT * FROM assets ORDER BY criticality DESC,last_seen DESC")]; con.close()
    out={"engine":"Enterprise Asset Inventory 1.0","timestamp":stamp(),"target":target,"asset_count":len(dbrows),"assets":dbrows}
    return out


def import_vuln_feed(path):
    data=_json(path, None)
    if not isinstance(data,list):
        data=data.get("vulnerabilities",[]) if isinstance(data,dict) else []
    valid=[]
    for x in data:
        if not isinstance(x,dict): continue
        vid=str(x.get("id") or x.get("cve") or x.get("cwe") or "").strip()
        if not vid: continue
        valid.append({"id":vid,"name":x.get("name",vid),"cvss_v4":float(x.get("cvss_v4",x.get("cvss",0)) or 0),"epss":float(x.get("epss",0) or 0),"cwe":x.get("cwe")})
    out=STATE/"vulnerability_catalog.json"; out.write_text(json.dumps(valid,indent=2),encoding="utf-8"); audit("system","vulnerability_feed_import",str(out),{"count":len(valid)}); return {"imported":len(valid),"path":str(out)}


def catalog():
    p=STATE/"vulnerability_catalog.json"; return _json(p,VULN_CATALOG)


def _catalog_for(f):
    refs=[]
    refs += [str(x).upper() for x in f.get("references",[]) or []]
    refs += [str(x).upper() for x in f.get("control_tags",[]) or []]
    refs += [str(f.get("cwe","")).upper(),str(f.get("cve","")).upper()]
    title=str(f.get("title","")).lower()
    for x in catalog():
        if str(x.get("id","")).upper() in refs or str(x.get("cwe","")).upper() in refs: return x
        if str(x.get("name","")).lower() in title: return x
    return None


def enterprise_risk(findings, asset_criticality=50, internet_exposed=True, business_impact=50):
    scored=[]; total=0.0
    for f in findings or []:
        sev=str(f.get("severity","info")).lower(); conf=str(f.get("confidence","medium")).lower()
        c=_catalog_for(f) or {}
        cvss=float(c.get("cvss_v4", f.get("cvss_v4", 0)) or 0)
        epss=float(c.get("epss", f.get("epss", 0)) or 0)
        exposure=1.0 if internet_exposed else .55
        asset_factor=.5+max(0,min(100,int(asset_criticality)))/200
        impact_factor=.5+max(0,min(100,int(business_impact)))/200
        base=SEVERITY.get(sev,0) or min(10,cvss)
        value=(base*.45 + cvss*.35 + epss*10*.20)*CONFIDENCE.get(conf,.5)*exposure*asset_factor*impact_factor
        total += value
        scored.append({"title":f.get("title","Unnamed"),"severity":sev,"confidence":conf,"cve":c.get("id") if str(c.get("id","")).upper().startswith("CVE-") else f.get("cve"),"cwe":c.get("cwe") or f.get("cwe"),"cvss_v4":cvss,"epss":epss,"contribution":round(value,3),"remediation":f.get("remediation")})
    score=round(min(100,total*2.5),2)
    level="CRITICAL" if score>=85 else "HIGH" if score>=65 else "MEDIUM" if score>=35 else "LOW" if score>0 else "INFO"
    return {"score":score,"level":level,"method":"CVSS v4 + EPSS + severity + confidence + exposure + asset criticality + business impact","contributions":sorted(scored,key=lambda x:x["contribution"],reverse=True)}


def correlate_findings(findings, target=None, criticality=50):
    aid=upsert_asset(target or "unknown", "assessment", criticality) if target else None
    rows=[]; now=stamp()
    con=sqlite3.connect(DB)
    for f in findings or []:
        c=_catalog_for(f) or {}; fid=hashlib.sha256(json.dumps(f,sort_keys=True,default=str).encode()).hexdigest()[:32]
        row=(fid,aid,f.get("title","Unnamed"),str(f.get("severity","info")),str(f.get("confidence","medium")),f.get("cve") or (c.get("id") if str(c.get("id","")).upper().startswith("CVE-") else None),f.get("cwe") or c.get("cwe"),float(f.get("cvss_v4",c.get("cvss_v4",0)) or 0),float(f.get("epss",c.get("epss",0)) or 0),1.0,50.0,"open",f.get("remediation"),now,now,json.dumps(f,ensure_ascii=False))
        con.execute("""INSERT INTO findings(id,asset_id,title,severity,confidence,cve,cwe,cvss4,epss,exposure,business_impact,status,remediation,first_seen,last_seen,metadata) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen,status=excluded.status,metadata=excluded.metadata""",row); rows.append({"id":fid,"title":f.get("title"),"cve":row[5],"cwe":row[6]})
    con.commit(); con.close(); return rows


def scan_secrets(root, max_bytes=2_000_000):
    root=Path(root).expanduser().resolve(); files=[root] if root.is_file() else [p for p in root.rglob("*") if p.is_file() and p.stat().st_size<=max_bytes]
    findings=[]
    ignored={".git","node_modules","__pycache__",".venv","venv"}
    for p in files:
        if any(part in ignored for part in p.parts): continue
        try: text=p.read_text(errors="ignore")
        except Exception: continue
        for name,pat in SECRET_PATTERNS:
            for m in pat.finditer(text):
                line=text.count("\n",0,m.start())+1; digest=hashlib.sha256(m.group(0).encode()).hexdigest()[:16]
                findings.append({"type":name,"file":str(p),"line":line,"fingerprint":digest,"severity":"high","remediation":"Revoke/rotate the exposed secret, remove it from source, and use a managed secret store."})
    return {"engine":"Cyber Terrafor Secret Detection 1.0","timestamp":stamp(),"root":str(root),"count":len(findings),"findings":findings}


def container_audit(root):
    root=Path(root).expanduser().resolve(); findings=[]
    candidates=list(root.rglob("Dockerfile"))+list(root.rglob("docker-compose.yml"))+list(root.rglob("docker-compose.yaml"))
    for p in candidates[:200]:
        try: text=p.read_text(errors="ignore")
        except Exception: continue
        if re.search(r"(?mi)^\s*USER\s+root\s*$",text): findings.append({"file":str(p),"severity":"medium","title":"Container runs as root","remediation":"Use a dedicated non-root runtime user where supported."})
        if re.search(r"(?mi)^\s*(?:ENV|ARG)\s+[^\n]*(?:PASSWORD|TOKEN|SECRET|API_KEY)\s*=",text): findings.append({"file":str(p),"severity":"high","title":"Potential secret in container build configuration","remediation":"Move secrets to a runtime secret manager; never bake credentials into images."})
        if re.search(r"(?mi)^\s*FROM\s+[^:@\s]+\s*$",text): findings.append({"file":str(p),"severity":"low","title":"Unpinned container base image","remediation":"Pin a trusted base image by immutable digest and maintain a patch process."})
    return {"engine":"Cyber Terrafor Container Security 1.0","timestamp":stamp(),"root":str(root),"files_checked":len(candidates),"findings":findings}


def compliance_matrix(findings):
    rows=[]
    for f in findings or []:
        title=str(f.get("title","")).lower(); tags=[]
        if "tls" in title or "https" in title or "certificate" in title or "cleartext" in title: tags += ["NIST-CSF:PR.DS","CIS:4","ISO27001:A.8.24","PCI-DSS:4"]
        if "cookie" in title or "cache" in title or "information" in title: tags += ["NIST-CSF:PR.DS","ISO27001:A.8.12","OWASP:ASVS"]
        if "api" in title or "authentication" in title: tags += ["NIST-CSF:PR.AA","OWASP:API","ISO27001:A.5.15"]
        if "secret" in title or "credential" in title: tags += ["CIS:3","NIST-CSF:PR.AA","ISO27001:A.5.17"]
        if not tags: tags=["NIST-CSF:ID.RA","ISO27001:A.8"]
        rows.append({"finding":f.get("title"),"severity":f.get("severity"),"controls":sorted(set(tags))})
    return rows


def evidence_seal(paths, output=None):
    artifacts=[]
    for raw in paths:
        p=Path(raw).expanduser().resolve()
        if not p.exists() or not p.is_file(): continue
        b=p.read_bytes(); artifacts.append({"path":str(p),"size":len(b),"sha256":hashlib.sha256(b).hexdigest(),"timestamp":stamp()})
    manifest={"engine":"Cyber Terrafor Evidence Integrity Engine 2.0","version":VERSION,"created_at":stamp(),"artifacts":artifacts}
    # Prefer Ed25519 when cryptography is installed. The private key remains local.
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        keyfile=KEY_DIR/"ed25519_private.key"
        if keyfile.exists(): key=Ed25519PrivateKey.from_private_bytes(keyfile.read_bytes())
        else:
            key=Ed25519PrivateKey.generate(); keyfile.write_bytes(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())); os.chmod(keyfile,0o600)
        payload=json.dumps(manifest,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); sig=key.sign(payload)
        manifest["signature"]={"algorithm":"Ed25519","public_key_b64":base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)).decode(),"signature_b64":base64.b64encode(sig).decode()}
    except Exception as e:
        manifest["signature"]={"algorithm":"SHA256-MANIFEST","note":f"Ed25519 unavailable: {e}"}
    out=Path(output) if output else REPORTS/(datetime.now().strftime("%Y%m%d_%H%M%S")+"_evidence_seal.json"); out.write_text(json.dumps(manifest,indent=2,ensure_ascii=False),encoding="utf-8"); audit("system","evidence_sealed",str(out),{"artifacts":len(artifacts)}); return manifest


def create_job(target,module,schedule):
    jid=hashlib.sha256(f"{target}|{module}|{schedule}".encode()).hexdigest()[:24]; now=stamp(); con=sqlite3.connect(DB); con.execute("INSERT OR REPLACE INTO jobs(id,target,module,schedule,enabled,last_run,next_run,metadata) VALUES(?,?,?,?,?,?,?,?)",(jid,target,module,schedule,1,None,now,json.dumps({}))); con.commit(); con.close(); audit("system","job_created",jid,{"target":target,"module":module,"schedule":schedule}); return {"id":jid,"target":target,"module":module,"schedule":schedule,"enabled":True}


def dashboard():
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row
    assets=[dict(x) for x in con.execute("SELECT * FROM assets ORDER BY criticality DESC,last_seen DESC")]
    findings=[dict(x) for x in con.execute("SELECT * FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,last_seen DESC")]
    jobs=[dict(x) for x in con.execute("SELECT * FROM jobs WHERE enabled=1")]; con.close()
    return {"engine":"Cyber Terrafor Enterprise Security Center","version":VERSION,"timestamp":stamp(),"assets":{"total":len(assets),"critical":sum(x["criticality"]>=80 for x in assets)},"findings":{"total":len(findings),"critical":sum(x["severity"]=="critical" for x in findings),"high":sum(x["severity"]=="high" for x in findings),"medium":sum(x["severity"]=="medium" for x in findings)},"scheduled_jobs":len(jobs)}

#!/usr/bin/env python3
"""Cyber Terrafor Enterprise Platform Engine 11.1.
Defensive, authorized, scope-aware exposure-management primitives.
No exploitation, credential attacks, persistence, or destructive actions.
"""
from __future__ import annotations
import hashlib, json, re, socket, sqlite3, ssl, urllib.parse, urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]; STATE=ROOT/'state'; REPORTS=ROOT/'reports'; STATE.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True)
DB=STATE/'enterprise.db'; VERSION='11.1.0'


def now(): return datetime.now(timezone.utc)
def stamp(): return now().isoformat()
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c

def migrate():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS vulnerabilities(id TEXT PRIMARY KEY, name TEXT, cvss4 REAL DEFAULT 0, epss REAL DEFAULT 0, cwe TEXT, source TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS remediation(id TEXT PRIMARY KEY, finding_id TEXT, owner TEXT, priority TEXT, due_at TEXT, status TEXT DEFAULT 'open', notes TEXT, created_at TEXT, updated_at TEXT);
    CREATE TABLE IF NOT EXISTS verification(id TEXT PRIMARY KEY, finding_id TEXT, status TEXT, verified_at TEXT, evidence_hash TEXT, notes TEXT);
    CREATE TABLE IF NOT EXISTS asm_snapshots(id TEXT PRIMARY KEY, target TEXT, observed_at TEXT, fingerprint TEXT, assets_json TEXT, changes_json TEXT);
    CREATE TABLE IF NOT EXISTS threat_intel(ioc TEXT PRIMARY KEY, ioc_type TEXT, verdict TEXT, source TEXT, confidence REAL DEFAULT 0, first_seen TEXT, last_seen TEXT, metadata TEXT);
    CREATE TABLE IF NOT EXISTS compliance_controls(framework TEXT, control_id TEXT, title TEXT, description TEXT, PRIMARY KEY(framework,control_id));
    '''); c.commit(); c.close()
migrate()


def import_vulnerabilities(path):
    data=json.loads(Path(path).read_text(encoding='utf-8')); data=data.get('vulnerabilities',data) if isinstance(data,dict) else data
    count=0; c=db()
    for x in data:
        if not isinstance(x,dict): continue
        vid=str(x.get('id') or x.get('cve') or x.get('cwe') or '').strip().upper()
        if not vid: continue
        cv=float(x.get('cvss_v4',x.get('cvss',0)) or 0); ep=float(x.get('epss',0) or 0)
        c.execute('INSERT OR REPLACE INTO vulnerabilities VALUES(?,?,?,?,?,?,?)',(vid,x.get('name',vid),cv,ep,x.get('cwe'),x.get('source','import'),stamp())); count+=1
    c.commit(); c.close(); return {'imported':count,'database':str(DB),'version':VERSION}


def vulnerability_lookup(ref):
    r=str(ref).upper().strip(); c=db(); row=c.execute('SELECT * FROM vulnerabilities WHERE id=?',(r,)).fetchone(); c.close()
    return dict(row) if row else None


def create_remediation(finding_id, owner='unassigned', priority='high', due_days=14, notes=''):
    rid=hashlib.sha256(f'{finding_id}|{owner}|{stamp()}'.encode()).hexdigest()[:24]; due=(now()+timedelta(days=max(0,due_days))).isoformat(); c=db()
    c.execute('INSERT INTO remediation VALUES(?,?,?,?,?,?,?,?,?)',(rid,finding_id,owner,priority,due,'open',notes,stamp(),stamp())); c.commit(); c.close(); return {'id':rid,'finding_id':finding_id,'owner':owner,'priority':priority,'due_at':due,'status':'open'}


def update_remediation(remediation_id,status,notes=''):
    allowed={'open','in_progress','blocked','resolved','accepted','false_positive'}
    if status not in allowed: raise ValueError('Invalid remediation status')
    c=db(); c.execute('UPDATE remediation SET status=?,notes=?,updated_at=? WHERE id=?',(status,notes,stamp(),remediation_id)); c.commit(); c.close(); return {'id':remediation_id,'status':status}


def verify_finding(finding_id, status='verified', evidence_path=None, notes=''):
    if status not in {'verified','still_open','inconclusive'}: raise ValueError('Invalid verification status')
    h=''
    if evidence_path:
        p=Path(evidence_path).expanduser().resolve(); h=hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ''
    vid=hashlib.sha256(f'{finding_id}|{stamp()}'.encode()).hexdigest()[:24]; c=db(); c.execute('INSERT INTO verification VALUES(?,?,?,?,?,?)',(vid,finding_id,status,stamp(),h,notes));
    if status=='verified': c.execute("UPDATE remediation SET status='resolved',updated_at=? WHERE finding_id=? AND status IN ('open','in_progress')",(stamp(),finding_id))
    c.commit(); c.close(); return {'id':vid,'finding_id':finding_id,'status':status,'evidence_hash':h}


def remediation_queue():
    c=db(); rows=[dict(r) for r in c.execute("SELECT * FROM remediation WHERE status NOT IN ('resolved','false_positive') ORDER BY CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,due_at")]; c.close(); return rows


def _resolve(host):
    try: return sorted(set(socket.gethostbyname_ex(host)[2]))
    except Exception: return []


def attack_surface_snapshot(target, prefixes=None):
    p=urllib.parse.urlparse(target if '://' in target else '//'+target); host=p.hostname or target; prefixes=prefixes or ['www','api','app','dev','staging','portal','vpn','mail','auth','cdn']
    assets=[{'hostname':host,'ips':_resolve(host),'source':'seed'}]
    for pre in prefixes:
        h=f'{pre}.{host}'
        ips=_resolve(h)
        if ips: assets.append({'hostname':h,'ips':ips,'source':'safe_dns_discovery'})
    fp=hashlib.sha256(json.dumps(assets,sort_keys=True).encode()).hexdigest(); c=db(); prev=c.execute('SELECT * FROM asm_snapshots WHERE target=? ORDER BY observed_at DESC LIMIT 1',(target,)).fetchone()
    old=json.loads(prev['assets_json']) if prev else []; oldset={x['hostname'] for x in old}; newset={x['hostname'] for x in assets}; changes={'added':sorted(newset-oldset),'removed':sorted(oldset-newset),'count_delta':len(assets)-len(old)}
    sid=hashlib.sha256(f'{target}|{stamp()}'.encode()).hexdigest()[:24]; c.execute('INSERT INTO asm_snapshots VALUES(?,?,?,?,?,?)',(sid,target,stamp(),fp,json.dumps(assets),json.dumps(changes))); c.commit(); c.close()
    return {'engine':'Cyber Terrafor Continuous Attack Surface Management','version':VERSION,'target':target,'observed_at':stamp(),'asset_count':len(assets),'assets':assets,'changes':changes,'fingerprint':fp}


def continuous_check(target):
    return attack_surface_snapshot(target)


def cloud_config_audit(path):
    """Audit a supplied cloud inventory/config export; never calls provider APIs or changes cloud state."""
    data=json.loads(Path(path).read_text(encoding='utf-8')); findings=[]
    text=json.dumps(data,ensure_ascii=False).lower()
    rules=[('public storage','high',r'"public"\s*:\s*true'),('logging disabled','high',r'"logging"\s*:\s*false'),('unencrypted resource','high',r'"encrypted"\s*:\s*false'),('wildcard principal','high',r'"principal"\s*:\s*"\*"'),('open security group','high',r'0\.0\.0\.0/0')]
    for title,severity,pat in rules:
        if re.search(pat,text): findings.append({'title':title,'severity':severity,'remediation':'Restrict exposure, enable security controls, and apply least privilege.'})
    return {'engine':'Cyber Terrafor Cloud Posture Audit 1.0','mode':'offline-export','provider':data.get('provider'),'findings':findings,'timestamp':stamp()}


def threat_intel_import(path):
    data=json.loads(Path(path).read_text(encoding='utf-8')); data=data.get('indicators',data) if isinstance(data,dict) else data; c=db(); n=0
    for x in data:
        if isinstance(x,str): x={'ioc':x}
        if not isinstance(x,dict) or not x.get('ioc'): continue
        i=str(x['ioc']).strip(); c.execute('INSERT OR REPLACE INTO threat_intel VALUES(?,?,?,?,?,?,?,?)',(i,x.get('type','unknown'),x.get('verdict','unknown'),x.get('source','import'),float(x.get('confidence',0) or 0),x.get('first_seen',stamp()),stamp(),json.dumps(x))); n+=1
    c.commit(); c.close(); return {'imported':n,'database':str(DB)}


def threat_intel_lookup(ioc):
    c=db(); r=c.execute('SELECT * FROM threat_intel WHERE ioc=?',(ioc.strip(),)).fetchone(); c.close(); return dict(r) if r else {'ioc':ioc,'verdict':'unknown'}


def enterprise_dashboard():
    c=db(); counts={}
    for table in ('assets','findings','remediation','verification','asm_snapshots','threat_intel','vulnerabilities'):
        try: counts[table]=c.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0]
        except sqlite3.Error: counts[table]=0
    due=c.execute("SELECT COUNT(*) FROM remediation WHERE status NOT IN ('resolved','false_positive') AND due_at < ?",(stamp(),)).fetchone()[0]
    c.close(); return {'engine':'Cyber Terrafor Enterprise Security Center','version':VERSION,'timestamp':stamp(),'counts':counts,'overdue_remediations':due,'pillars':['ASM','Vulnerability Management','Risk Intelligence','Evidence','Compliance','Defensive Monitoring']}

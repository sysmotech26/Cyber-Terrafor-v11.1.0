#!/usr/bin/env python3
"""Minimal SaaS control-plane API layer.

This additive service intentionally lives outside the legacy Cyber Terrafor engine.
It provides tenant/subscription/feature/lead/isolation primitives using SQLite.
Production deployments should put it behind TLS, SSO/MFA, a reverse proxy and a
proper secrets manager.
"""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import json,sqlite3,secrets,time,os
BASE=Path(__file__).resolve().parents[2]; DB=BASE/'saas'/'data'/'saas.db'; DB.parent.mkdir(parents=True,exist_ok=True)

def db():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
 c.executescript('''CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT NOT NULL,plan TEXT NOT NULL,status TEXT NOT NULL,namespace TEXT UNIQUE NOT NULL,created_at REAL NOT NULL);CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL,plan TEXT NOT NULL,status TEXT NOT NULL,requested_at REAL NOT NULL,FOREIGN KEY(tenant_id) REFERENCES tenants(id));CREATE TABLE IF NOT EXISTS features(key TEXT PRIMARY KEY,label TEXT NOT NULL,enabled INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS leads(id TEXT PRIMARY KEY,company TEXT NOT NULL,email TEXT,source TEXT,intent TEXT,score INTEGER DEFAULT 0,created_at REAL NOT NULL);CREATE TABLE IF NOT EXISTS isolation(tenant_id TEXT PRIMARY KEY,isolation_key TEXT NOT NULL,storage_namespace TEXT NOT NULL,audit_scope TEXT NOT NULL,FOREIGN KEY(tenant_id) REFERENCES tenants(id));''')
 for k,l,e in [('asset_discovery','Asset Discovery',1),('exposure_assessment','Exposure Assessment',1),('risk_intelligence','Risk Intelligence',1),('defensive_engine','Defensive Engine',1),('deep_web_pentest','Deep Web Pentest',0),('enterprise_reports','Enterprise Reports',1),('infrastructure_vault','Infrastructure Vault',1),('community','Community',0)]: c.execute('INSERT OR IGNORE INTO features VALUES(?,?,?)',(k,l,e))
 c.commit(); return c

def out(h,code,payload):
 raw=json.dumps(payload).encode(); h.send_response(code); h.send_header('Content-Type','application/json'); h.send_header('Content-Length',str(len(raw))); h.end_headers(); h.wfile.write(raw)
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  c=db(); p=self.path.split('?')[0]
  if p=='/api/health': return out(self,200,{'ok':True,'service':'cyber-terrafor-saas'})
  if p=='/api/features': return out(self,200,{'features':[dict(x) for x in c.execute('SELECT * FROM features ORDER BY label') ]})
  if p=='/api/tenants': return out(self,200,{'tenants':[dict(x) for x in c.execute('SELECT * FROM tenants ORDER BY created_at DESC') ]})
  if p=='/api/subscriptions': return out(self,200,{'subscriptions':[dict(x) for x in c.execute('SELECT * FROM subscriptions ORDER BY requested_at DESC') ]})
  if p=='/api/leads': return out(self,200,{'leads':[dict(x) for x in c.execute('SELECT * FROM leads ORDER BY created_at DESC') ]})
  return out(self,404,{'error':'not_found'})
 def do_POST(self):
  c=db(); p=self.path; n=int(self.headers.get('Content-Length','0') or 0); data=json.loads(self.rfile.read(n) or b'{}')
  if p=='/api/subscriptions':
   tid=secrets.token_hex(8); name=data.get('company','Unnamed'); plan=data.get('plan','Starter'); ns=(data.get('slug') or name.lower().replace(' ','-'))+'-'+secrets.token_hex(3); now=time.time(); c.execute('INSERT INTO tenants VALUES(?,?,?,?,?,?)',(tid,name,plan,'Pending',ns,now)); sid=secrets.token_hex(8); c.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?)',(sid,tid,plan,'Pending',now)); c.commit(); return out(self,201,{'subscription_id':sid,'tenant_id':tid,'status':'Pending'})
  if p=='/api/subscriptions/approve':
   sid=data.get('subscription_id'); row=c.execute('SELECT tenant_id FROM subscriptions WHERE id=?',(sid,)).fetchone()
   if not row:return out(self,404,{'error':'subscription_not_found'})
   c.execute('UPDATE subscriptions SET status="Approved" WHERE id=?',(sid,)); c.execute('UPDATE tenants SET status="Active" WHERE id=?',(row['tenant_id'],)); c.execute('INSERT OR REPLACE INTO isolation VALUES(?,?,?,?)',(row['tenant_id'],secrets.token_urlsafe(32),'tenant-'+row['tenant_id'],'tenant')); c.commit(); return out(self,200,{'status':'Approved','tenant_id':row['tenant_id']})
  if p=='/api/subscriptions/reject':
   sid=data.get('subscription_id'); c.execute('UPDATE subscriptions SET status="Rejected" WHERE id=?',(sid,)); c.commit(); return out(self,200,{'status':'Rejected'})
  if p=='/api/features/toggle':
   key=data.get('key'); enabled=1 if data.get('enabled') else 0; c.execute('UPDATE features SET enabled=? WHERE key=?',(enabled,key)); c.commit(); return out(self,200,{'key':key,'enabled':bool(enabled)})
  if p=='/api/leads':
   lid=secrets.token_hex(8); c.execute('INSERT INTO leads VALUES(?,?,?,?,?,?,?)',(lid,data.get('company',''),data.get('email'),data.get('source','website'),data.get('intent','unknown'),int(data.get('score',0)),time.time())); c.commit(); return out(self,201,{'id':lid})
  return out(self,404,{'error':'not_found'})
 def log_message(self,*args): pass
if __name__=='__main__': ThreadingHTTPServer((os.getenv('SAAS_HOST','127.0.0.1'),int(os.getenv('SAAS_PORT','8787'))),H).serve_forever()

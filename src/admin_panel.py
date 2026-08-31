#!/usr/bin/env python3
"""Cyber Terrafor Professional v7.2 local control plane.

Designed for authorized site/infrastructure administration. It stores secrets
encrypted at rest, never renders them back to the browser, and exposes a small
authenticated connector API for heartbeat/status/events. It intentionally does
not provide arbitrary remote command execution.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from pathlib import Path
import hashlib, hmac, html, json, secrets, time, urllib.parse, sys, ipaddress, socket, mimetypes, base64, struct, re
from infrastructure_vault import Vault, VaultError
from infrastructure_adapters import CloudflareDNSAdapter, CPanelHostingAdapter, LocalBackupAdapter, AdapterError

VERSION='11.1.0'; DEFAULT_USERNAME='admin'; BASE=Path(__file__).resolve().parents[1]; STATE=BASE/'state'; REPORTS=BASE/'reports'; CONFIG=STATE/'admin.json'; AUDIT=STATE/'audit.log'
SESSIONS={}; LOGIN_ATTEMPTS={}; STATE.mkdir(exist_ok=True); REPORTS.mkdir(exist_ok=True); ASSETS=BASE/'assets'; ASSETS.mkdir(exist_ok=True)
MAX_FAILED=5; LOCK_SECONDS=900; SESSION_SECONDS=3600; MFA_PENDING_SECONDS=300
ROLES={'super_admin':{'*'},'security_admin':{'dashboard','assessments','files','sites','vault','reports','audit','security'},'analyst':{'dashboard','assessments','files','reports'},'auditor':{'dashboard','reports','audit'},'viewer':{'dashboard','reports'}}
API_SCOPES={'status','heartbeat','event'}

def hashpw(p,s=None):
    s=s or secrets.token_hex(16); return s,hashlib.pbkdf2_hmac('sha256',p.encode(),bytes.fromhex(s),220000).hex()
def cfg():
    if not CONFIG.exists(): return None
    c=json.loads(CONFIG.read_text())
    users=c.setdefault('users',{})
    uname=c.get('username')
    if uname and uname not in users:
        users[uname]={'username':uname,'salt':c.get('salt'),'password_hash':c.get('password_hash'),'role':c.get('role','super_admin'),'enabled':True,'mfa_enabled':bool(c.get('mfa_enabled',False)),'mfa_secret':c.get('mfa_secret'),'created_at':time.time()}
    c.setdefault('mfa_policy',{'required_for_roles':['super_admin','security_admin'],'issuer':'Cyber Terrafor Professional'})
    return c
def save(c):
    tmp=CONFIG.with_suffix('.tmp'); tmp.write_text(json.dumps(c,indent=2)); tmp.chmod(0o600); tmp.replace(CONFIG); CONFIG.chmod(0o600)
def audit(action, site_id='', detail=''):
    rec={'ts':time.time(),'action':action,'site_id':site_id,'detail':detail[:300]}
    with AUDIT.open('a') as f: f.write(json.dumps(rec,separators=(',',':'))+'\n')
    AUDIT.chmod(0o600)
def setup():
    return cfg()

def initialize_admin(username,password):
    username=(username or '').strip()
    if not 3 <= len(username) <= 64 or not username.replace('_','').replace('-','').isalnum(): raise ValueError('Username must be 3-64 characters and contain only letters, numbers, _ or -.')
    if len(password)<14: raise ValueError('Password must be at least 14 characters long.')
    salt,digest=hashpw(password)
    c={'version':VERSION,'username':username,'salt':salt,'password_hash':digest,'role':'super_admin','users':{username:{'username':username,'salt':salt,'password_hash':digest,'role':'super_admin','enabled':True,'mfa_enabled':False,'mfa_secret':None,'created_at':time.time()}},'sites':[],'auth_mode':'first_run_setup','mfa_ready':True,'mfa_policy':{'required_for_roles':['super_admin','security_admin'],'issuer':'Cyber Terrafor Professional'}}
    save(c); Vault(STATE,password=password); audit('first_run_setup',detail='administrator account initialized'); return c

def users(c): return c.setdefault('users',{})
def user_record(c,u):
    r=users(c).get(u)
    if r: return r
    if u==c.get('username'): return {'username':u,'salt':c.get('salt'),'password_hash':c.get('password_hash'),'role':c.get('role','super_admin'),'enabled':True,'mfa_enabled':bool(c.get('mfa_enabled',False)),'mfa_secret':c.get('mfa_secret')}
    return None
def verify(c,u,p):
    r=user_record(c,u)
    if not r or not r.get('enabled',True) or not r.get('salt') or not r.get('password_hash'): return False
    _,d=hashpw(p,r['salt']); return hmac.compare_digest(d,r['password_hash'])
def totp(secret,counter=None,digits=6):
    if counter is None: counter=int(time.time())//30
    key=base64.b32decode(secret.upper()+('='*((8-len(secret)%8)%8)),casefold=True)
    msg=struct.pack('>Q',counter); mac=hmac.new(key,msg,hashlib.sha1).digest(); off=mac[-1]&15
    return f'{(struct.unpack(">I",mac[off:off+4])[0]&0x7fffffff)%10**digits:0{digits}d}'
def verify_totp(secret,code,window=1):
    if not secret or not re.fullmatch(r'\d{6}',str(code or '')): return False
    now=int(time.time())//30
    return any(hmac.compare_digest(totp(secret,now+i),str(code)) for i in range(-window,window+1))
def new_totp_secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')
def required_mfa(c,r): return r.get('role') in c.get('mfa_policy',{}).get('required_for_roles',['super_admin','security_admin'])
def role_allowed(c,section,username=None):
    r=user_record(c,username) if username else None
    role=(r or {}).get('role',c.get('role','super_admin'))
    return role=='super_admin' or section in ROLES.get(role,set())
def client_ip(h): return h.client_address[0] if getattr(h,'client_address',None) else 'unknown'
def login_locked(ip): return LOGIN_ATTEMPTS.get(ip,{}).get('locked_until',0)>time.time()
def record_login_failure(ip):
    x=LOGIN_ATTEMPTS.setdefault(ip,{'count':0,'window':time.time()})
    if time.time()-x.get('window',0)>900: x.update(count=0,window=time.time())
    x['count']=x.get('count',0)+1
    if x['count']>=MAX_FAILED: x['locked_until']=time.time()+LOCK_SECONDS
def clear_login_failures(ip): LOGIN_ATTEMPTS.pop(ip,None)
def site(c,sid): return next((x for x in c.get('sites',[]) if x['id']==sid),None)
def page(t,b):
    nav = '<nav class="topnav"><a href="/">Overview</a><a href="/assessments">Assessments</a><a href="/files">File Security</a><a href="/sites">Websites</a><a href="/vault">Vault</a><a href="/reports">Reports</a><a href="/audit">Audit Log</a><a href="/security">Security</a><a href="/mfa">MFA</a><a href="/users">Users</a><a class="danger-link" href="/logout">Sign out</a></nav>' if t not in ('Login','First Run Setup') else ''
    return f"""<!doctype html>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta name=theme-color content="#08111f">
<link rel="icon" type="image/png" href="/assets/cyber-terrafor-mark.png">
<title>{html.escape(t)} · Cyber Terrafor Professional</title>
<style>
:root{{--bg:#07101d;--panel:#0d182a;--panel2:#101e33;--line:#203452;--text:#edf5ff;--muted:#8ea3c3;--accent:#4da3ff;--accent2:#7c5cff;--ok:#39d98a;--warn:#ffcc66;--danger:#ff667d;--shadow:0 18px 55px rgba(0,0,0,.28)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{font:14px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;background:radial-gradient(circle at 20% 0%,#12294a 0,transparent 34%),radial-gradient(circle at 90% 10%,#1a1640 0,transparent 30%),var(--bg);color:var(--text);margin:0;min-height:100vh}}
body:before{{content:"";position:fixed;inset:0;pointer-events:none;background-image:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);background-size:32px 32px;mask-image:linear-gradient(to bottom,black,transparent 78%)}}
header{{position:sticky;top:0;z-index:20;padding:15px 28px;border-bottom:1px solid rgba(103,139,188,.18);background:rgba(7,16,29,.82);backdrop-filter:blur(18px);display:flex;align-items:center;justify-content:space-between;gap:18px}}
.brand{{display:flex;align-items:center;gap:12px;min-width:0}}.brand-mark{{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;background:#050a12;border:1px solid rgba(255,75,75,.38);box-shadow:0 0 22px rgba(255,55,55,.18);overflow:hidden}}.brand-mark img{{width:100%;height:100%;object-fit:cover}}.brand-title{{font-weight:850;letter-spacing:.5px}}.brand-sub{{color:var(--muted);font-size:12px;margin-top:1px}}
.topnav{{display:flex;gap:6px;flex-wrap:wrap;align-items:center}}.topnav a{{text-decoration:none;color:#b9c9e3;padding:8px 11px;border-radius:9px;border:1px solid transparent}}.topnav a:hover{{color:white;background:#11223a;border-color:#223a5e}}.topnav .danger-link{{color:#ff9aab}}
main{{max-width:1220px;margin:0 auto;padding:34px 22px 70px;position:relative}}h1{{font-size:34px;line-height:1.15;margin:0 0 9px;letter-spacing:-.8px}}h2{{margin-top:0}}h3{{margin:0 0 5px}}p{{color:#b8c7dd}}.muted{{color:var(--muted)}}
.card{{background:linear-gradient(180deg,rgba(16,30,51,.94),rgba(11,23,40,.94));border:1px solid var(--line);border-radius:17px;padding:22px;margin:16px 0;box-shadow:var(--shadow);overflow:hidden}}.card:hover{{border-color:#2c4a72}}
input,textarea,select,button{{font:inherit;padding:11px 13px;margin:5px 0;background:#081426;color:#eef5ff;border:1px solid #29415f;border-radius:10px;outline:none}}input:focus,textarea:focus,select:focus{{border-color:var(--accent);box-shadow:0 0 0 3px rgba(77,163,255,.12)}}input,textarea,select{{width:min(100%,720px)}}textarea{{min-height:90px;resize:vertical}}button{{cursor:pointer;background:linear-gradient(135deg,#1d76c9,#6350d8);border-color:#4b8fe4;font-weight:750;padding:10px 15px;transition:.18s transform,.18s filter}}button:hover{{transform:translateY(-1px);filter:brightness(1.1)}}a{{color:#79b8ff}}label{{display:inline-block;margin-top:7px;color:#d8e5f7;font-weight:650}}
.badge{{display:inline-flex;align-items:center;gap:7px;padding:5px 9px;border-radius:999px;border:1px solid #29415f;background:#0b192c;color:#bcd0ea;font-size:12px;font-weight:700}}.badge:before{{content:"";width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 10px currentColor}}.ok{{color:var(--ok)}}.warn{{color:var(--warn)}}.danger{{color:var(--danger)}}
.kpis{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:22px 0}}.kpi{{padding:18px;border-radius:15px;border:1px solid var(--line);background:linear-gradient(145deg,#10233b,#0b1728);box-shadow:0 10px 30px rgba(0,0,0,.18)}}.kpi-label{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}}.kpi-value{{font-size:30px;font-weight:850;margin-top:3px}}
.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}}.module-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px}}.module{{display:block;text-decoration:none;padding:17px;border:1px solid var(--line);border-radius:13px;background:#0b1728;color:#dce9fa}}.module:hover{{background:#10213a;border-color:#3a5e8c;transform:translateY(-1px)}}.module strong{{display:block;margin-bottom:4px}}.module span{{font-size:12px;color:var(--muted)}}
table{{width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;border:1px solid var(--line);border-radius:13px}}td,th{{padding:12px 13px;border-bottom:1px solid #1b2c45;text-align:left;vertical-align:top}}th{{color:#9fb5d4;font-size:11px;text-transform:uppercase;letter-spacing:.8px;background:#0a1526}}tr:last-child td{{border-bottom:0}}tr:hover td{{background:rgba(38,70,110,.13)}}
pre{{background:#050c16;border:1px solid #1b2c45;border-radius:12px;padding:16px;color:#cfe2ff}}ul{{padding-left:20px}}.hero{{display:flex;justify-content:space-between;gap:18px;align-items:flex-start}}.hero-copy{{max-width:760px}}.eyebrow{{font-size:11px;letter-spacing:1.6px;text-transform:uppercase;color:#72b7ff;font-weight:800;margin-bottom:8px}}.actions{{display:flex;gap:8px;flex-wrap:wrap}}
.login-shell{{min-height:calc(100vh - 30px);display:grid;place-items:center;padding:24px}}.login-card{{width:min(460px,94vw);text-align:center;padding:30px 28px!important;background:linear-gradient(180deg,rgba(13,24,42,.97),rgba(6,13,24,.98));border:1px solid rgba(255,78,78,.25);box-shadow:0 25px 90px rgba(0,0,0,.55),0 0 55px rgba(160,20,20,.10)}}.login-logo{{width:150px;height:150px;margin:0 auto 12px;border-radius:28px;display:grid;place-items:center;background:radial-gradient(circle,rgba(255,44,44,.13),transparent 68%),#03070d;overflow:hidden;border:1px solid rgba(255,80,80,.22);box-shadow:0 0 35px rgba(255,35,35,.16)}}.login-logo img{{width:100%;height:100%;object-fit:cover;transform:scale(1.13)}}.login-title{{font-size:25px;font-weight:900;letter-spacing:2px}}.login-title span{{color:#ff4d4d}}.login-tag{{font-size:11px;letter-spacing:2px;color:#879ab8;margin:4px 0 24px}}.login-status{{display:flex;align-items:center;justify-content:center;gap:8px;color:#9eb2cf;font-size:12px;margin-top:16px}}.status-dot{{width:8px;height:8px;border-radius:50%;background:#39d98a;box-shadow:0 0 12px #39d98a}}.loading-shell{{min-height:calc(100vh - 30px);display:grid;place-items:center;background:radial-gradient(circle at center,rgba(120,15,15,.13),transparent 38%)}}.loader-card{{width:min(520px,92vw);text-align:center;padding:42px 30px;border:1px solid rgba(255,70,70,.28);border-radius:22px;background:rgba(6,12,21,.92);box-shadow:0 30px 100px rgba(0,0,0,.6),0 0 70px rgba(255,35,35,.08)}}.loader-logo{{width:190px;height:190px;margin:0 auto 18px;border-radius:38px;display:grid;place-items:center;background:#02050a;border:1px solid rgba(255,70,70,.28);box-shadow:0 0 55px rgba(255,40,40,.16);animation:torPulse 1.5s ease-in-out infinite}}.loader-logo img{{width:100%;height:100%;object-fit:cover;transform:scale(1.13);filter:drop-shadow(0 0 12px rgba(255,55,55,.55))}}.loader-ring{{width:52px;height:52px;margin:0 auto 18px;border:3px solid rgba(255,255,255,.12);border-top-color:#ff4b4b;border-right-color:#ff8b4b;border-radius:50%;animation:spin .85s linear infinite}}.loader-title{{font-size:20px;font-weight:850;letter-spacing:1px}}.loader-sub{{color:#8195b5;font-size:12px;margin-top:6px}}.progress{{height:5px;width:min(320px,80%);margin:22px auto 0;border-radius:99px;background:#172238;overflow:hidden}}.progress:after{{content:"";display:block;height:100%;width:35%;background:linear-gradient(90deg,#ff3f3f,#ff8d62);border-radius:99px;animation:progress 3.5s ease-in-out forwards}}@keyframes spin{{to{{transform:rotate(360deg)}}}}@keyframes torPulse{{50%{{transform:scale(1.035);box-shadow:0 0 70px rgba(255,40,40,.24)}}}}@keyframes progress{{from{{width:0}}to{{width:100%}}}}@media(max-width:900px){{.topnav{{display:none}}.kpis{{grid-template-columns:repeat(2,minmax(0,1fr))}}.module-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}.grid{{grid-template-columns:1fr}}}}
@media(max-width:560px){{header{{padding:12px 16px}}main{{padding:25px 14px 55px}}h1{{font-size:28px}}.kpis,.module-grid{{grid-template-columns:1fr}}.card{{padding:16px}}table{{display:block;overflow:auto;white-space:nowrap}}}}
</style>
<header><div class="brand"><div class="brand-mark"><img src="/assets/cyber-terrafor-mark.png" alt="Cyber Terrafor"></div><div><div class="brand-title">CYBER TERRAFOR PROFESSIONAL</div><div class="brand-sub">v{VERSION} · Enterprise Security Operations Center</div></div></div>{nav}</header><main>{b}</main>"""

def scope_match(url, scopes):
    host=urlparse(url).hostname
    if not host:return False
    host=host.lower().rstrip('.')
    for raw in scopes:
        x=raw.strip().lower().rstrip('.')
        if not x: continue
        if x.startswith('*.') and (host==x[2:] or host.endswith('.'+x[2:])): return True
        if x==host:return True
        try:
            if ipaddress.ip_address(host) in ipaddress.ip_network(x,strict=False): return True
        except ValueError: pass
    return False
class H(BaseHTTPRequestHandler):
    server_version='CyberTor/11.1'
    def sendx(self,code,body,headers=None,typ='text/html; charset=utf-8'):
        self.send_response(code); self.send_header('Content-Type',typ); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('X-Frame-Options','DENY'); self.send_header('Referrer-Policy','no-referrer'); self.send_header('Permissions-Policy','camera=(),microphone=(),geolocation=()'); self.send_header('Content-Security-Policy',"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body.encode())
    def send_bytes(self,code,body,typ='application/octet-stream',headers=None):
        self.send_response(code); self.send_header('Content-Type',typ); self.send_header('Cache-Control','public, max-age=86400'); self.send_header('X-Content-Type-Options','nosniff')
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(body)
    def auth(self, allow_pending=False):
        cookie=self.headers.get('Cookie',''); sid=''
        for part in cookie.split(';'):
            if part.strip().startswith('sid='): sid=part.strip()[4:]
        sidkey=hashlib.sha256(sid.encode()).hexdigest() if sid else ''
        x=SESSIONS.get(sidkey)
        if isinstance(x,dict) and x.get('exp',0)>time.time() and (x.get('authenticated',False) or (allow_pending and x.get('mfa_pending',False))): return x
        if sid: SESSIONS.pop(sidkey,None)
        return None
    def form(self):
        n=int(self.headers.get('Content-Length','0')); return parse_qs(self.rfile.read(n).decode())
    def csrf_ok(self,a,d): return hmac.compare_digest(d.get('csrf',[''])[0],a.get('csrf',''))
    def current_user(self,a,c): return user_record(c,a.get('username','')) if a else None
    def require_role(self,c,a,section): return bool(a and role_allowed(c,section,a.get('username')))
    def do_GET(self):
        if self.path.startswith("/api/v1/"): return self.do_API()
        c=setup(); u=urlparse(self.path); a=self.auth()
        if not c and u.path not in ('/setup','/assets/cyber-terrafor-mark.png'): return self.sendx(302,'',{'Location':'/setup'})
        if u.path=='/assets/cyber-terrafor-mark.png':
            try:
                data=(ASSETS/'cyber-terrafor-mark.png').read_bytes()
                return self.send_bytes(200,data,'image/png')
            except FileNotFoundError: return self.sendx(404,'Not found')
        if u.path=='/setup':
            if c: return self.sendx(302,'',{'Location':'/login'})
            body='''<div class=login-shell><div class=card login-card><div class=login-logo><img src="/assets/cyber-terrafor-mark.png" alt="Cyber Terrafor logo"></div><div class=login-title>CYBER <span>TERRAFOR</span></div><div class=login-tag>FIRST-RUN SECURE SETUP</div><h2>Create Administrator</h2><p class=muted>Choose your own credentials. No default password is created.</p><form method=post action=/setup><input name=username placeholder="Administrator username" autocomplete=username required style="width:100%"><input name=password type=password placeholder="Password (14+ characters)" autocomplete=new-password minlength=14 required style="width:100%"><input name=confirm type=password placeholder="Confirm password" autocomplete=new-password minlength=14 required style="width:100%"><button style="width:100%;padding:13px;margin-top:10px">Initialize Secure Control Plane</button></form></div></div>'''
            return self.sendx(200,page('First Run Setup',body))
        if u.path=='/login':
            body='''<div class=login-shell><div class=card login-card><div class=login-logo><img src="/assets/cyber-terrafor-mark.png" alt="Cyber Terrafor logo"></div><div class=login-title>CYBER <span>TERRAFOR</span></div><div class=login-tag>ASSESS · ANALYZE · SECURE</div><h2 style="margin-bottom:6px">Administrator Login</h2><p class=muted style="margin-top:0">Secure access to the Cyber Terrafor Professional control plane.</p><form method=post><input name=username placeholder="Username" autocomplete=username required style="width:100%"><input name=password type=password placeholder="Password" autocomplete=current-password required style="width:100%"><button style="width:100%;padding:13px;margin-top:10px">Sign in securely</button></form><div class=login-status><span class=status-dot></span> Local secure control plane</div></div></div>'''
            return self.sendx(200,page('Login',body))
        if u.path=='/logout':
            raw=next((part.strip()[4:] for part in self.headers.get('Cookie','').split(';') if part.strip().startswith('sid=')), '')
            if raw: SESSIONS.pop(hashlib.sha256(raw.encode()).hexdigest(),None)
            audit('logout'); return self.sendx(302,'',{'Location':'/login','Set-Cookie':'sid=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/'})
        if not a:return self.sendx(302,'',{'Location':'/login'})
        route_sections={'/assessments':'assessments','/files':'files','/sites':'sites','/vault':'vault','/reports':'reports','/audit':'audit','/security':'security','/ops':'vault'}
        section=route_sections.get(u.path)
        if section and not self.require_role(c,a,section): return self.sendx(403,page('Forbidden','<h1>Access denied</h1><p>Your role does not have permission for this section.</p>'))
        if u.path=='/':
            sites=len(c.get("sites",[])); enabled=sum(1 for x in c.get("sites",[]) if x.get("enabled")); reports=len(list(REPORTS.glob("*.json")))
            body=f"""<div class="hero"><div class="hero-copy"><div class="eyebrow">Security Operations Center</div><h1>Command Dashboard</h1><p>Centralized administration for authorized assessments, website connectors, infrastructure access, reports and audit evidence.</p></div><div class="actions"><a class="badge ok" href="/sites">System protected</a></div></div>
            <div class="kpis"><div class="kpi"><div class="kpi-label">Registered Sites</div><div class="kpi-value">{sites}</div><div class="muted">Authorized assets</div></div><div class="kpi"><div class="kpi-label">Active Connectors</div><div class="kpi-value">{enabled}</div><div class="muted">Enabled integrations</div></div><div class="kpi"><div class="kpi-label">Reports</div><div class="kpi-value">{reports}</div><div class="muted">Stored evidence</div></div><div class="kpi"><div class="kpi-label">Platform</div><div class="kpi-value">11.0</div><div class="muted">Enterprise build</div></div></div>
            <div class="card"><div class="eyebrow">Operations</div><h2>Security Control Center</h2><div class="module-grid"><a class="module" href="/assessments"><strong>Assessment Center</strong><span>Web, network, TLS, API and configuration assessments.</span></a><a class="module" href="/files"><strong>File Security</strong><span>Hashing, malware analysis, baseline and scope checks.</span></a><a class="module" href="/sites"><strong>Websites & Connectors</strong><span>Register authorized assets and manage connector tokens.</span></a><a class="module" href="/vault"><strong>Infrastructure Vault</strong><span>Encrypted storage for approved infrastructure credentials.</span></a><a class="module" href="/reports"><strong>Reports & Evidence</strong><span>Review generated reports and assessment output.</span></a><a class="module" href="/audit"><strong>Audit Log</strong><span>Track administrative and security operations.</span></a></div></div>
            <div class="grid"><div class="card"><div class="eyebrow">Operating posture</div><h3>Authorized-scope enforcement</h3><p class="muted">Assessment workflows require an explicit authorized scope before execution.</p><span class="badge ok">Scope controls enabled</span></div><div class="card"><div class="eyebrow">Security model</div><h3>Local control plane</h3><p class="muted">Administrative actions remain behind authenticated access and audit logging.</p><span class="badge">Authenticated</span></div></div>"""
            return self.sendx(200,page('Dashboard',body))
        if u.path=='/sites':
            rows=''.join(f'<tr><td>{html.escape(x["name"])}</td><td>{html.escape(x["url"])}</td><td>{"Enabled" if x.get("enabled") else "Disabled"}</td><td>{html.escape(", ".join(x.get("scopes",[])) or "No scope")}</td><td><form method=post action=/sites/toggle><input type=hidden name=site_id value="{x["id"]}"><input type=hidden name=csrf value="{a["csrf"]}"><button>Toggle</button></form><form method=post action=/sites/rotate-token><input type=hidden name=site_id value="{x["id"]}"><input type=hidden name=csrf value="{a["csrf"]}"><button>Rotate Token</button></form><a href="/ops?site_id={x["id"]}">Operations</a></td></tr>' for x in c.get('sites',[]))
            body=f'<h1>Authorized Websites</h1><div class=card><form method=post action=/sites/register><input name=csrf type=hidden value="{a["csrf"]}"><input name=name placeholder="Website name" required><br><input name=url placeholder="https://example.com" required><br><input name=scopes placeholder="example.com, *.example.com" required><br><button>Register & Issue Connector Token</button></form><p class=muted>Scopes are mandatory. Only HTTPS sites are accepted.</p></div><div class=card><table><tr><th>Name</th><th>URL</th><th>Status</th><th>Scope</th><th>Control</th></tr>'+rows+'</table></div><a href=/>Dashboard</a>'; return self.sendx(200,page('Websites',body))
        if u.path=='/vault':
            v=Vault(STATE,key=a['vault_key']); rows=''.join(f'<tr><td>{html.escape(x["name"])}</td><td>{"Configured" if v.has(x["id"]) else "Not configured"}</td><td><a href="/vault/edit?site_id={x["id"]}">Manage</a></td></tr>' for x in c.get('sites',[])); body='<h1>Infrastructure Access Vault</h1><p class=muted>Secrets are encrypted at rest with a random vault master key wrapped by the administrator password. Existing secret values are never rendered back to the browser.</p><div class=card><table><tr><th>Website</th><th>Vault</th><th>Action</th></tr>'+rows+'</table></div><a href=/>Dashboard</a>'; return self.sendx(200,page('Vault',body))
        if u.path=='/vault/edit':
            s=site(c,parse_qs(u.query).get('site_id',[''])[0]);
            if not s:return self.sendx(404,'Not found')
            v=Vault(STATE,key=a['vault_key']); old=v.get(s['id']) or {}
            def val(k):return html.escape(str(old.get(k,'')))
            b=f'''<h1>Infrastructure Access — {html.escape(s["name"])}</h1><p>{html.escape(s["url"])}</p><form method=post action=/vault/save><input type=hidden name=site_id value="{s["id"]}"><input type=hidden name=csrf value="{a["csrf"]}"><div class=card>Hosting provider<br><input name=provider value="{val('provider')}" placeholder="cloudflare_dns or cpanel_hosting"><br>Hosting base URL<br><input name=hosting_base_url value="{val('hosting_base_url')}" placeholder="https://host:2087"><br>Hosting API token<br><input name=hosting_token type=password placeholder="blank = preserve"><br>DNS API token<br><input name=dns_token type=password placeholder="blank = preserve"></div><div class=card>SSH username<br><input name=ssh_user value="{val('ssh_user')}"><br>SSH private key<br><textarea name=ssh_key placeholder="blank = preserve"></textarea><br>SFTP username<br><input name=sftp_user value="{val('sftp_user')}"><br>SFTP password<br><input name=sftp_password type=password placeholder="blank = preserve"></div><div class=card>Database host<br><input name=db_host value="{val('db_host')}"><br>Database username<br><input name=db_user value="{val('db_user')}"><br>Database password<br><input name=db_password type=password placeholder="blank = preserve"><br>Notes<br><textarea name=notes>{val('notes')}</textarea></div><button>Encrypt & Save</button></form><form method=post action=/vault/delete><input type=hidden name=site_id value="{s["id"]}"><input type=hidden name=csrf value="{a["csrf"]}"><button>Delete Stored Credentials</button></form><p><a href=/vault>Back</a></p>'''; return self.sendx(200,page('Manage Vault',b))
        if u.path=='/ops': return self.ops_page(c,a,parse_qs(u.query).get('site_id',[''])[0])
        if u.path=='/assessments':
            modules=[('web-audit','Web Security Audit'),('deep-audit','Deep Web Audit'),('deep-web-pentest','Deep Web Pentest'),('tls','TLS / HTTPS Audit'),('nmap','Network Service Scan'),('ports','Port Assessment'),('dns','DNS Assessment'),('geoip','GeoIP Intelligence'),('subdomain-intel','Subdomain Intelligence'),('api-audit','API Security Audit'),('cookie-audit','Cookie Audit'),('cors-audit','CORS Audit'),('javascript-audit','JavaScript Audit'),('cloud-audit','Cloud Exposure Audit'),('waf-cdn','WAF / CDN Detection'),('auth-audit','Authentication Audit'),('api-endpoints','API Endpoint Discovery'),('dependency-intel','Dependency Intelligence'),('http-methods','HTTP Methods Audit'),('headers','Security Headers Audit'),('tech-fingerprint','Technology Fingerprinting'),('vulnerability-assessment','Vulnerability Assessment'),('broken-links','Broken Links Audit'),('sensitive-objects','Sensitive Object Audit'),('error-misconfig','Error / Misconfiguration Audit'),('security-config','Security Configuration Audit'),('ssl-intel','SSL Intelligence'),('robots-sitemap','Robots / Sitemap Audit'),('redirect-security','Redirect Security Audit'),('adaptive-analysis','Adaptive Site Analysis'),('enterprise-posture','Enterprise Posture & Compliance'),('load-check','Load Check')]
            opts=''.join(f'<option value="{html.escape(k)}">{html.escape(v)}</option>' for k,v in modules)
            body=f"""<h1>Security Assessment Center</h1><p class=muted>All assessment modules are available from this authenticated panel. Use only assets you are authorized to assess.</p><div class=card><form method=post action=/assessments/run><input type=hidden name=csrf value="{a['csrf']}"><label>Module</label><br><select name=module style="padding:10px;margin:5px 0;background:#0d1430;color:#fff;border:1px solid #3b4c7a;border-radius:7px;width:100%">{opts}</select><br><label>Target URL / Host</label><br><input name=target placeholder="https://example.com or host" required style="width:96%"><br><label>Authorized scope (required)</label><br><input name=scope placeholder="example.com, *.example.com" style="width:96%"><br><label>Extra option (optional)</label><br><input name=extra placeholder="e.g. ports: 80,443 or nmap profile: quick" style="width:96%"><br><button>Run Assessment</button></form></div><div class=card><b>Other tools</b><p><a href=/files>File Security</a> · <a href=/reports>Reports</a> · <a href=/sites>Websites & Connector Control</a> · <a href=/vault>Infrastructure Vault</a> · <a href=/audit>Audit Log</a></p></div><p><a href=/>Dashboard</a></p>"""
            return self.sendx(200,page('Assessment Center',body))
        if u.path=='/files':
            body=f"""<h1>File Security</h1><div class=card><form method=post action=/files/run><input type=hidden name=csrf value="{a['csrf']}"><label>File / directory path</label><br><input name=target placeholder="/path/to/file-or-directory" required style="width:96%"><br><select name=module><option value="file-hash">File Hash</option><option value="malware-analyze">Malware Analyze</option><option value="malware-scan">Malware Scan</option><option value="baseline">Baseline</option><option value="scope-check">Scope Check</option></select><br><label><input type=checkbox name=quarantine> Enable quarantine (malware-scan only)</label><br><button>Run File Tool</button></form></div><p><a href=/>Dashboard</a></p>"""
            return self.sendx(200,page('File Security',body))
        if u.path=='/reports':
            rows=''.join(f'<li><a href="/reports/view?name={urllib.parse.quote(x.name)}">{html.escape(x.name)}</a></li>' for x in sorted(REPORTS.glob('*'), key=lambda x:x.stat().st_mtime, reverse=True) if x.is_file())
            return self.sendx(200,page('Reports',f'<h1>Reports</h1><div class=card><ul>{rows or "<li>No reports yet.</li>"}</ul></div><p><a href=/>Dashboard</a></p>'))
        if u.path=='/reports/view':
            name=Path(parse_qs(u.query).get('name',[''])[0]).name; f=REPORTS/name
            if not f.exists() or not f.is_file(): return self.sendx(404,'Not found')
            return self.sendx(200,page('Report',f'<h1>{html.escape(name)}</h1><div class=card><pre style="white-space:pre-wrap">{html.escape(f.read_text(errors="replace")[:200000])}</pre></div><a href=/reports>Back</a>'))
        if u.path=='/audit':
            lines=AUDIT.read_text().splitlines()[-100:] if AUDIT.exists() else []; items=''.join('<tr><td>'+html.escape(x.get('action',''))+'</td><td>'+html.escape(str(x.get('site_id','')))+'</td><td>'+html.escape(time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(x.get('ts',0))))+'</td><td>'+html.escape(x.get('detail',''))+'</td></tr>' for x in (json.loads(z) for z in lines)); body='<h1>Audit Log</h1><div class=card><table><tr><th>Action</th><th>Site</th><th>Time</th><th>Detail</th></tr>'+items+'</table></div><a href=/>Dashboard</a>'; return self.sendx(200,page('Audit',body))
        if u.path=='/users':
            if not a or user_record(c,a.get('username','')).get('role')!='super_admin': return self.sendx(403,'Forbidden')
            rows=''.join(f'<tr><td>{html.escape(x.get("username",k))}</td><td>{html.escape(x.get("role","viewer"))}</td><td>{"Enabled" if x.get("enabled",True) else "Disabled"}</td><td>{"Enabled" if x.get("mfa_enabled") else "Not enrolled"}</td><td><form method=post action=/users/toggle><input type=hidden name=csrf value="{a["csrf"]}"><input type=hidden name=username value="{html.escape(x.get("username",k))}"><button>Toggle</button></form><form method=post action=/users/reset-mfa><input type=hidden name=csrf value="{a["csrf"]}"><input type=hidden name=username value="{html.escape(x.get("username",k))}"><button>Reset MFA</button></form></td></tr>' for k,x in users(c).items())
            body=f'''<h1>Identity & Access Management</h1><p class=muted>Multi-user RBAC, account lifecycle and MFA administration.</p><div class=card><h2>Create User</h2><form method=post action=/users/create><input type=hidden name=csrf value="{a['csrf']}"><input name=username placeholder="username" required><select name=role><option>viewer</option><option>auditor</option><option>analyst</option><option>security_admin</option><option>super_admin</option></select><input name=password type=password minlength=14 placeholder="temporary password (14+)" required><button>Create user</button></form></div><div class=card><table><tr><th>User</th><th>Role</th><th>Status</th><th>MFA</th><th>Actions</th></tr>{rows}</table></div>'''
            return self.sendx(200,page('Users',body))
        if u.path=='/mfa':
            r=self.current_user(a,c)
            if not r:return self.sendx(403,'Forbidden')
            if r.get('mfa_enabled'): body='<h1>Multi-Factor Authentication</h1><div class=card><h2>TOTP enabled</h2><p>Your account is protected by authenticator-based MFA.</p><form method=post action=/mfa/disable><input type=hidden name=csrf value="'+a['csrf']+'"><button>Disable TOTP</button></form></div>'
            else:
                secret=r.get('mfa_secret') or new_totp_secret(); r['mfa_secret']=secret; save(c); issuer=urllib.parse.quote(c.get('mfa_policy',{}).get('issuer','Cyber Terrafor Professional')); label=urllib.parse.quote(f'{issuer}:{r["username"]}'); uri=f'otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30'; body=f'<h1>Enroll TOTP MFA</h1><div class=card><p>Add this secret to your authenticator app.</p><p><b>Secret:</b></p><pre>{secret}</pre><p><b>otpauth URI:</b></p><textarea readonly style="width:100%;min-height:110px">{html.escape(uri)}</textarea><form method=post action=/mfa/enable><input type=hidden name=csrf value="{a["csrf"]}"><input name=code inputmode=numeric maxlength=6 placeholder="Current 6-digit code" required><button>Verify & Enable MFA</button></form></div>'
            return self.sendx(200,page('MFA',body))
        if u.path=='/security':
            if not self.require_role(c,a,'security'): return self.sendx(403,'Forbidden')
            body=f'''<h1>Security Settings</h1><div class=card><h2>Administrator Password</h2><p class=muted>Changing the password automatically re-wraps the encrypted infrastructure vault and revokes all active sessions.</p><form method=post action=/security/password><input type=hidden name=csrf value="{a['csrf']}"><input name=current type=password placeholder="Current password" required style="width:100%"><input name=password type=password placeholder="New password (14+ characters)" minlength=14 required style="width:100%"><input name=confirm type=password placeholder="Confirm new password" minlength=14 required style="width:100%"><button>Change Password</button></form></div><div class=card><h3>Authentication Controls</h3><ul><li>PBKDF2-HMAC-SHA256 password hashing</li><li>5-attempt temporary lockout</li><li>Hashed session identifiers</li><li>HttpOnly + SameSite session cookie</li><li>8-hour absolute session lifetime</li><li>Multi-user RBAC with role isolation</li><li>TOTP MFA with enrollment/reset</li><li>Scoped connector API permissions</li></ul></div>'''; return self.sendx(200,page('Security Settings',body))
        return self.sendx(404,'Not found')
    def ops_page(self, c, a, sid):
        s=site(c,sid)
        if not s: return self.sendx(404,'Not found')
        v=Vault(STATE,key=a['vault_key']); creds=v.get(sid) or {}
        provider=creds.get('provider','')
        body=f"<h1>Infrastructure Operations — {html.escape(s['name'])}</h1><p class=muted>Read-only provider discovery and health checks. Operations are constrained to the registered site scope.</p>"
        body += '<div class=card><b>Provider:</b> '+html.escape(provider or 'Not configured')+'<br><form method=post action=/ops/run><input type=hidden name=csrf value="'+a['csrf']+'"><input type=hidden name=site_id value="'+html.escape(sid)+'"><button name=op value="dns_inventory">DNS inventory</button><button name=op value="hosting_health">Hosting health</button><button name=op value="backup_inventory">Backup inventory</button><button name=op value="backup_snapshot">Create state backup</button></form></div>'
        body += '<p><a href=/vault>Vault</a> · <a href=/sites>Sites</a> · <a href=/>Dashboard</a></p>'
        return self.sendx(200,page('Infrastructure Operations',body))

    def do_POST(self):
        if self.path.startswith("/api/v1/"): return self.do_API()
        c=setup(); d=self.form(); a=self.auth(allow_pending=(self.path=='/login/mfa'))
        if self.path=='/setup':
            if c: return self.sendx(409,'Initial setup has already been completed')
            if d.get('password',[''])[0] != d.get('confirm',[''])[0]: return self.sendx(400,page('Setup failed','<h1>Passwords do not match</h1><a href=/setup>Try again</a>'))
            try: initialize_admin(d.get('username',[''])[0],d.get('password',[''])[0])
            except ValueError as e: return self.sendx(400,page('Setup failed','<h1>Setup failed</h1><p>'+html.escape(str(e))+'</p><a href=/setup>Try again</a>'))
            return self.sendx(302,'',{'Location':'/login'})
        if not c: return self.sendx(302,'',{'Location':'/setup'})
        if self.path=='/login':
            ip=client_ip(self)
            if login_locked(ip): return self.sendx(429,page('Temporarily locked','<h1>Too many failed attempts</h1><p>Please wait 15 minutes.</p>'))
            u_name=d.get('username',[''])[0].strip(); p=d.get('password',[''])[0]; r=user_record(c,u_name)
            if verify(c,u_name,p):
                clear_login_failures(ip)
                if required_mfa(c,r) and not r.get('mfa_enabled'):
                    # First authenticated session is allowed solely so the user can enroll TOTP.
                    audit('mfa_enrollment_required',detail=u_name)
                if r.get('mfa_enabled'):
                    raw=secrets.token_urlsafe(32); sid=hashlib.sha256(raw.encode()).hexdigest(); now=time.time(); SESSIONS[sid]={'exp':now+MFA_PENDING_SECONDS,'absolute_exp':now+MFA_PENDING_SECONDS,'csrf':secrets.token_urlsafe(24),'username':u_name,'password':p,'mfa_pending':True,'authenticated':False,'vault_key':None,'role':r.get('role','viewer')}
                    body=f'''<div class=login-shell><div class=card login-card><div class=login-logo><img src="/assets/cyber-terrafor-mark.png"></div><div class=login-title>CYBER <span>TERRAFOR</span></div><div class=login-tag>MULTI-FACTOR VERIFICATION</div><h2>Enter authenticator code</h2><p class=muted>Enter the current 6-digit code from your authenticator.</p><form method=post action=/login/mfa><input name=code inputmode=numeric autocomplete=one-time-code maxlength=6 pattern="[0-9]{{6}}" placeholder="6-digit code" required style="width:100%"><input type=hidden name=csrf value="{SESSIONS[sid]['csrf']}"><button style="width:100%;padding:13px">Verify MFA</button></form></div></div>'''
                    return self.sendx(200,page('MFA Verification',body),{'Set-Cookie':f'sid={raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age={MFA_PENDING_SECONDS}'})
                try: vk=Vault(STATE,password=p)._key
                except VaultError as e: return self.sendx(500,page('Vault error',html.escape(str(e))))
                raw=secrets.token_urlsafe(32); sid=hashlib.sha256(raw.encode()).hexdigest(); now=time.time(); SESSIONS[sid]={'exp':now+SESSION_SECONDS,'absolute_exp':now+8*3600,'csrf':secrets.token_urlsafe(24),'vault_key':vk,'role':r.get('role','super_admin'),'username':u_name,'authenticated':True}
                audit('login',detail=f'successful user={u_name}')
                loader='''<div class=loading-shell><div class=loader-card><div class=loader-logo><img src="/assets/cyber-terrafor-mark.png" alt="Cyber Terrafor"></div><div class=loader-ring></div><div class=loader-title>Initializing Cyber Terrafor</div><div class=loader-sub>Verifying secure session · Loading control plane · Preparing operations center</div><div class=progress></div></div></div><script>setTimeout(function(){window.location.replace('/');},3500);</script>'''
                return self.sendx(200,page('Initializing Cyber Terrafor',loader),{'Set-Cookie':f'sid={raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}'})
            record_login_failure(ip); audit('login_failed',detail=f'invalid credentials user={u_name[:64]}')
            return self.sendx(401,page('Login failed','<h1>Login failed</h1><p>Invalid username or password.</p><a href=/login>Try again</a>'))
        if self.path=='/login/mfa':
            cookie=self.headers.get('Cookie',''); raw=next((part.strip()[4:] for part in cookie.split(';') if part.strip().startswith('sid=')), ''); sidkey=hashlib.sha256(raw.encode()).hexdigest() if raw else ''; pending=SESSIONS.get(sidkey)
            if not pending or not pending.get('mfa_pending') or pending.get('exp',0)<=time.time() or not self.csrf_ok(pending,d): return self.sendx(403,'MFA session expired or invalid')
            c=setup(); r=user_record(c,pending.get('username',''))
            if not r or not verify_totp(r.get('mfa_secret'),d.get('code',[''])[0]): audit('mfa_failed',detail=pending.get('username','')); return self.sendx(401,page('MFA failed','<h1>Invalid MFA code</h1><a href=/login>Start again</a>'))
            try: vk=Vault(STATE,password=pending['password'])._key
            except VaultError as e: return self.sendx(500,page('Vault error',html.escape(str(e))))
            now=time.time(); pending.update({'exp':now+SESSION_SECONDS,'absolute_exp':now+8*3600,'vault_key':vk,'role':r.get('role','viewer'),'authenticated':True}); pending.pop('password',None); pending.pop('mfa_pending',None); audit('mfa_success',detail=r.get('username','')); return self.sendx(302,'',{'Location':'/','Set-Cookie':f'sid={raw}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_SECONDS}'})
        if not a:return self.sendx(403,'Forbidden')
        post_sections={'/assessments/run':'assessments','/files/run':'files','/sites/register':'sites','/sites/toggle':'sites','/sites/rotate-token':'sites','/ops/run':'vault','/vault/save':'vault','/vault/delete':'vault','/users/create':'users','/users/toggle':'users','/users/reset-mfa':'users'}
        section=post_sections.get(self.path)
        if section and not self.require_role(c,a,section): return self.sendx(403,'Forbidden')
        if not self.csrf_ok(a,d):return self.sendx(403,'CSRF validation failed')
        if self.path=='/users/create':
            if not a or user_record(c,a.get('username','')).get('role')!='super_admin': return self.sendx(403,'Forbidden')
            uname=d.get('username',[''])[0].strip(); role=d.get('role',['viewer'])[0]; pw=d.get('password',[''])[0]
            if role not in ROLES or not re.fullmatch(r'[A-Za-z0-9_-]{3,64}',uname): return self.sendx(400,'Invalid username or role')
            if uname in users(c): return self.sendx(409,'User already exists')
            if len(pw)<14:return self.sendx(400,'Password must be at least 14 characters')
            salt,digest=hashpw(pw); users(c)[uname]={'username':uname,'salt':salt,'password_hash':digest,'role':role,'enabled':True,'mfa_enabled':False,'mfa_secret':None,'created_at':time.time()}; save(c); audit('user_created',detail=f'user={uname} role={role}'); return self.sendx(302,'',{'Location':'/users'})
        if self.path=='/users/toggle':
            if not a or user_record(c,a.get('username','')).get('role')!='super_admin': return self.sendx(403,'Forbidden')
            uname=d.get('username',[''])[0]; r=user_record(c,uname)
            if not r:return self.sendx(404,'User not found')
            if uname==a.get('username') and r.get('enabled',True):return self.sendx(400,'You cannot disable your own active account')
            r['enabled']=not r.get('enabled',True); save(c); audit('user_toggled',detail=f'user={uname} enabled={r["enabled"]}'); return self.sendx(302,'',{'Location':'/users'})
        if self.path=='/users/reset-mfa':
            if not a or user_record(c,a.get('username','')).get('role')!='super_admin': return self.sendx(403,'Forbidden')
            uname=d.get('username',[''])[0]; r=user_record(c,uname)
            if not r:return self.sendx(404,'User not found')
            r['mfa_enabled']=False; r['mfa_secret']=None; save(c); audit('mfa_reset',detail=f'user={uname}'); return self.sendx(302,'',{'Location':'/users'})
        if self.path=='/mfa/enable':
            r=self.current_user(a,c)
            if not r:return self.sendx(403,'Forbidden')
            if not verify_totp(r.get('mfa_secret'),d.get('code',[''])[0]):return self.sendx(400,page('MFA verification failed','<h1>Invalid TOTP code</h1><a href=/mfa>Try again</a>'))
            r['mfa_enabled']=True; save(c); audit('mfa_enabled',detail=f'user={r["username"]}'); return self.sendx(200,page('MFA enabled','<h1>TOTP MFA enabled</h1><p>Your next login will require an authenticator code.</p><a href=/security>Security</a>'))
        if self.path=='/mfa/disable':
            r=self.current_user(a,c)
            if not r:return self.sendx(403,'Forbidden')
            if required_mfa(c,r):return self.sendx(400,'MFA is mandatory for this role')
            r['mfa_enabled']=False; r['mfa_secret']=None; save(c); audit('mfa_disabled',detail=f'user={r["username"]}'); return self.sendx(302,'',{'Location':'/mfa'})
        if self.path=='/security/password':
            if not self.require_role(c,a,'security'): return self.sendx(403,'Forbidden')
            current=d.get('current',[''])[0]; newp=d.get('password',[''])[0]
            uname=a.get('username',c.get('username','')); r=user_record(c,uname)
            if not verify(c,uname,current): return self.sendx(403,'Current password is incorrect')
            if newp != d.get('confirm',[''])[0] or len(newp)<14: return self.sendx(400,'New password confirmation failed or password is too short')
            try: Vault(STATE).change_password(current,newp)
            except VaultError as e: return self.sendx(500,page('Password change failed','<h1>Password change failed</h1><p>'+html.escape(str(e))+'</p>'))
            salt,digest=hashpw(newp); r['salt']=salt; r['password_hash']=digest; c['auth_mode']='password_changed';
            if uname==c.get('username'): c['salt']=salt; c['password_hash']=digest
            save(c); audit('password_changed',detail=f'user={uname}'); SESSIONS.clear()
            return self.sendx(200,page('Password changed','<h1>Password changed successfully</h1><p>All sessions were revoked.</p><a href=/login>Sign in again</a>'))
        if self.path=='/assessments/run':
            allowed={'web-audit','deep-audit','tls','nmap','ports','dns','geoip','subdomain-intel','api-audit','cookie-audit','cors-audit','javascript-audit','cloud-audit','waf-cdn','auth-audit','api-endpoints','dependency-intel','http-methods','headers','tech-fingerprint','vulnerability-assessment','broken-links','sensitive-objects','error-misconfig','security-config','ssl-intel','robots-sitemap','redirect-security','adaptive-analysis','enterprise-posture','deep-web-pentest','load-check'}
            module=d.get('module',[''])[0]; target=d.get('target',[''])[0].strip(); scope=d.get('scope',[''])[0].strip(); extra=d.get('extra',[''])[0].strip()
            if module not in allowed or not target:return self.sendx(400,'Invalid assessment request')
            if not scope:
                return self.sendx(400,'Authorized scope is required for network assessments. Enter the authorized hostname, wildcard, CIDR, or a comma-separated list.')
            import subprocess
            scope_entries=[x.strip() for x in scope.split(',') if x.strip()]
            if not scope_entries:
                return self.sendx(400,'Authorized scope is required for network assessments.')
            scope_dir=BASE/'state'/'runtime_scopes'
            scope_dir.mkdir(parents=True, exist_ok=True)
            safe_id=re.sub(r'[^A-Za-z0-9_.-]+','_',secrets.token_urlsafe(12))
            scope_path=scope_dir/f'assessment_{safe_id}.txt'
            scope_path.write_text('\n'.join(scope_entries)+'\n', encoding='utf-8')
            cmd=[sys.executable,str(BASE/'src'/'cyber_terrafor.py'),'--scope',str(scope_path)]
            cmd.extend([module,target])
            if module=='deep-web-pentest' and extra in ('deep-web','enterprise'): cmd.extend(['--profile',extra])
            if module=='load-check' and extra:
                try: cmd.extend(['--count',str(max(1,min(50,int(extra))))])
                except ValueError: pass
            if module=='nmap' and extra in ('quick','service','os','common'): cmd.extend(['--profile',extra])
            if module=='ports' and extra:
                ports=','.join(x.strip() for x in extra.split(',') if x.strip().isdigit())
                if ports: cmd.extend(['--ports',ports])
            try:
                r=subprocess.run(cmd,cwd=str(BASE),capture_output=True,text=True,timeout=180)
                audit('assessment_run',detail=f'{module} target={target[:180]} rc={r.returncode}')
                out=(r.stdout+'\n'+r.stderr).strip()
                return self.sendx(200 if r.returncode==0 else 400,page('Assessment Result',f'<h1>{html.escape(module)} result</h1><div class=card><pre style="white-space:pre-wrap;max-height:70vh;overflow:auto">{html.escape(out[-100000:])}</pre></div><p><a href=/assessments>Run another</a> · <a href=/>Dashboard</a></p>'))
            except subprocess.TimeoutExpired:
                audit('assessment_timeout',detail=f'{module} target={target[:180]}')
                return self.sendx(408,page('Assessment Timeout','<h1>Assessment timed out</h1><p>Try a narrower scope or a lighter module.</p><a href=/assessments>Back</a>'))
            finally:
                try: scope_path.unlink(missing_ok=True)
                except Exception: pass
        if self.path=='/files/run':
            module=d.get('module',[''])[0]; target=d.get('target',[''])[0].strip(); quarantine='quarantine' in d
            allowed={'file-hash','malware-analyze','malware-scan','baseline','scope-check'}
            if module not in allowed or not target:return self.sendx(400,'Invalid file request')
            import subprocess
            cmd=[sys.executable,str(BASE/'src'/'cyber_terrafor.py'),module,target]
            if module=='malware-scan' and quarantine: cmd.append('--quarantine')
            try:
                r=subprocess.run(cmd,cwd=str(BASE),capture_output=True,text=True,timeout=180)
                audit('file_tool_run',detail=f'{module} target={target[:180]} rc={r.returncode}')
                out=(r.stdout+'\n'+r.stderr).strip()
                return self.sendx(200 if r.returncode==0 else 400,page('File Tool Result',f'<h1>{html.escape(module)} result</h1><div class=card><pre style="white-space:pre-wrap;max-height:70vh;overflow:auto">{html.escape(out[-100000:])}</pre></div><a href=/files>Back</a>'))
            except subprocess.TimeoutExpired:
                return self.sendx(408,page('File Tool Timeout','<h1>Operation timed out</h1><a href=/files>Back</a>'))
        if self.path=='/sites/register':
            url=d.get('url',[''])[0].strip().rstrip('/'); scopes=[x.strip() for x in d.get('scopes',[''])[0].split(',') if x.strip()]
            if not url.lower().startswith('https://'):return self.sendx(400,'HTTPS URL required')
            if not scopes or not scope_match(url,scopes):return self.sendx(400,'Scope must explicitly authorize the registered hostname')
            if any(x.get('url')==url for x in c.get('sites',[])):return self.sendx(409,'Site already registered')
            token=secrets.token_urlsafe(32); th=hashlib.sha256(token.encode()).hexdigest(); sid=secrets.token_urlsafe(9); c.setdefault('sites',[]).append({'id':sid,'name':d.get('name',[''])[0][:80],'url':url,'enabled':True,'scopes':scopes,'token_hash':th,'created_at':time.time(),'last_heartbeat':None,'api_scopes':['status','heartbeat','event']}); save(c); audit('site_registered',sid,url); body=f'<h1>Site registered</h1><div class=card><p><b>Site ID:</b> {sid}</p><p class=warn><b>Connector token — shown once:</b></p><textarea rows=3 style="width:100%">{html.escape(token)}</textarea><p>Store this token in the authorized site environment. It cannot be recovered from the panel.</p></div><a href=/sites>Back to sites</a>'; return self.sendx(201,page('Registered',body))
        if self.path=='/sites/toggle':
            s=site(c,d.get('site_id',[''])[0]);
            if s:s['enabled']=not s.get('enabled',True);save(c);audit('site_toggled',s['id'],str(s['enabled']))
            return self.sendx(302,'',{'Location':'/sites'})
        if self.path=='/sites/rotate-token':
            s=site(c,d.get('site_id',[''])[0])
            if not s:return self.sendx(404,'Not found')
            token=secrets.token_urlsafe(32); s['token_hash']=hashlib.sha256(token.encode()).hexdigest(); save(c); audit('connector_token_rotated',s['id'])
            body=f'<h1>Connector token rotated</h1><div class=card><p><b>Site ID:</b> {html.escape(s["id"])}</p><p class=warn><b>New token — shown once:</b></p><textarea rows=3 style="width:100%">{html.escape(token)}</textarea><p>The previous token is immediately invalid.</p></div><a href=/sites>Back to sites</a>'
            return self.sendx(200,page('Token rotated',body))
        if self.path=='/ops/run':
            s=site(c,d.get('site_id',[''])[0])
            if not s:return self.sendx(404,'Not found')
            op=d.get('op',[''])[0]; v=Vault(STATE,key=a['vault_key']); creds=v.get(s['id']) or {}; host=urlparse(s['url']).hostname
            try:
                if op=='dns_inventory':
                    token=creds.get('dns_token','')
                    if not token or creds.get('provider')!='cloudflare_dns': raise AdapterError('Configure provider=cloudflare_dns and DNS API token')
                    result=CloudflareDNSAdapter(token).inventory(host)
                elif op=='hosting_health':
                    token=creds.get('hosting_token',''); base=creds.get('hosting_base_url','')
                    if not token or creds.get('provider')!='cpanel_hosting' or not base: raise AdapterError('Configure provider=cpanel_hosting, hosting base URL and API token')
                    result=CPanelHostingAdapter(token,base).health()
                elif op=='backup_inventory':
                    result=LocalBackupAdapter(STATE).inventory()
                elif op=='backup_snapshot':
                    result=LocalBackupAdapter(STATE).create_snapshot()
                else: raise AdapterError('Unknown operation')
                audit('infrastructure_operation',s['id'],op)
                return self.sendx(200,page('Operation result','<h1>Operation completed</h1><div class=card><pre>'+html.escape(json.dumps(result,indent=2))+'</pre></div><a href="/ops?site_id='+urllib.parse.quote(s['id'])+'">Back</a>'))
            except AdapterError as e:
                audit('infrastructure_operation_failed',s['id'],op+': '+str(e))
                return self.sendx(400,page('Operation failed','<h1>Operation failed</h1><div class=card>'+html.escape(str(e))+'</div><a href="/ops?site_id='+urllib.parse.quote(s['id'])+'">Back</a>'))
        if self.path=='/vault/save':
            s=site(c,d.get('site_id',[''])[0]);
            if not s:return self.sendx(404,'Not found')
            v=Vault(STATE,key=a['vault_key']); old=v.get(s['id']) or {}; keys=['provider','hosting_base_url','hosting_token','dns_token','ssh_user','ssh_key','sftp_user','sftp_password','db_host','db_user','db_password','notes']; obj={k:(d.get(k,[''])[0] or old.get(k,'')) for k in keys}; v.put(s['id'],obj); audit('vault_saved',s['id']); return self.sendx(200,page('Saved','<h1>Encrypted infrastructure credentials saved.</h1><p>Secrets are not returned to the browser.</p><a href=/vault>Back</a>'))
        if self.path=='/vault/delete':
            s=site(c,d.get('site_id',[''])[0]);
            if s:Vault(STATE,key=a['vault_key']).delete(s['id']);audit('vault_deleted',s['id'])
            return self.sendx(302,'',{'Location':'/vault'})
        return self.sendx(404,'Not found')
    def do_API(self):
        c=cfg(); u=urlparse(self.path); token=self.headers.get('Authorization','')
        if not token.startswith('Bearer '): return self.sendx(401,json.dumps({'error':'missing token'}),typ='application/json')
        raw=token[7:]; th=hashlib.sha256(raw.encode()).hexdigest(); s=next((x for x in c.get('sites',[]) if hmac.compare_digest(x.get('token_hash',''),th)),None)
        if not s or not s.get('enabled'): return self.sendx(403,json.dumps({'error':'invalid or disabled connector'}),typ='application/json')
        scope=u.path.rsplit('/',1)[-1]
        if scope not in set(s.get('api_scopes',[])): return self.sendx(403,json.dumps({'error':'API scope denied','required_scope':scope}),typ='application/json')
        if u.path=='/api/v1/site/status': out={'ok':True,'version':VERSION,'site_id':s['id'],'enabled':s['enabled'],'last_heartbeat':s.get('last_heartbeat')}
        elif u.path in ('/api/v1/site/heartbeat','/api/v1/site/event'):
            try: body=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))).decode() or '{}')
            except: body={}
            if body.get('site_id')!=s['id']: return self.sendx(400,json.dumps({'error':'site_id mismatch'}),typ='application/json')
            if u.path.endswith('heartbeat'):
                s['last_heartbeat']=time.time(); save(c); audit('connector_heartbeat',s['id'])
                out={'ok':True,'site_id':s['id'],'received_at':s['last_heartbeat']}
            else:
                ev=str(body.get('event','connector_event'))[:200]; audit('connector_event',s['id'],ev); out={'ok':True,'site_id':s['id'],'accepted':True}
        else:return self.sendx(404,json.dumps({'error':'not found'}),typ='application/json')
        return self.sendx(200,json.dumps(out),typ='application/json')
    def do_PUT(self): self.do_API()
    def do_PATCH(self): self.do_API()
    def do_DELETE(self): self.do_API()
    def do_OPTIONS(self): self.sendx(204,'',{'Allow':'GET,POST,PUT,PATCH,DELETE,OPTIONS'})
    def do(self,method):
        if self.path.startswith('/api/v1/'): return self.do_API()
        return super().do(method)
def run(host='127.0.0.1',port=8787): setup(); print(f'Cyber Terrafor v{VERSION} admin: http://{host}:{port}/'); ThreadingHTTPServer((host,port),H).serve_forever()
if __name__=='__main__':
    host=sys.argv[1] if len(sys.argv)>1 else '127.0.0.1'
    port=int(sys.argv[2]) if len(sys.argv)>2 else 8787
    run(host,port)

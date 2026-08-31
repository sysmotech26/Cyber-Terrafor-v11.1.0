"""Scope-controlled infrastructure provider adapters for v11.0.

All provider operations exposed here are read-only. There is no arbitrary
remote command execution, file upload, DNS mutation, or destructive action.
"""
import json, urllib.parse, urllib.request, urllib.error, tarfile, time
from pathlib import Path

class AdapterError(Exception): pass

def _request(url, token, headers=None, timeout=10):
    h={'Accept':'application/json','User-Agent':'Cyber-Terrafor-Adapter/10.0'}
    if headers: h.update(headers)
    if token: h['Authorization']='Bearer '+token
    req=urllib.request.Request(url, headers=h, method='GET')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw=r.read().decode(errors='replace')
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise AdapterError(f'HTTP {e.code}') from e
    except Exception as e:
        raise AdapterError(str(e)) from e

class CloudflareDNSAdapter:
    name='cloudflare_dns'
    def __init__(self, token): self.token=token
    def inventory(self, hostname):
        host=hostname.lower().rstrip('.')
        zones=_request('https://api.cloudflare.com/client/v4/zones?name='+urllib.parse.quote(host), self.token)
        result=zones.get('result') or []
        if not result: raise AdapterError('No Cloudflare zone matched the authorized hostname')
        zone=result[0]; zid=zone.get('id')
        records=_request(f'https://api.cloudflare.com/client/v4/zones/{zid}/dns_records?per_page=100', self.token)
        safe=[]
        for r in (records.get('result') or []):
            name=(r.get('name') or '').lower().rstrip('.')
            if name==host or name.endswith('.'+host) or host.endswith('.'+name):
                safe.append({'id':r.get('id'),'type':r.get('type'),'name':r.get('name'),'content':r.get('content'),'proxied':r.get('proxied')})
        return {'provider':self.name,'zone':zone.get('name'),'zone_status':zone.get('status'),'records':safe}

class CPanelHostingAdapter:
    name='cpanel_hosting'
    def __init__(self, token, base_url): self.token=token; self.base=base_url.rstrip('/')
    def health(self):
        if not self.base.startswith('https://'): raise AdapterError('cPanel base URL must use HTTPS')
        url=self.base+'/execute/ServerInformation/get_information'
        return {'provider':self.name,'response':_request(url,self.token)}

class LocalBackupAdapter:
    name='local_backup'
    def __init__(self, root): self.root=Path(root); self.backup_dir=self.root/'backups'; self.backup_dir.mkdir(exist_ok=True)
    def inventory(self):
        return {'provider':self.name,'backups':sorted(p.name for p in self.backup_dir.glob('*.tar.gz')),'state_files':sorted(p.name for p in self.root.glob('*') if p.is_file())}
    def create_snapshot(self):
        stamp=time.strftime('%Y%m%d-%H%M%S',time.gmtime())
        out=self.backup_dir/f'cyber-terrafor-state-{stamp}.tar.gz'
        with tarfile.open(out,'w:gz') as tar:
            for p in self.root.iterdir():
                if p.name=='backups' or not p.is_file(): continue
                tar.add(p,arcname=p.name)
        return {'provider':self.name,'backup':out.name,'created_at':time.time()}

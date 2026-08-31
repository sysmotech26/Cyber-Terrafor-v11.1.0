#!/usr/bin/env python3
"""Cyber Terrafor Professional v11.0 authorized website connector."""
import argparse, json, urllib.request, urllib.error
VERSION='11.0.0'
def request(url, method='GET', token=None, payload=None):
    data=json.dumps(payload).encode() if payload is not None else None
    headers={'Content-Type':'application/json','Accept':'application/json','User-Agent':f'Cyber-Terrafor-Connector/{VERSION}'}
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(url,data=data,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=10) as r:return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body=e.read().decode(errors='replace'); raise SystemExit(f'Connector request failed: HTTP {e.code}: {body}')
def main():
    p=argparse.ArgumentParser(description='Cyber Terrafor authorized website connector')
    p.add_argument('--panel',required=True); p.add_argument('--site-id',required=True); p.add_argument('--token',required=True)
    p.add_argument('action',choices=['status','heartbeat','event']); p.add_argument('--event',default='connector_check')
    a=p.parse_args(); base=a.panel.rstrip('/')
    if a.action=='status': out=request(f'{base}/api/v1/site/status?site_id={a.site_id}',token=a.token)
    elif a.action=='heartbeat': out=request(f'{base}/api/v1/site/heartbeat',method='POST',token=a.token,payload={'site_id':a.site_id})
    else: out=request(f'{base}/api/v1/site/event',method='POST',token=a.token,payload={'site_id':a.site_id,'event':a.event})
    print(json.dumps(out,indent=2))
if __name__=='__main__': main()

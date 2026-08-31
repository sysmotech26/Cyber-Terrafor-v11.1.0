#!/usr/bin/env python3
"""Cyber Terrafor Professional v11.1.0 - Authorized Security Assessment & Defensive Security Suite."""
import argparse, hashlib, html, ipaddress, json, math, re, shutil, socket, ssl, os
import subprocess, sys, time, urllib.error, urllib.parse, urllib.request
from datetime import datetime, timezone
from pathlib import Path

VERSION = "11.1.0"
# Project root (src/ is the source directory). Runtime state/reports live at project root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASE = PROJECT_ROOT
REPORTS = BASE / "reports"
TIMEOUT = 8
MAX_REQUESTS = 50
MIN_DELAY = 0.20
UA = "Cyber-Terrafor/11.1.0 (Authorized Defensive Assessment)"

from enterprise_engine import tls_posture, web_posture, security_txt, compliance_map, evidence_manifest, executive_posture
from pentest_engine import run_deep_web_pentest
from enterprise_upgrade import (asset_inventory, enterprise_risk, correlate_findings, scan_secrets, container_audit, compliance_matrix, evidence_seal, create_job, dashboard, import_vuln_feed)
from platform_engine import (import_vulnerabilities, vulnerability_lookup, create_remediation, update_remediation, verify_finding, remediation_queue, attack_surface_snapshot, continuous_check, cloud_config_audit, threat_intel_import, threat_intel_lookup, enterprise_dashboard)

DEFAULT_PORTS = [21,22,23,25,53,80,110,143,443,445,587,993,995,3306,3389,5432,6379,8080,8443]

SECURITY_HEADERS = {
    "strict-transport-security":"HSTS",
    "content-security-policy":"CSP",
    "x-content-type-options":"X-Content-Type-Options",
    "x-frame-options":"X-Frame-Options",
    "referrer-policy":"Referrer-Policy",
    "permissions-policy":"Permissions-Policy",
    "cross-origin-opener-policy":"COOP",
    "cross-origin-resource-policy":"CORP",
}

SENSITIVE_PATHS = [
    ".env", ".git/HEAD", ".git/config", "config.php", "wp-config.php",
    "database.yml", "docker-compose.yml", "backup.zip", "backup.tar.gz",
    "backup.sql", "dump.sql", "debug.log", "error.log", ".DS_Store"
]

ERROR_PATTERNS = [
    r"traceback \(most recent call last\)", r"stack trace", r"fatal error",
    r"sql syntax", r"uncaught exception", r"exception in thread"
]

TECH_PATTERNS = {
    # CMS / e-commerce
    "WordPress":[r"/wp-content/",r"/wp-includes/",r"wp-json",r"wordpress"],
    "WooCommerce":[r"woocommerce",r"wc-ajax",r"woocommerce_params"],
    "Drupal":[r"drupalSettings",r"/sites/default/files/",r"x-generator.*drupal"],
    "Joomla":[r"/media/system/js/",r"joomla!",r"content=\"joomla"],
    "Magento / Adobe Commerce":[r"mage/",r"Magento_Ui",r"x-magento-init"],
    "Shopify":[r"cdn.shopify.com",r"Shopify\.theme",r"myshopify.com"],
    "PrestaShop":[r"prestashop",r"prestashop\.js"],
    # Frontend frameworks / runtimes
    "React":[r"react(?:\.production)?\.min\.js",r"data-reactroot",r"react-dom"],
    "Next.js":[r"/_next/",r"__NEXT_DATA__",r"next/router"],
    "Nuxt":[r"/_nuxt/",r"__NUXT__",r"nuxt"],
    "Vue":[r"vue(?:\.min)?\.js",r"data-v-",r"__VUE__"],
    "Angular":[r"ng-version",r"angular(?:\.min)?\.js",r"ng-app"],
    "Svelte / SvelteKit":[r"svelte",r"__svelte",r"/_app/immutable/"],
    "Astro":[r"astro-island",r"/_astro/",r"astro"],
    "Ember.js":[r"ember(?:\.min)?\.js",r"ember-view"],
    "Backbone.js":[r"backbone(?:\.min)?\.js"],
    "jQuery":[r"jquery(?:\.min)?\.js"],
    "Bootstrap":[r"bootstrap(?:\.min)?\.(?:css|js)"],
    "Tailwind CSS":[r"tailwindcss",r"cdn.tailwindcss.com"],
    "TypeScript":[r"typescript",r"tslib"],
    # Backend / server fingerprints
    "Node.js / Express":[r"x-powered-by: *express",r"express",r"connect.sid"],
    "NestJS":[r"nestjs",r"nestfactory"],
    "Django":[r"csrfmiddlewaretoken",r"django",r"csrftoken"],
    "Flask":[r"werkzeug",r"flask"],
    "FastAPI":[r"fastapi",r"starlette",r"application/json.*fastapi"],
    "Laravel":[r"laravel_session",r"laravel",r"csrf-token"],
    "Symfony":[r"symfony",r"_wdt",r"_profiler"],
    "Ruby on Rails":[r"rails",r"_rails_session",r"action_dispatch"],
    "Spring Boot":[r"whitelabel error page",r"spring",r"jsessionid"],
    "ASP.NET / .NET":[r"aspnetcore",r"asp.net",r"__viewstate",r"\.aspx"],
    "PHP":[r"x-powered-by: *php",r"phpsessid",r"\.php(?:[?\"'])"],
    "Go":[r"go-http-client",r"net/http",r"gin-gonic"],
    "Rust":[r"actix-web",r"rocket",r"axum"],
    # API / realtime
    "GraphQL":[r"graphql",r"__schema",r"apollo",r"hasura"],
    "WebSocket":[r"websocket",r"socket\.io",r"sockjs"],
    "gRPC":[r"grpc",r"grpc-web"],
    # Infra / CDN / WAF
    "Cloudflare":[r"cf-ray",r"cloudflare",r"__cf_bm"],
    "AWS":[r"amazonaws.com",r"x-amz-",r"awselb"],
    "Azure":[r"azurewebsites.net",r"x-azure-ref",r"microsoft"],
    "Google Cloud":[r"googleusercontent.com",r"x-cloud-trace-context",r"appspot.com"],
    "Vercel":[r"x-vercel",r"vercel",r"vercel.app"],
    "Netlify":[r"netlify",r"netlify.app",r"x-nf-request-id"],
    "Render":[r"onrender.com",r"render.com"],
    "Nginx":[r"server: *nginx"],
    "Apache":[r"server: *apache"],
    "IIS":[r"server: *microsoft-iis",r"asp.net"],
    "Caddy":[r"server: *caddy"],
}

TECH_PROFILES = {
    "WordPress":{"checks":["wp-json","wp-login.php","wp-admin/"],"notes":"Review CMS/plugin/theme exposure and version hygiene."},
    "WooCommerce":{"checks":["wc-ajax","wp-json/wc/"],"notes":"Review e-commerce API, cookies, checkout and webhook exposure."},
    "Drupal":{"checks":["core/","sites/default/files/"],"notes":"Review Drupal core/modules, exposed files and configuration."},
    "Joomla":{"checks":["administrator/","api/index.php/v1/"],"notes":"Review Joomla administrator/API exposure and extension hygiene."},
    "Magento / Adobe Commerce":{"checks":["graphql","rest/V1/","static/version"],"notes":"Review Magento API, static assets and admin exposure."},
    "Shopify":{"checks":["/products.json","/collections.json"],"notes":"Review public storefront/API surface; platform-managed server security is not inferred."},
    "Next.js":{"checks":["/_next/","/api/"],"notes":"Review server/client boundary, API routes, source maps and framework headers."},
    "Nuxt":{"checks":["/_nuxt/","/api/"],"notes":"Review SSR/SPA payload exposure and API routes."},
    "Django":{"checks":["/admin/","/static/"],"notes":"Review admin exposure, CSRF, debug configuration and static/media paths."},
    "Laravel":{"checks":["/storage/","/api/"],"notes":"Review APP_DEBUG indicators, storage exposure and session/cookie posture."},
    "Spring Boot":{"checks":["/actuator/health","/actuator/info"],"notes":"Review management/actuator exposure and production error handling."},
    "ASP.NET / .NET":{"checks":["/swagger","/swagger/index.html"],"notes":"Review API documentation exposure and framework configuration."},
    "GraphQL":{"checks":["/graphql","/api/graphql"],"notes":"Review endpoint exposure, error leakage and authorization controls."},
    "Node.js / Express":{"checks":["/api/","/health","/metrics"],"notes":"Review Express headers, API exposure and production error handling."},
    "PHP":{"checks":["/composer.json","/phpinfo.php"],"notes":"Review accidental diagnostics, dependency manifests and PHP headers."},
}

def stamp():
    return datetime.now(timezone.utc).isoformat()

def clear():
    print("\033[2J\033[H", end="")

def banner():
    print("\033[1;36m╔════════════════════════════════════════════════════════════╗")
    print("║\033[1;97m                  CYBER TERRAFOR v11.1.0                         \033[1;36m║")
    print("║\033[1;33m             AUTHORIZED SECURITY ASSESSMENT              \033[1;36m║")
    print("╚════════════════════════════════════════════════════════════╝\033[0m")
    print("\033[0;90m Safe-by-design: network actions require explicit scope.\033[0m")

def save_report(name, data):
    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / (datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + name + ".json")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print("\033[1;32m[+] Report:\033[0m", path.relative_to(BASE))
    return data

def normalize_url(value):
    value = value.strip()
    if not urllib.parse.urlparse(value).scheme:
        value = "https://" + value
    p = urllib.parse.urlparse(value)
    if p.scheme not in ("http","https") or not p.hostname:
        raise ValueError("Only valid http/https URLs are supported.")
    return value

def urlparse_host(url):
    p = urllib.parse.urlparse(normalize_url(url))
    return p.hostname or ""

def scope_entries(path):
    if isinstance(path, dict):
        return list(path.get("hosts", set())) + list(path.get("wildcards", set())) + list(path.get("cidrs", []))
    p = Path(path)
    if not p.exists():
        raise ValueError("Scope file not found: " + str(p))
    return [
        x.split("#",1)[0].strip().lower().rstrip(".")
        for x in p.read_text(errors="ignore").splitlines()
        if x.strip() and not x.lstrip().startswith("#")
    ]

def host_ok(host, entries):
    host = host.lower().rstrip(".")
    try:
        hip = ipaddress.ip_address(host)
    except ValueError:
        hip = None
    for entry in entries:
        if entry == "*":
            return True
        if entry.startswith("*.") and (host == entry[2:] or host.endswith("." + entry[2:])):
            return True
        if host == entry:
            return True
        try:
            if hip and hip in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            pass
    return False

def require_scope(target, scope):
    if not scope:
        raise PermissionError("Network action blocked. Add --scope scope.txt")
    if isinstance(scope, dict):
        entries = list(scope.get("hosts", set())) + list(scope.get("wildcards", set())) + list(scope.get("cidrs", []))
    else:
        entries = scope_entries(scope)
    u = urllib.parse.urlparse(target if "://" in target else "//" + target)
    host = u.hostname or target.split("/")[0].split(":")[0]
    if not host_ok(host, entries):
        raise PermissionError(f"Target '{host}' is not in {scope}")
    return host

def fetch(url, method="GET", timeout=TIMEOUT, max_bytes=300000):
    req = urllib.request.Request(url, method=method, headers={"User-Agent":UA,"Accept":"*/*"})
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.URLError as exc:
        # Preserve TLS verification errors as structured scanner observations.
        raise
    body = b"" if method == "HEAD" else r.read(max_bytes)
    return r, body

def finding(severity, title, evidence, remediation, module="General", confidence="medium", verification="OBSERVED", location=None, impact=None):
    """Create an evidence-backed finding without pretending an observation is an exploit confirmation."""
    return {"severity": severity, "title": title, "evidence": evidence, "remediation": remediation,
            "module": module, "confidence": confidence, "verification": verification,
            "location": location, "impact": impact}

def risk(findings):
    """
    Finding-aware risk scoring.
    Each finding contributes according to severity, confidence, exploitability,
    and exposure. Duplicate observations are deduplicated before scoring.
    The score is NOT reused between modules.
    """
    severity_weight = {
        "critical": 25.0,
        "high": 15.0,
        "medium": 8.0,
        "low": 3.0,
        "info": 0.0,
    }
    confidence_weight = {
        "confirmed": 1.0,
        "high": 1.0,
        "medium": 0.75,
        "low": 0.5,
        "unknown": 0.5,
    }
    exploit_weight = {
        "critical": 1.25,
        "high": 1.10,
        "medium": 0.90,
        "low": 0.60,
        "info": 0.0,
    }

    unique = []
    seen = set()
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        key = (
            str(f.get("severity","info")).lower(),
            str(f.get("title","")).strip().lower(),
            str(f.get("location", f.get("url",""))).strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)

    raw = 0.0
    contributions = []
    for f in unique:
        sev = str(f.get("severity","info")).lower()
        conf = str(f.get("confidence","medium")).lower()
        weight = severity_weight.get(sev, 0.0)
        multiplier = confidence_weight.get(conf, 0.75)
        multiplier *= exploit_weight.get(sev, 0.75)

        # Optional explicit factors, bounded to avoid arbitrary inflation.
        for field in ("exposure_factor", "exploitability_factor", "impact_factor"):
            try:
                multiplier *= min(1.25, max(0.50, float(f.get(field, 1.0))))
            except Exception:
                pass

        contribution = weight * multiplier
        raw += contribution
        contributions.append({
            "title": f.get("title","Finding"),
            "severity": sev,
            "confidence": conf,
            "contribution": round(contribution, 2),
        })

    # Cap at 100 while preserving meaningful differences.
    score = round(min(100.0, raw), 1)
    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    elif score > 0:
        level = "LOW"
    else:
        level = "INFO"

    return score, level, {
        "raw_score": round(raw, 2),
        "unique_findings": len(unique),
        "contributions": contributions,
    }

def hashes(path):
    p = Path(path)
    if not p.is_file():
        raise ValueError("File not found: " + str(p))
    hs = {x:hashlib.new(x) for x in ("md5","sha1","sha256","sha512")}
    total = 0
    with p.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024), b""):
            total += len(chunk)
            for h in hs.values():
                h.update(chunk)
    return {"file":str(p),"size":total,**{k:v.hexdigest() for k,v in hs.items()}}

def entropy(data):
    if not data: return 0.0
    freq = [0]*256
    for b in data: freq[b] += 1
    n = len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def malware_analyze(path):
    p = Path(path)
    meta = hashes(p)
    raw = p.read_bytes()[:2000000]
    low = raw.lower()
    indicators = []
    if raw[:2] == b"MZ": indicators.append("PE executable signature")
    if raw[:4] == b"\x7fELF": indicators.append("ELF executable signature")
    if len(raw) > 4096 and entropy(raw) > 7.2: indicators.append("high entropy content")
    for token in (b"powershell -enc",b"eval(",b"base64_decode(",b"cmd.exe /c",b"wget http",b"curl http"):
        if token in low: indicators.append(token.decode(errors="ignore"))
    meta["entropy"] = round(entropy(raw),4)
    meta["indicators"] = sorted(set(indicators))
    meta["risk"] = "HIGH" if len(indicators)>=3 else "MEDIUM" if indicators else "LOW"
    meta["yara_available"] = bool(shutil.which("yara"))
    print("\n\033[1;36mMalware & Suspicious File Analysis\033[0m")
    for k,v in meta.items(): print(f" {k}: {v}")
    return save_report("malware_analysis",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"analysis":meta})

def dns(host, scope):
    host = require_scope(host,scope)
    ips = sorted({x[4][0] for x in socket.getaddrinfo(host,None)})
    rows = []
    for ip in ips:
        try: rev = socket.gethostbyaddr(ip)[0]
        except Exception: rev = None
        rows.append({"ip":ip,"reverse_dns":rev})
    print("\n\033[1;36mDNS / Address Resolution\033[0m",host)
    for row in rows: print(" ",row["ip"],"->",row["reverse_dns"] or "no PTR")
    return save_report("dns",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":host,"addresses":ips,"details":rows})

def geoip(host, scope):
    host = require_scope(host,scope)
    ip = socket.gethostbyname(host)
    data = {"ip":ip}
    try:
        _, body = fetch("https://ipwho.is/" + urllib.parse.quote(ip),timeout=6,max_bytes=30000)
        obj = json.loads(body.decode("utf-8","replace"))
        conn = obj.get("connection") or {}
        data.update(country=obj.get("country"),region=obj.get("region"),city=obj.get("city"),
                    latitude=obj.get("latitude"),longitude=obj.get("longitude"),
                    isp=conn.get("isp"),organization=conn.get("org"),asn=conn.get("asn"))
    except Exception as e:
        data["lookup_error"] = str(e)
    data["note"] = "GeoIP is approximate; it is not precise real-time physical tracking."
    for k,v in data.items(): print(f" {k}: {v}")
    return save_report("geoip",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":host,"result":data})

def tls(host, scope, port=443):
    host=require_scope(host,scope)
    result=tls_posture(host,port,scope,finding)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":host,"port":port,**result}
    score,level,risk_meta=risk(result.get("findings",[])); data.update(risk_score=score,risk=level,risk_analysis=risk_meta)
    return save_report("tls",data)

def tech_detect(headers, body):
    text = body.decode("utf-8","replace") if isinstance(body,(bytes,bytearray)) else str(body)
    header_text = "\n".join(f"{k}:{v}" for k,v in headers.items())
    hay = (text + "\n" + header_text).lower()
    found = []
    for tech,pats in TECH_PATTERNS.items():
        hits=[p for p in pats if re.search(p,hay,re.I)]
        if hits: found.append(tech)
    return sorted(set(found))

def technology_profile(url, scope, r=None, body=None):
    url=normalize_url(url); require_scope(url,scope)
    if r is None or body is None: r,body=fetch(url,timeout=TIMEOUT,max_bytes=600000)
    h={k.lower():v for k,v in r.headers.items()}
    text=body.decode("utf-8","replace") if isinstance(body,(bytes,bytearray)) else str(body)
    tech=tech_detect(h,body)
    evidence={}
    for t in tech:
        pats=TECH_PATTERNS.get(t,[])
        evidence[t]=[p for p in pats if re.search(p,text+"\n"+"\n".join(f"{k}:{v}" for k,v in h.items()),re.I)][:8]
    recommendations=[]
    for t in tech:
        if t in TECH_PROFILES: recommendations.append({"technology":t,**TECH_PROFILES[t]})
    return {"detected":tech,"evidence":evidence,"recommendations":recommendations,
            "server":h.get("server"),"powered_by":h.get("x-powered-by"),
            "content_type":h.get("content-type"),"status":r.status}

def parse_links(base, body):
    text = body.decode("utf-8","replace")
    links = set()
    pattern = r'(?:href|src)\s*=\s*["\']([^"\']+)["\']'
    for m in re.finditer(pattern,text,re.I):
        u = urllib.parse.urljoin(base,m.group(1))
        if urllib.parse.urlparse(u).scheme in ("http","https"): links.add(u)
    return sorted(links)

def header_findings(headers, https):
    result, findings = {}, []
    for key,label in SECURITY_HEADERS.items():
        ok = key in headers
        result[label] = ok
        if not ok:
            sev = "medium" if label in ("HSTS","CSP") and https else "low"
            findings.append(finding(sev,"Missing "+label,"Response header not present","Configure "+label+"."))
    return result,findings

def cookie_findings(headers):
    raw = headers.get("set-cookie","")
    if not raw: return []
    out=[]
    if "secure" not in raw.lower(): out.append(finding("medium","Cookie without Secure","Set-Cookie lacks Secure","Set Secure on security-sensitive cookies."))
    if "httponly" not in raw.lower(): out.append(finding("medium","Cookie without HttpOnly","Set-Cookie lacks HttpOnly","Set HttpOnly on session cookies where appropriate."))
    if "samesite" not in raw.lower(): out.append(finding("low","Cookie without SameSite","Set-Cookie lacks SameSite","Set an appropriate SameSite policy."))
    return out

def web_audit(url, scope, deep=True):
    url = normalize_url(url)
    require_scope(url,scope)
    findings=[]
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url}
    print("\n\033[1;36mAdvanced Web Security Audit\033[0m",url)
    try:
        r,body = fetch(url)
        headers={k.lower():v for k,v in r.headers.items()}
        final=r.geturl()
        data.update(status=r.status,final_url=final,headers=dict(headers),
                    content_type=headers.get("content-type"),technologies=tech_detect(headers,body))
        data["technology_profile"]=technology_profile(final,scope,r,body)
        sh,f = header_findings(headers,urllib.parse.urlparse(final).scheme=="https")
        data["security_headers"]=sh
        findings += f + cookie_findings(headers)
        for pat in ERROR_PATTERNS:
            if re.search(pat,body.decode("utf-8","replace"),re.I):
                findings.append(finding("medium","Verbose error information indicator",pat,"Disable verbose errors in production."))
        links=parse_links(final,body)
        host=urllib.parse.urlparse(final).hostname
        same=[x for x in links if urllib.parse.urlparse(x).hostname==host]
        data["links_sample"]=same[:100]
        print(" HTTP status:",r.status)
        print(" Final URL:",final)
        print(" Technologies:",", ".join(data["technologies"]) or "not detected")
        print(" Same-origin links:",len(same))
        for label,ok in sh.items():
            print(f" {label:28}", "\033[1;32mOK\033[0m" if ok else "\033[1;33mMISSING\033[0m")
        if "server" in headers: data["server_header"]=headers["server"]
        if deep:
            for name,path in (("robots","/robots.txt"),("sitemap","/sitemap.xml")):
                try:
                    rr,bb=fetch(urllib.parse.urljoin(final,path),timeout=5,max_bytes=10000)
                    data[name]={"status":rr.status,"size":len(bb),"preview":bb.decode("utf-8","replace")[:5000]}
                except Exception:
                    data[name]={"status":"unavailable"}
            checks=[]
            for name in SENSITIVE_PATHS:
                u=urllib.parse.urljoin(final,"/"+name)
                try:
                    rr,_=fetch(u,method="HEAD",timeout=4,max_bytes=0)
                    checks.append({"url":u,"status":rr.status})
                    if rr.status < 400:
                        findings.append(finding("medium","Potentially sensitive public resource",u,"Restrict or remove if not intentionally public."))
                except urllib.error.HTTPError as e:
                    checks.append({"url":u,"status":e.code})
                except Exception:
                    pass
                time.sleep(MIN_DELAY)
            data["sensitive_resource_checks"]=checks
            health=[]
            for link in same[:30]:
                try:
                    rr,_=fetch(link,method="HEAD",timeout=4,max_bytes=0)
                    health.append({"url":link,"status":rr.status})
                    if rr.status >= 500:
                        findings.append(finding("medium","Server error on public endpoint",f"{rr.status} {link}","Review application/server error handling."))
                except Exception as e:
                    health.append({"url":link,"error":str(e)[:120]})
                time.sleep(MIN_DELAY)
            data["endpoint_health"]=health
    except urllib.error.HTTPError as e:
        data["status"]=e.code
        findings.append(finding("medium","HTTP error response",str(e),"Review endpoint and error handling."))
    except Exception as e:
        data["error"]=str(e)
        findings.append(finding("high","Web audit failed",str(e),"Verify target, DNS, TLS and scope."))
    score, level, risk_meta = risk(findings)
    data["findings"]=findings
    data["risk_score"]=score
    data["risk"]=level
    save_report("web_audit",data)
    return data



def security_headers_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=2000); h={k.lower():v for k,v in r.headers.items()}
    sh,findings=header_findings(h,urllib.parse.urlparse(r.geturl()).scheme=="https")
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"status":r.status,"headers":h,"security_headers":sh,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("security_headers",data)

def technology_fingerprint(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,b=fetch(url,timeout=TIMEOUT,max_bytes=600000)
    profile=technology_profile(r.geturl(),scope,r,b)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,
          "final_url":r.geturl(),"status":r.status,"technology_profile":profile}
    print("\n\033[1;36mTechnology Intelligence / Adaptive Stack Detection\033[0m",url)
    print(" Detected:", ", ".join(profile["detected"]) or "Unknown / no reliable fingerprint")
    for t in profile["detected"]: print("  -",t,"| evidence:",", ".join(profile["evidence"].get(t,[])[:3]))
    return save_report("technology_fingerprint",data)

def adaptive_site_analysis(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,b=fetch(url,timeout=TIMEOUT,max_bytes=700000)
    profile=technology_profile(r.geturl(),scope,r,b)
    findings=[]; checks=[]
    base=r.geturl()
    # Passive, scope-safe probes selected from detected technologies. No mutation or credentials.
    for rec in profile["recommendations"]:
        for path in rec["checks"][:4]:
            u=urllib.parse.urljoin(base,path)
            try:
                require_scope(u,scope); rr,_=fetch(u,method="HEAD",timeout=4,max_bytes=0)
                if rr.status in (405,501): rr,_=fetch(u,method="GET",timeout=4,max_bytes=120)
                row={"technology":rec["technology"],"path":path,"url":u,"status":rr.status}
                if rr.status < 400: row["reachable"]=True
                checks.append(row)
            except urllib.error.HTTPError as e: checks.append({"technology":rec["technology"],"path":path,"url":u,"status":e.code})
            except Exception as e: checks.append({"technology":rec["technology"],"path":path,"url":u,"error":str(e)[:160]})
            time.sleep(MIN_DELAY)
    if not profile["detected"]:
        findings.append(finding("info","Technology stack not reliably fingerprinted","No strong technology signature observed","Continue with generic HTTP, TLS, API and configuration analysis; avoid assuming an unknown stack."))
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,
          "status":r.status,"technology_profile":profile,"adaptive_checks":checks,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    result=save_report("adaptive_site_analysis",data)
    try: article_summary(result, "Cyber Terrafor Adaptive Technology Analysis")
    except Exception as e: print("[!] Article summary generation failed:",e)
    return result

def vulnerability_assessment(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,b=fetch(url,timeout=TIMEOUT,max_bytes=500000); h={k.lower():v for k,v in r.headers.items()}; text=b.decode("utf-8","replace"); findings=[]
    sh,f=header_findings(h,urllib.parse.urlparse(r.geturl()).scheme=="https"); findings += f + cookie_findings(h)
    patterns=[(r"(?i)sql syntax.*mysql|mysql_fetch|ora-\d{4,}|postgresql.*error","Possible database error disclosure"),(r"(?i)traceback \(most recent call last\)|stack trace|debug=true","Debug/stack trace indicator"),(r"(?i)directory listing|index of /","Directory listing indicator")]
    for pat,title in patterns:
        if re.search(pat,text): findings.append(finding("medium",title,"Response body matched a passive indicator","Review production error handling and disable unintended debug output."))
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"status":r.status,"security_headers":sh,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("vulnerability_assessment",data)

def broken_link_endpoint_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,b=fetch(url,timeout=TIMEOUT,max_bytes=400000); base=r.geturl(); host=urllib.parse.urlparse(base).hostname
    links=[u for u in parse_links(base,b) if urllib.parse.urlparse(u).hostname==host][:60]; rows=[]; findings=[]
    for u in links:
        try:
            rr,_=fetch(u,method="HEAD",timeout=4,max_bytes=0); row={"url":u,"status":rr.status}
            if rr.status in (405,501):
                rr,_=fetch(u,method="GET",timeout=4,max_bytes=100); row["fallback_status"]=rr.status
            if row.get("fallback_status",row["status"])>=500: findings.append(finding("medium","Server error on linked endpoint",f"{row.get('fallback_status',row['status'])} {u}","Review endpoint error handling."))
        except Exception as e: row={"url":u,"error":str(e)[:180]}
        rows.append(row); time.sleep(MIN_DELAY)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"links_checked":len(rows),"results":rows,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("broken_links",data)

def sensitive_object_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope); findings=[]; rows=[]
    for name in SENSITIVE_PATHS:
        u=urllib.parse.urljoin(url,"/"+name)
        try:
            rr,_=fetch(u,method="HEAD",timeout=4,max_bytes=0); row={"url":u,"status":rr.status};
            if rr.status < 400: findings.append(finding("medium","Potentially sensitive public object",u,"Restrict or remove the resource if it is not intentionally public."))
        except urllib.error.HTTPError as e: row={"url":u,"status":e.code}
        except Exception as e: row={"url":u,"error":str(e)[:160]}
        rows.append(row); time.sleep(MIN_DELAY)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"results":rows,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("sensitive_objects",data)

def error_misconfiguration_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope); r,b=fetch(url,timeout=TIMEOUT,max_bytes=400000); h={k.lower():v for k,v in r.headers.items()}; text=b.decode("utf-8","replace"); findings=[]
    checks={"server_banner":h.get("server"),"powered_by":h.get("x-powered-by"),"debug_indicator":bool(re.search(r"(?i)debug|traceback|stack trace|exception",text)),"directory_listing":bool(re.search(r"(?i)directory listing|index of /",text))}
    if checks["server_banner"]: findings.append(finding("low","Server banner disclosed",checks["server_banner"],"Minimize unnecessary version disclosure."))
    if checks["powered_by"]: findings.append(finding("low","Framework banner disclosed",checks["powered_by"],"Remove unnecessary framework disclosure."))
    if checks["debug_indicator"]: findings.append(finding("medium","Debug/error indicator in response","Passive response-body indicator detected","Disable verbose/debug output in production."))
    if checks["directory_listing"]: findings.append(finding("medium","Directory listing indicator","Response resembles a directory index","Disable directory indexing where unnecessary."))
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"status":r.status,"checks":checks,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("error_misconfiguration",data)

def security_configuration_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope); r,_=fetch(url,timeout=TIMEOUT,max_bytes=2000); h={k.lower():v for k,v in r.headers.items()}; findings=[]
    sh,f=header_findings(h,urllib.parse.urlparse(r.geturl()).scheme=="https"); findings += f + cookie_findings(h)
    config={"https":urllib.parse.urlparse(r.geturl()).scheme=="https","headers":sh,"cookie_security":bool(h.get("set-cookie"))}
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"status":r.status,"configuration":config,"findings":findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("security_configuration",data)

def ssl_certificate_intelligence(url, scope):
    url=normalize_url(url); host=require_scope(url,scope)
    result=tls_posture(host,443,scope,finding)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"host":host,"certificate":result.get("certificate",{}),"verification":result.get("verification"),"protocols":result.get("protocols",{}),"errors":result.get("errors",[]),"findings":result.get("findings",[])}
    score,level,risk_meta=risk(data["findings"]); data.update(risk_score=score,risk=level,risk_analysis=risk_meta)
    return save_report("ssl_certificate",data)

def robots_sitemap_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope); results={}; findings=[]
    for path in ("/robots.txt","/sitemap.xml"):
        u=urllib.parse.urljoin(url,path)
        try:
            rr,bb=fetch(u,timeout=5,max_bytes=50000); results[path]={"url":u,"status":rr.status,"content_type":rr.headers.get("Content-Type"),"preview":bb.decode("utf-8","replace")[:10000]}
            if path=="/robots.txt" and rr.status==200 and re.search(r"(?i)disallow:\s*/(?:admin|private|backup|\.git)",bb.decode("utf-8","replace")): findings.append(finding("info","Sensitive path referenced by robots.txt","Robots file references a potentially sensitive path","Treat robots.txt as public metadata, not an access-control mechanism."))
        except Exception as e: results[path]={"url":u,"error":str(e)}
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"results":results,"findings":findings}; score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("robots_sitemap",data)

def redirect_security_audit(url, scope):
    current=normalize_url(url); require_scope(current,scope); chain=[]; findings=[]
    for i in range(10):
        require_scope(current,scope)
        try:
            rr,_=fetch(current,timeout=TIMEOUT,max_bytes=100); nxt=rr.geturl(); chain.append({"step":i+1,"url":current,"status":rr.status,"final_url":nxt})
            if nxt==current: break
            require_scope(nxt,scope); current=nxt
        except Exception as e: chain.append({"step":i+1,"url":current,"error":str(e)}); break
    if len(chain)>5: findings.append(finding("low","Long redirect chain",f"{len(chain)} hops observed","Reduce unnecessary redirects."))
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"chain":chain,"final_url":current,"findings":findings}; score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    return save_report("redirect_security",data)

def fetch_text(url, scope, max_bytes=300000, timeout=TIMEOUT):
    url = normalize_url(url)
    require_scope(url, scope)
    r, body = fetch(url, timeout=timeout, max_bytes=max_bytes)
    return r, body

def subdomain_intelligence(url, scope):
    url = normalize_url(url); host = require_scope(url, scope)
    data = {"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"host":host,"subdomains":[],"sources":[]}
    candidates = set()
    try:
        r, body = fetch(url, timeout=6, max_bytes=200000)
        text = body.decode("utf-8","replace")
        for m in re.findall(r"(?:https?:)?//([A-Za-z0-9.-]+)", text):
            h = m.lower().rstrip('.')
            if h == host or h.endswith('.' + host): candidates.add(h)
        data["sources"].append("page_links")
        cert = ssl.create_default_context().wrap_socket(socket.socket(), server_hostname=host)
        cert.settimeout(TIMEOUT); cert.connect((host,443)); obj=cert.getpeercert(); cert.close()
        for kind,name in obj.get("subjectAltName",[]):
            if kind == "DNS" and (name.lower().rstrip('.') == host or name.lower().endswith('.'+host)):
                candidates.add(name.lower().lstrip('*.').rstrip('.'))
        data["sources"].append("tls_certificate_san")
    except Exception as e:
        data["errors"]=[str(e)]
    entries=scope_entries(scope)
    data["subdomains"] = sorted(x for x in candidates if host_ok(x, entries))
    print("\n\033[1;36mSubdomain Intelligence\033[0m",host)
    for x in data["subdomains"]: print(" ",x)
    if not data["subdomains"]: print("  No in-scope subdomains discovered from passive sources.")
    return save_report("subdomain_intelligence",data)

def api_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r, body = fetch(url, timeout=TIMEOUT, max_bytes=300000)
    headers={k.lower():v for k,v in r.headers.items()}
    text=body.decode('utf-8','replace')
    endpoints=[]
    for u in parse_links(r.geturl(), body):
        path=urllib.parse.urlparse(u).path.lower()
        if any(x in path for x in ('/api/','/graphql','/rest/','/v1/','/v2/')):
            endpoints.append(u)
    endpoints=sorted(set(endpoints))[:50]
    findings=[]
    if 'authorization' not in headers and any(x in text.lower() for x in ('/api/','graphql')):
        findings.append(finding('info','API indicators detected','Page references API-style endpoints','Review authentication and authorization controls for each API.'))
    if 'access-control-allow-origin' in headers and headers['access-control-allow-origin'].strip() == '*':
        findings.append(finding('medium','Permissive API CORS policy','Access-Control-Allow-Origin: *','Restrict origins where sensitive API data is exposed.'))
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'status':r.status,'api_endpoints':endpoints,'findings':findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mAPI Security Audit\033[0m",url)
    print(' API-style endpoints:',len(endpoints)); print(' CORS:',headers.get('access-control-allow-origin','not advertised'))
    return save_report('api_security',data)

def cookie_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=100)
    headers={k.lower():v for k,v in r.headers.items()}
    raw=r.headers.get_all('Set-Cookie') or []
    findings=[]; rows=[]
    for c in raw:
        low=c.lower(); name=c.split('=',1)[0].strip()
        row={'name':name,'secure':'secure' in low,'httponly':'httponly' in low,'samesite':re.search(r'samesite=([^;]+)',low).group(1) if re.search(r'samesite=([^;]+)',low) else None}
        rows.append(row)
        if not row['secure']: findings.append(finding('medium','Cookie missing Secure',name,'Use Secure for cookies carrying sensitive state over HTTPS.'))
        if not row['httponly']: findings.append(finding('medium','Cookie missing HttpOnly',name,'Use HttpOnly for session cookies when JavaScript access is unnecessary.'))
        if not row['samesite']: findings.append(finding('low','Cookie missing SameSite',name,'Set an appropriate SameSite policy.'))
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'cookies':rows,'findings':findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mCookie Security Audit\033[0m",url)
    print(' Cookies:',len(rows))
    for x in rows: print(' ',x['name'], 'Secure='+str(x['secure']), 'HttpOnly='+str(x['httponly']), 'SameSite='+str(x['samesite']))
    return save_report('cookie_security',data)

def cors_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=100)
    h={k.lower():v for k,v in r.headers.items()}; findings=[]
    origin=h.get('access-control-allow-origin')
    creds=h.get('access-control-allow-credentials','').lower()
    if origin=='*': findings.append(finding('medium','Wildcard CORS origin','Access-Control-Allow-Origin: *','Restrict cross-origin access for sensitive resources.'))
    if origin and origin!='*' and creds=='true': findings.append(finding('info','Credentialed CORS enabled',f'{origin} with credentials=true','Ensure the allowed origin is a trusted application origin.'))
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'cors':{k:v for k,v in h.items() if k.startswith('access-control-')},'findings':findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mCORS Security Audit\033[0m",url)
    print(' Allow-Origin:',origin or 'not advertised'); print(' Allow-Credentials:',creds or 'not advertised')
    return save_report('cors_security',data)

def javascript_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); links=parse_links(r.geturl(),body)
    text=body.decode('utf-8','replace'); scripts=[]
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)',text,re.I):
        u=urllib.parse.urljoin(r.geturl(),m.group(1));
        if urllib.parse.urlparse(u).scheme in ('http','https') and host_ok(urllib.parse.urlparse(u).hostname or '',scope_entries(scope)): scripts.append(u)
    indicators=[]
    for pat,label in [(r'(?i)sourceMappingURL=','source map reference'),(r'(?i)(api[_-]?key|client[_-]?secret)\s*[:=]','possible exposed configuration key'),(r'(?i)eval\s*\(','eval usage indicator')]:
        if re.search(pat,text): indicators.append(label)
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'scripts':sorted(set(scripts))[:100],'indicators':indicators,'findings':[]}
    if 'source map reference' in indicators: data['findings'].append(finding('low','Source map reference detected','JavaScript references a source map','Review whether production source maps should be publicly accessible.'))
    if 'possible exposed configuration key' in indicators: data['findings'].append(finding('medium','Possible exposed client configuration','JavaScript contains a key-like configuration pattern','Verify no secret credential is embedded in client-side code.'))
    score, level, risk_meta = risk(data['findings']); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mJavaScript Security Audit\033[0m",url); print(' Scripts:',len(data['scripts'])); print(' Indicators:',', '.join(indicators) or 'none')
    return save_report('javascript_security',data)

def cloud_exposure_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); text=body.decode('utf-8','replace')
    patterns=[r'https?://[A-Za-z0-9._-]+\.s3(?:[-.][A-Za-z0-9.-]+)?\.amazonaws\.com[^\s"\']*',r'https?://storage\.googleapis\.com/[^\s"\']+',r'https?://[A-Za-z0-9.-]+\.blob\.core\.windows\.net[^\s"\']*']
    matches=[]
    for pat in patterns: matches += re.findall(pat,text,re.I)
    findings=[]
    if matches: findings.append(finding('medium','Public cloud resource reference detected',', '.join(sorted(set(matches))[:10]),'Verify referenced cloud objects are intentionally public and access-controlled.'))
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'cloud_references':sorted(set(matches))[:50],'findings':findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mCloud Exposure Audit\033[0m",url); print(' Cloud references:',len(data['cloud_references']))
    return save_report('cloud_exposure',data)

def waf_cdn_detection(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,timeout=TIMEOUT,max_bytes=100); h={k.lower():v for k,v in r.headers.items()}
    signals=[]
    if 'cf-ray' in h or 'cloudflare' in h.get('server','').lower(): signals.append('Cloudflare')
    if 'x-amz-cf-id' in h or 'cloudfront' in h.get('via','').lower(): signals.append('Amazon CloudFront')
    if 'x-sucuri-id' in h or 'sucuri' in h.get('server','').lower(): signals.append('Sucuri')
    if 'akamai' in h.get('server','').lower() or 'akamai' in h.get('via','').lower(): signals.append('Akamai')
    if 'x-cache' in h: signals.append('Generic cache/CDN signal')
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'detected':sorted(set(signals)),'evidence':{k:v for k,v in h.items() if k in ('server','via','cf-ray','x-amz-cf-id','x-sucuri-id','x-cache')}}
    print("\n\033[1;36mWAF / CDN Detection\033[0m",url); print(' Detected:',', '.join(data['detected']) or 'not detected')
    return save_report('waf_cdn',data)

def authentication_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); text=body.decode('utf-8','replace'); findings=[]
    forms=re.findall(r'<form\b[^>]*>(.*?)</form>',text,re.I|re.S)
    password_forms=sum(1 for f in forms if re.search(r'type=["\']password["\']',f,re.I))
    auth_links=[x for x in parse_links(r.geturl(),body) if re.search(r'(login|signin|auth|account|session)',x,re.I)][:30]
    if password_forms and urllib.parse.urlparse(r.geturl()).scheme!='https': findings.append(finding('high','Password form served over HTTP','Password input detected on non-HTTPS page','Serve authentication forms only over HTTPS.'))
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'password_forms':password_forms,'auth_links':auth_links,'findings':findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mAuthentication Security Audit\033[0m",url); print(' Password forms:',password_forms); print(' Auth-related links:',len(auth_links))
    return save_report('authentication_security',data)

def api_endpoint_discovery(url, scope):
    url=normalize_url(url); require_scope(url,scope); r,body=fetch(url,timeout=TIMEOUT,max_bytes=500000); base=r.geturl(); text=body.decode('utf-8','replace')
    endpoints=set()
    for u in parse_links(base,body):
        if host_ok(urllib.parse.urlparse(u).hostname or '',scope_entries(scope)) and re.search(r'/(api|graphql|rest|v\d+)(?:/|$)',urllib.parse.urlparse(u).path,re.I): endpoints.add(u)
    for m in re.findall(r'["\']((?:/|https?://)[A-Za-z0-9_./?=&%-]*(?:api|graphql|rest|v1|v2)[A-Za-z0-9_./?=&%-]*)["\']',text,re.I):
        u=urllib.parse.urljoin(base,m)
        if host_ok(urllib.parse.urlparse(u).hostname or '',scope_entries(scope)): endpoints.add(u)
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'endpoints':sorted(endpoints)[:100]}
    print("\n\033[1;36mAPI Endpoint Discovery\033[0m",url); print(' Endpoints:',len(data['endpoints']))
    for x in data['endpoints'][:30]: print(' ',x)
    return save_report('api_endpoints',data)

def dependency_cve_intelligence(url, scope):
    url=normalize_url(url); require_scope(url,scope); r,body=fetch(url,timeout=TIMEOUT,max_bytes=400000); h={k.lower():v for k,v in r.headers.items()}; text=body.decode('utf-8','replace')
    candidates=[]
    patterns=[('WordPress',r'(?i)wp(?:-|_)?version["\']?\s*[:=]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),('jQuery',r'(?i)jquery(?:-|\.)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'),('Bootstrap',r'(?i)bootstrap(?:-|\.)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)')]
    for name,pat in patterns:
        for v in re.findall(pat,text): candidates.append({'component':name,'version':v,'cve_lookup':'recommended'})
    if 'x-powered-by' in h: candidates.append({'component':'X-Powered-By','version':h['x-powered-by'],'cve_lookup':'recommended'})
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'detected_components':candidates,'note':'This module identifies version candidates; verify against a trusted CVE database before treating a CVE as confirmed.'}
    print("\n\033[1;36mDependency / CVE Intelligence\033[0m",url)
    for x in candidates: print(' ',x['component'],x['version'])
    if not candidates: print(' No reliable component versions detected.')
    return save_report('dependency_cve',data)

def http_method_security_audit(url, scope):
    url=normalize_url(url); require_scope(url,scope)
    r,_=fetch(url,method='OPTIONS',timeout=TIMEOUT,max_bytes=2000); h={k.lower():v for k,v in r.headers.items()}; allow=h.get('allow','')
    methods=[x.strip().upper() for x in allow.split(',') if x.strip()]
    findings=[]
    unusual=[x for x in methods if x not in ('GET','HEAD','POST','OPTIONS')]
    if any(x in methods for x in ('TRACE','CONNECT')): findings.append(finding('medium','Potentially unnecessary HTTP method advertised',', '.join(methods),'Disable methods not required by the application.'))
    if unusual: findings.append(finding('low','Additional HTTP methods advertised',', '.join(unusual),'Review whether each method is necessary and properly authorized.'))
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':url,'status':r.status,'allow':allow,'methods':methods,'findings':findings}
    score, level, risk_meta = risk(findings); data.update(risk_score=score,risk=level)
    print("\n\033[1;36mHTTP Method Security Audit\033[0m",url); print(' Allow:',allow or 'not advertised')
    return save_report('http_methods',data)

def risk_scoring_engine(target=None):
    files=sorted(REPORTS.glob('*.json'))[-100:]; selected=[]
    for f in files:
        try:
            d=json.loads(f.read_text(encoding='utf-8'))
            if target and d.get('target') and d.get('target') != target: continue
            selected.append((f,d))
        except Exception: pass
    findings=[]
    for _,d in selected: findings.extend(d.get('findings',[]))
    score, level, risk_meta = risk(findings)
    counts={k:sum(1 for x in findings if x.get('severity','').lower()==k) for k in ('critical','high','medium','low','info')}
    normalized=min(100,score*4)
    grade='A' if normalized<=10 else 'B' if normalized<=25 else 'C' if normalized<=50 else 'D' if normalized<=75 else 'F'
    data={'tool':'Cyber Terrafor','version':VERSION,'timestamp':stamp(),'target':target,'reports_considered':len(selected),'finding_counts':counts,'risk_score':score,'risk_level':level,'security_score':max(0,100-normalized),'grade':grade,'top_findings':findings[:20]}
    print("\n\033[1;35mCYBER TERRAFOR SECURITY SCORE\033[0m")
    print(' Overall Score:',data['security_score'],'/ 100'); print(' Grade:',grade); print(' Risk:',level); print(' Critical:',counts['critical'],'High:',counts['high'],'Medium:',counts['medium'],'Low:',counts['low'])
    return save_report('risk_score',data)

def nmap_scan(host, scope, profile="quick"):
    host=require_scope(host,scope)
    if not shutil.which("nmap"):
        print("[!] Nmap not installed; using built-in safe port/service fallback.")
        rows=[]
        for port in (DEFAULT_PORTS if profile=="common" else DEFAULT_PORTS[:10]):
            with socket.socket() as s:
                s.settimeout(0.8); state="open" if s.connect_ex((host,int(port)))==0 else "closed/filtered"
            rows.append({"port":int(port),"state":state})
        return save_report("nmap",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":host,"profile":profile,"engine":"builtin-fallback","results":rows})
    profiles={
        "quick":["-T2","--top-ports","20","-sV","--version-light"],
        "service":["-T2","-p-","-sV","--version-light"],
        "os":["-T2","-sV","-O","--osscan-limit"],
        "common":["-T2","-p",",".join(map(str,DEFAULT_PORTS)),"-sV","--version-light"],
    }
    cmd=["nmap",*profiles[profile],host]
    print("\n\033[1;36mNmap Network Scanner\033[0m",host)
    print(" Command:"," ".join(cmd))
    p=subprocess.run(cmd,capture_output=True,text=True,timeout=180)
    out=(p.stdout or "")[-20000:]
    err=(p.stderr or "")[-5000:]
    print(out)
    if err: print("\033[1;33mNmap notes:\033[0m",err)
    return save_report("nmap",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),
        "target":host,"profile":profile,"returncode":p.returncode,"stdout":out,"stderr":err})

def ports(host,scope,plist=None):
    host=require_scope(host,scope)
    plist=plist or DEFAULT_PORTS
    if len(plist)>50: raise ValueError("Maximum 50 ports per run")
    rows=[]
    print("\n\033[1;36mPort Audit\033[0m",host)
    for port in plist:
        with socket.socket() as s:
            s.settimeout(.8); t=time.perf_counter()
            try: state="open" if s.connect_ex((host,int(port)))==0 else "closed/filtered"
            except OSError: state="error"
            ms=round((time.perf_counter()-t)*1000,2)
        print(f" {int(port):5} {state:16} {ms:8.2f} ms")
        rows.append({"port":int(port),"state":state,"latency_ms":ms})
    return save_report("ports",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":host,"results":rows})

def load_check(url,scope,count=10,delay=.5):
    url=normalize_url(url); require_scope(url,scope)
    if not 1<=count<=MAX_REQUESTS: raise ValueError(f"count must be 1-{MAX_REQUESTS}")
    if delay<MIN_DELAY: raise ValueError(f"delay must be >= {MIN_DELAY}s")
    rows=[]
    for i in range(1,count+1):
        t=time.perf_counter(); status=None; err=None
        try: r,_=fetch(url,max_bytes=64); status=r.status
        except Exception as e: err=str(e)
        ms=round((time.perf_counter()-t)*1000,2)
        print(f" {i:02}/{count} status={status} {ms:8.2f} ms")
        rows.append({"request":i,"status":status,"latency_ms":ms,"error":err})
        if i<count: time.sleep(delay)
    return save_report("load_check",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"count":count,"delay":delay,"results":rows})

def file_hash(path):
    data=hashes(path)
    print(json.dumps(data,indent=2))
    return save_report("file_hash",{"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),**data})

def reports_list():
    REPORTS.mkdir(exist_ok=True)
    for f in sorted(REPORTS.glob("*.json"))[-30:]: print(" ",f.name)

def _collect_findings(obj, module="General", out=None):
    if out is None: out=[]
    if isinstance(obj, dict):
        if isinstance(obj.get("findings"), list):
            for f in obj["findings"]:
                if isinstance(f, dict):
                    out.append({"module":module, **f})
        next_module = module
        if obj.get("tool") == "Cyber Terrafor" and obj.get("target"):
            next_module = module
        for k,v in obj.items():
            if k in ("findings",): continue
            label = str(k).replace("_"," ").title()
            _collect_findings(v, label, out)
    elif isinstance(obj, list):
        for v in obj: _collect_findings(v, module, out)
    return out

def _severity_rank(s):
    return {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(str(s).lower(),5)

def article_summary(report, title="Cyber Terrafor Security Analysis"):
    """Generate a human-readable article-style security summary from structured results."""
    target = report.get("target") or report.get("summary",{}).get("target") or "Unknown target"
    findings = _collect_findings(report)
    # Deduplicate while preserving the most useful evidence.
    unique=[]; seen=set()
    for f in findings:
        key=(f.get("severity"),f.get("title"),f.get("evidence"),f.get("remediation"))
        if key not in seen:
            seen.add(key); unique.append(f)
    findings=sorted(unique,key=lambda x:_severity_rank(x.get("severity")))
    counts={s:sum(1 for f in findings if str(f.get("severity","")).lower()==s) for s in ("critical","high","medium","low","info")}
    score, level, risk_meta = risk(findings)
    profile=report.get("technology_profile") or report.get("modules",{}).get("adaptive",{}).get("technology_profile",{})
    detected=profile.get("detected",[]) if isinstance(profile,dict) else []
    evidence=profile.get("evidence",{}) if isinstance(profile,dict) else {}
    lines=[]
    lines.append(title)
    lines.append("="*len(title))
    lines.append("")
    lines.append(f"Target: {target}")
    lines.append(f"Generated: {stamp()}")
    lines.append("")
    lines.append("Executive Summary")
    lines.append("-----------------")
    if findings:
        lines.append(f"Cyber Terrafor-এর বিশ্লেষণে মোট {len(findings)}টি security/configuration observation পাওয়া গেছে। সামগ্রিক risk level {level}, এবং weighted risk score {score}।")
        lines.append(f"Severity breakdown: Critical {counts['critical']}, High {counts['high']}, Medium {counts['medium']}, Low {counts['low']}, Informational {counts['info']}।")
    else:
        lines.append("নির্বাচিত checks-এ কোনো finding পাওয়া যায়নি। এটি সম্পূর্ণ নিরাপদ—এমন নিশ্চয়তা নয়; এটি কেবল এই passive/authorized analysis-এর ফলাফল।")
    lines.append("")
    lines.append("Detected Technology Stack")
    lines.append("-------------------------")
    if detected:
        for t in detected:
            ev="; ".join(evidence.get(t,[])[:3]) if isinstance(evidence,dict) else ""
            lines.append(f"- {t}" + (f" — evidence: {ev}" if ev else ""))
    else:
        lines.append("- Reliable technology fingerprint পাওয়া যায়নি; generic analysis-এর ফলাফলকে অগ্রাধিকার দেওয়া হয়েছে।")
    lines.append("")
    lines.append("Where Problems Were Found")
    lines.append("--------------------------")
    if findings:
        for i,f in enumerate(findings,1):
            sev=str(f.get("severity","info")).upper()
            lines.append(f"{i}. [{sev}] {f.get('title','Unnamed finding')}")
            lines.append(f"   Module/Area: {f.get('module','General')}")
            lines.append(f"   Location/Target: {target}")
            if f.get("evidence"): lines.append(f"   Evidence: {f['evidence']}")
            lines.append(f"   Confidence: {str(f.get('confidence','medium')).upper()}")
            lines.append(f"   Verification: {f.get('verification','OBSERVED')}")
            if f.get("impact"): lines.append(f"   Impact: {f['impact']}")
            if f.get("remediation"): lines.append(f"   Recommended action: {f['remediation']}")
    else:
        lines.append("- কোনো নির্দিষ্ট সমস্যা শনাক্ত হয়নি।")
    lines.append("")
    lines.append("Why This Risk Score")
    lines.append("--------------------")
    lines.append((risk_meta or {}).get("score_method", "Finding-based scoring was applied."))
    for c in (risk_meta or {}).get("contributions", []):
        lines.append(f"- {c.get('title','Finding')}: +{c.get('contribution',0)} ({str(c.get('severity','info')).upper()}, {str(c.get('confidence','medium')).upper()})")
    lines.append(f"Final score: {score}/100 ({level})")
    lines.append("")
    lines.append("Priority Remediation Plan")
    lines.append("-------------------------")
    if findings:
        priority=0
        for f in findings:
            if str(f.get("severity","")).lower() in ("critical","high","medium"):
                priority += 1
                lines.append(f"{priority}. {f.get('title','Issue')}: {f.get('remediation','Review and remediate the finding.')}" )
        if priority==0: lines.append("- কোনো Critical/High/Medium finding নেই; নিয়মিত hardening ও monitoring বজায় রাখুন।")
    else:
        lines.append("- Baseline তৈরি করুন এবং নিয়মিত পুনরায় scan করে regression শনাক্ত করুন।")
    lines.append("")
    lines.append("Conclusion")
    lines.append("----------")
    if level in ("CRITICAL","HIGH"):
        lines.append("প্রধান ঝুঁকিগুলো remediation না হওয়া পর্যন্ত production exposure কমানো এবং সংশ্লিষ্ট configuration/application owner-এর review করা উচিত।")
    elif level == "MEDIUM":
        lines.append("তাৎক্ষণিক hardening প্রয়োজন এমন কয়েকটি issue আছে। Medium findings-এর remediation করে baseline পুনরায় যাচাই করা উচিত।")
    else:
        lines.append("এই analysis-এ বড় ঝুঁকি পাওয়া যায়নি। তবে এটি একটি point-in-time assessment; নিয়মিত monitoring এবং regression scan চালু রাখা উচিত।")
    text="\n".join(lines)+"\n"
    REPORTS.mkdir(exist_ok=True)
    out=REPORTS/(datetime.now().strftime("%Y%m%d_%H%M%S")+"_article_summary.txt")
    out.write_text(text,encoding="utf-8")
    print("\n\033[1;36m=== ARTICLE-STYLE SECURITY SUMMARY ===\033[0m\n")
    print(text)
    print("[+] Text summary:",out.relative_to(BASE))
    return {"path":str(out),"text":text,"risk":level,"risk_score":score,"findings":len(findings)}

def article_summary_from_target(target=None):
    files=sorted(REPORTS.glob("*.json"))
    selected=[]
    for f in files:
        try:
            d=json.loads(f.read_text(encoding="utf-8"))
            if target and d.get("target") and d.get("target") != target: continue
            selected.append(d)
        except Exception: pass
    if not selected: raise ValueError("No JSON analysis reports available for the requested target.")
    report={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":target or selected[-1].get("target"),"modules":selected}
    return article_summary(report)

def export_html():
    files=sorted(REPORTS.glob("*.json"), key=lambda p:p.stat().st_mtime, reverse=True)
    if not files: raise ValueError("No JSON reports available.")
    all_data=[]; findings=[]
    for f in files[:100]:
        try:
            d=json.loads(f.read_text(encoding="utf-8")); all_data.append((f,d)); findings.extend(_collect_findings(d))
        except Exception: pass
    counts={s:sum(1 for x in findings if str(x.get("severity","")).lower()==s) for s in ("critical","high","medium","low","info")}
    score,level,meta=risk(findings) if findings else (0,"low",{})
    cards="".join(f"<div class=card><div class=muted>{k.upper()}</div><strong>{v}</strong></div>" for k,v in counts.items())
    rows="".join("<tr><td>"+html.escape(str(x.get("severity","")))+"</td><td>"+html.escape(str(x.get("title","")))+"</td><td>"+html.escape(str(x.get("module","")))+"</td><td>"+html.escape(str(x.get("verification","")))+"</td></tr>" for x in findings[:80])
    sections=[]
    for f,d in all_data[:50]: sections.append("<details><summary>"+html.escape(f.name)+"</summary><pre>"+html.escape(json.dumps(d,indent=2,ensure_ascii=False))+"</pre></details>")
    out=REPORTS/(datetime.now().strftime("%Y%m%d_%H%M%S")+"_cyber_terrafor_professional_report.html")
    head='<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Cyber Terrafor Professional Audit Report</title><style>body{font-family:Inter,Arial;background:#08101f;color:#e9eefc;margin:0}header{padding:28px;background:#101a33}main{max-width:1200px;margin:24px auto;padding:0 18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,details{background:#111b34;border:1px solid #293a63;border-radius:12px;padding:15px;margin:12px 0}.card strong{font-size:28px}.muted{color:#91a0c5}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #293a63;text-align:left}pre{white-space:pre-wrap;overflow:auto}.risk{font-size:34px;font-weight:700}</style></head><body><header><h1>CYBER TERRAFOR PROFESSIONAL</h1><div class="muted">Evidence-driven Security Assessment & Defensive Intelligence • v"+VERSION+"</div></header><main>'
    doc=head+"<div class=card><div class=muted>OVERALL RISK</div><div class=risk>"+html.escape(level.upper())+" • "+str(score)+"/100</div><div class=muted>Evidence-weighted aggregate across collected reports.</div></div><div class=grid>"+cards+"</div><div class=card><h2>Findings & Audit Evidence</h2><table><tr><th>Severity</th><th>Finding</th><th>Module</th><th>Verification</th></tr>"+rows+"</table></div><h2>Report Evidence</h2>"+"".join(sections)+"</main></body></html>"
    out.write_text(doc,encoding="utf-8"); print("[+] HTML report:",out.relative_to(BASE)); return out

def enterprise_posture_audit(url, scope):
    url=normalize_url(url); host=require_scope(url,scope)
    reports=[]
    try:
        r,body=fetch(url,timeout=TIMEOUT,max_bytes=500000)
        wp=web_posture(url,r,body,finding); reports.append({"module":"web_posture",**wp})
        st=security_txt(url,fetch,scope,finding); reports.append({"module":"security_txt",**st})
    except Exception as e:
        reports.append({"module":"web_posture","error":str(e),"findings":[]})
    try:
        reports.append({"module":"tls_posture",**tls_posture(host,443,scope,finding)})
    except Exception as e:
        reports.append({"module":"tls_posture","error":str(e),"findings":[]})
    findings=[]
    for d in reports: findings.extend(d.get("findings",[]))
    score,level,meta=risk(findings)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,"engine":"Enterprise Posture Engine 8.0","summary":{"risk_score":score,"risk_level":level,"finding_count":len(findings),"risk_analysis":meta},"modules":reports,"compliance_alignment":compliance_map(findings)}
    return save_report("enterprise_posture",data)


def deep_web_pentest(target, scope, profile="deep-web"):
    url=normalize_url(target); require_scope(url,scope)
    print("\n\033[1;35m=== CYBER TERRAFOR SAFE ACTIVE WEB PENTEST ===\033[0m")
    result=run_deep_web_pentest(url, lambda u: require_scope(u,scope), fetch, finding, profile=profile)
    score, level, meta = risk(result.get("findings",[]))
    result.update({"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,
                   "risk_score":score,"risk_level":level,"risk_analysis":meta})
    return save_report("deep_web_pentest", result)


def deep_analysis(target,scope):
    url=normalize_url(target); host=require_scope(url,scope)
    print("\n\033[1;35m=== CYBER TERRAFOR ENTERPRISE DEEP ANALYSIS ===\033[0m")
    modules=[]
    for label,fn in [
        ("deep_web_pentest",lambda:deep_web_pentest(url,scope,"deep-web")),
        ("web",lambda:web_audit(url,scope,True)),
        ("enterprise_posture",lambda:enterprise_posture_audit(url,scope)),
        ("adaptive",lambda:adaptive_site_analysis(url,scope)),
        ("tls",lambda:tls(host,scope,443)),
        ("dns",lambda:dns(host,scope)),
        ("api",lambda:api_security_audit(url,scope)),
        ("cookies",lambda:cookie_security_audit(url,scope)),
        ("cors",lambda:cors_security_audit(url,scope)),
        ("javascript",lambda:javascript_security_audit(url,scope)),
        ("cloud",lambda:cloud_exposure_audit(url,scope)),
        ("waf_cdn",lambda:waf_cdn_detection(url,scope)),
        ("auth",lambda:authentication_security_audit(url,scope)),
        ("api_endpoints",lambda:api_endpoint_discovery(url,scope)),
        ("dependency",lambda:dependency_cve_intelligence(url,scope)),
        ("http_methods",lambda:http_method_security_audit(url,scope)),
        ("headers",lambda:security_headers_audit(url,scope)),
        ("redirects",lambda:redirect_security_audit(url,scope)),
        ("robots",lambda:robots_sitemap_audit(url,scope)),
    ]:
        try: modules.append({"name":label,"result":fn()})
        except Exception as e: modules.append({"name":label,"error":str(e),"findings":[]})
    findings=[]
    for m in modules:
        r=m.get("result",m); findings.extend(r.get("findings",[]) if isinstance(r,dict) else [])
    score,level,meta=risk(findings)
    exec_summary=executive_posture(url,[m.get("result",{}) for m in modules if isinstance(m.get("result"),dict)],risk)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":url,
          "summary":exec_summary,"modules":modules,"assessment_profile":"enterprise-deep-passive-and-safe-active"}
    out=save_report("enterprise_deep_analysis",data)
    try:
        manifest=evidence_manifest(sorted(REPORTS.glob("*.json"))[-50:], REPORTS/(out.stem+"_evidence_manifest.json"))
        data["evidence_manifest"]=manifest
    except Exception as e: data["evidence_manifest_error"]=str(e)
    try: article_summary(data, "Cyber Terrafor Enterprise Deep Security Analysis")
    except Exception as e: print("[!] Article summary generation failed:",e)
    return data

def scope_check(scope):
    entries=scope_entries(scope)
    if not entries: raise ValueError("Scope file is empty.")
    print("\n\033[1;36mAuthorized Scope\033[0m")
    for e in entries: print(" -",e)

MODULE_REGISTRY = {
    1:"web_audit",2:"nmap_scan",3:"tls",4:"ports",5:"dns",6:"security_headers_audit",7:"technology_fingerprint",
    8:"vulnerability_assessment",9:"broken_link_endpoint_audit",10:"sensitive_object_audit",11:"malware_analyze",12:"error_misconfiguration_audit",
    13:"security_configuration_audit",14:"geoip",15:"ssl_certificate_intelligence",16:"robots_sitemap_audit",17:"redirect_security_audit",
    18:"file_hash",19:"deep_analysis",20:"scope_check",21:"reports_list",22:"export_html",23:"subdomain_intelligence",24:"api_security_audit",
    25:"cookie_security_audit",26:"cors_security_audit",27:"javascript_security_audit",28:"cloud_exposure_audit",29:"waf_cdn_detection",
    30:"authentication_security_audit",31:"api_endpoint_discovery",32:"dependency_cve_intelligence",33:"http_method_security_audit",34:"risk_scoring_engine",35:"adaptive_site_analysis",36:"enterprise_posture_audit",37:"deep_web_pentest"
}

def module_health_check():
    rows=[]
    for n,name in MODULE_REGISTRY.items():
        fn=globals().get(name); rows.append({"module":n,"function":name,"status":"ACTIVE" if callable(fn) else "INACTIVE"})
    active=sum(x["status"]=="ACTIVE" for x in rows)
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"active":active,"total":len(rows),"all_active":active==len(rows),"modules":rows}
    print(f"\\n\\033[1;36mMODULE HEALTH: {active}/{len(rows)} ACTIVE\\033[0m")
    for x in rows: print(f" {x['module']:02} {x['function']:35} {x['status']}")
    return save_report("module_health",data)


def summarize_risk(findings, score, level, risk_meta=None):
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    counts = {}
    for f in findings:
        s = str(f.get("severity","info")).upper()
        counts[s] = counts.get(s, 0) + 1

    priority = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1,"INFO":0}
    top = sorted(
        findings,
        key=lambda f: (
            priority.get(str(f.get("severity","info")).upper(), 0),
            -float(next((c.get("contribution",0) for c in (risk_meta or {}).get("contributions",[])
                         if c.get("title")==f.get("title")), 0))
        ),
        reverse=True
    )[:5]

    reasons = []
    for f in top:
        sev = str(f.get("severity","info")).upper()
        title = f.get("title","Unnamed finding")
        evidence = f.get("evidence","No evidence recorded")
        reasons.append(f"- [{sev}] {title}: {evidence}")

    return {
        "risk_score": score,
        "risk_level": level,
        "finding_counts": counts,
        "why": reasons,
        "score_method": (
            "Score is calculated from unique findings using severity, confidence, "
            "and bounded exploitability/impact/exposure factors. It is recalculated "
            "for each analysis result; no fixed module score is reused."
        ),
    }



def calculate_module_risk(findings):
    score, level, meta = risk(findings)
    return {
        "risk_score": score,
        "risk_level": level,
        "risk_analysis": meta,
        "risk_summary": summarize_risk(findings, score, level, meta),
    }



def enterprise_asset_inventory(target=None, criticality=50):
    data=asset_inventory(target,criticality); print(json.dumps(data,indent=2,ensure_ascii=False)); return save_report("enterprise_asset_inventory",data)

def enterprise_risk_score(target=None):
    findings=[]
    for f in sorted(REPORTS.glob("*.json"),key=lambda p:p.stat().st_mtime,reverse=True)[:100]:
        try:
            d=json.loads(f.read_text(encoding="utf-8")); findings.extend(_collect_findings(d))
        except Exception: pass
    result=enterprise_risk(findings); result["target"]=target; result["timestamp"]=stamp(); correlate_findings(findings,target)
    print(json.dumps(result,indent=2,ensure_ascii=False)); return save_report("enterprise_risk",result)

def enterprise_secret_scan(path):
    data=scan_secrets(path); print(json.dumps(data,indent=2,ensure_ascii=False)); return save_report("secret_scan",data)

def enterprise_container_audit(path):
    data=container_audit(path); print(json.dumps(data,indent=2,ensure_ascii=False)); return save_report("container_audit",data)

def enterprise_compliance(target=None):
    findings=[]
    for f in sorted(REPORTS.glob("*.json"),key=lambda p:p.stat().st_mtime,reverse=True)[:100]:
        try: findings.extend(_collect_findings(json.loads(f.read_text(encoding="utf-8"))))
        except Exception: pass
    data={"tool":"Cyber Terrafor","version":VERSION,"timestamp":stamp(),"target":target,"controls":compliance_matrix(findings)}; print(json.dumps(data,indent=2,ensure_ascii=False)); return save_report("enterprise_compliance",data)

def enterprise_seal():
    files=sorted(REPORTS.glob("*.json"),key=lambda p:p.stat().st_mtime,reverse=True)[:100]; data=evidence_seal(files); print(json.dumps(data,indent=2,ensure_ascii=False)); return data

def enterprise_center():
    data=dashboard(); print(json.dumps(data,indent=2,ensure_ascii=False)); return save_report("enterprise_center",data)

def startup_warning():
    print(r"""
⚠️ CYBER TERRAFOR — AUTHORIZED USE ONLY

Use only on systems you own or have explicit permission to test.
Scans may generate traffic and automated findings may require
manual verification.

Proceeding with Cyber Terrafor...

[Press ENTER to continue]
""")
    input()


def temporary_scope_for_target(target_url):
    """Create a narrow in-memory scope for one explicitly supplied target."""
    target_url = normalize_url(target_url)
    p = urllib.parse.urlparse(target_url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a complete HTTP/HTTPS website URL.")
    return {
        "target": target_url,
        "hosts": {p.hostname.lower()},
        "ips": set(),
        "cidrs": [],
        "wildcards": set(),
        "source": "temporary-url-scope",
    }

def require_target_url(url):
    url = normalize_url(url)
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("Enter a complete HTTP/HTTPS website URL.")
    return url

def url_first_menu():
    """Default interactive mode: every selected analysis asks for its own URL."""
    print("\n" + "=" * 64)
    print(" CYBER TERRAFOR — URL-FIRST ANALYSIS")
    print("=" * 64)
    print("Each tool accepts its own website URL.")
    print("A temporary host-only scope is created automatically.\n")
    print(" [1] HTTP Security Posture")
    print(" [2] Technology Detection")
    print(" [3] SSL/TLS Analysis")
    print(" [4] DNS Analysis")
    print(" [5] Deep Analysis")
    print(" [6] Adaptive Technology Analysis")
    print(" [7] Article Summary")
    print(" [8] Module Health")
    print(" [0] Exit")

    while True:
        choice = input("\nSelect tool > ").strip()
        if choice == "0":
            return

        if choice == "8":
            try:
                module_health_check()
            except Exception as e:
                print("[!] Module health check failed:", e)
            continue

        if choice == "7":
            url = require_target_url(input("Target Website URL > ").strip())
            try:
                article_summary(url)
            except Exception as e:
                print("[!] Article summary failed:", e)
            continue

        url = require_target_url(input("Target Website URL > ").strip())
        scope = temporary_scope_for_target(url)

        try:
            if choice == "1":
                web_audit(url, scope, True)
            elif choice == "2":
                technology_fingerprint(url, scope)
            elif choice == "3":
                ssl_certificate_intelligence(url, scope)
            elif choice == "4":
                dns(urlparse_host(url), scope)
            elif choice == "5":
                deep_analysis(url, scope)
            elif choice == "6":
                adaptive_site_analysis(url, scope)
            else:
                print("Unknown option.")
        except TypeError:
            print("[!] This module requires the persistent --scope mode.")
        except Exception as e:
            print("[!] Analysis failed:", e)


def interactive(scope_default=None):
    while True:
        clear(); banner()
        print("""
 [1]  Advanced Web Security Audit
 [2]  Nmap Network Scanner
 [3]  TLS / HTTPS Security Audit
 [4]  Port & Service Enumeration
 [5]  DNS / IP Intelligence
 [6]  Security Headers Audit (dedicated)
 [7]  Web Technology Fingerprinting (dedicated)
 [8]  Passive Vulnerability Assessment
 [9]  Broken Link & Endpoint Audit (active HEAD/GET fallback)
 [10] Sensitive File / Object Detection (dedicated)
 [11] Malware & Suspicious File Analysis
 [12] Error & Misconfiguration Detection (dedicated)
 [13] Security Configuration Audit (dedicated)
 [14] IP / ASN / GeoIP Intelligence
 [15] SSL Certificate Intelligence (dedicated)
 [16] Robots.txt / Sitemap Analysis (dedicated)
 [17] URL / Redirect Security Audit (scope-safe chain)
 [18] File Hash & Integrity Analysis
 [19] Deep Security Analysis
 [20] Scope / Authorization Check
 [21] Scan History
 [22] Generate HTML Report

 [23] Subdomain Intelligence
 [24] API Security Audit
 [25] Cookie Security Audit
 [26] CORS Security Audit
 [27] JavaScript Security Audit
 [28] Cloud Exposure Audit
 [29] WAF / CDN Detection
 [30] Authentication Security Audit
 [31] API Endpoint Discovery
 [32] Dependency / CVE Intelligence
 [33] HTTP Method Security Audit
 [34] Security Risk Scoring Engine
 [35] Adaptive Technology / Stack Analysis
 [36] Module Health Check
 [37] Article-Style Text Summary
 [0]  Exit
""")
        c=input(" Cyber Terrafor > ").strip()
        try:
            if c=="0": return
            if c=="11": malware_analyze(input(" Local file > ").strip())
            elif c=="18": file_hash(input(" Local file > ").strip())
            elif c=="21": reports_list()
            elif c=="22": export_html()
            elif c=="34": risk_scoring_engine(input(" Target URL [optional] > ").strip() or None)
            elif c=="35":
                s=input(f" Scope file [{scope_default or 'scope.txt'}] > ").strip() or scope_default or "scope.txt"
                adaptive_site_analysis(input(" URL > ").strip(),s)
            elif c=="36": module_health_check()
            elif c=="37": article_summary_from_target(input(" Target URL [optional] > ").strip() or None)
            elif c=="20": scope_check(input(" Scope file > ").strip() or scope_default or "scope.txt")
            else:
                s=input(f" Scope file [{scope_default or 'scope.txt'}] > ").strip() or scope_default or "scope.txt"
                if c=="1": web_audit(input(" URL > ").strip(),s,True)
                elif c=="2": nmap_scan(input(" Host > ").strip(),s,input(" Profile [quick/service/os/common] > ").strip() or "quick")
                elif c=="3": tls(input(" Host > ").strip(),s)
                elif c=="4":
                    h=input(" Host > ").strip(); q=input(" Ports [default] > ").strip(); ports(h,s,[int(x) for x in q.split(",")] if q else None)
                elif c=="5": dns(input(" Host > ").strip(),s)
                elif c=="6": security_headers_audit(input(" URL > ").strip(),s)
                elif c=="7": technology_fingerprint(input(" URL > ").strip(),s)
                elif c=="8": vulnerability_assessment(input(" URL > ").strip(),s)
                elif c=="9": broken_link_endpoint_audit(input(" URL > ").strip(),s)
                elif c=="10": sensitive_object_audit(input(" URL > ").strip(),s)
                elif c=="12": error_misconfiguration_audit(input(" URL > ").strip(),s)
                elif c=="13": security_configuration_audit(input(" URL > ").strip(),s)
                elif c=="14": geoip(input(" Host > ").strip(),s)
                elif c=="15": ssl_certificate_intelligence(input(" Host or URL > ").strip(),s)
                elif c=="16": robots_sitemap_audit(input(" URL > ").strip(),s)
                elif c=="17": redirect_security_audit(input(" URL > ").strip(),s)
                elif c=="19": deep_analysis(input(" URL > ").strip(),s)
                elif c=="23": subdomain_intelligence(input(" URL > ").strip(),s)
                elif c=="24": api_security_audit(input(" URL > ").strip(),s)
                elif c=="25": cookie_security_audit(input(" URL > ").strip(),s)
                elif c=="26": cors_security_audit(input(" URL > ").strip(),s)
                elif c=="27": javascript_security_audit(input(" URL > ").strip(),s)
                elif c=="28": cloud_exposure_audit(input(" URL > ").strip(),s)
                elif c=="29": waf_cdn_detection(input(" URL > ").strip(),s)
                elif c=="30": authentication_security_audit(input(" URL > ").strip(),s)
                elif c=="31": api_endpoint_discovery(input(" URL > ").strip(),s)
                elif c=="32": dependency_cve_intelligence(input(" URL > ").strip(),s)
                elif c=="33": http_method_security_audit(input(" URL > ").strip(),s)
                else: print(" Unknown option.")
        except (KeyboardInterrupt,EOFError): return
        except Exception as e: print("\033[1;31m[!]\033[0m",e)
        input("\n Press Enter to continue...")

def malware_scan(path, quarantine=False):
    from defense_engine import scan_file
    data=scan_file(path, quarantine=quarantine); save_report("malware_scan", data); return data

def create_baseline(path):
    from defense_engine import baseline
    data,out=baseline(path); print(f"[+] Integrity baseline: {out.relative_to(BASE)}"); save_report("integrity_baseline", data); return data

def platform_json(data, name):
    print(json.dumps(data, indent=2, ensure_ascii=False)); return save_report(name, data)

def platform_vuln_lookup(ref): return platform_json(vulnerability_lookup(ref) or {"id":ref,"status":"not_found"}, "vulnerability_lookup")
def platform_remediation(finding_id, owner, priority, due_days, notes): return platform_json(create_remediation(finding_id,owner,priority,due_days,notes), "remediation_created")
def platform_remediation_update(rid,status,notes): return platform_json(update_remediation(rid,status,notes), "remediation_updated")
def platform_verify(fid,status,path,notes): return platform_json(verify_finding(fid,status,path,notes), "finding_verification")
def platform_queue(): return platform_json({"remediation_queue":remediation_queue()}, "remediation_queue")
def platform_asm(target): return platform_json(attack_surface_snapshot(target), "attack_surface_snapshot")
def platform_cloud(path): return platform_json(cloud_config_audit(path), "cloud_config_audit")
def platform_ti_import(path): return platform_json(threat_intel_import(path), "threat_intel_import")
def platform_ti_lookup(ioc): return platform_json(threat_intel_lookup(ioc), "threat_intel_lookup")
def platform_center(): return platform_json(enterprise_dashboard(), "enterprise_platform_center")

def ransomware_guard(path, interval=2.0, once=False):
    from defense_engine import monitor
    print("[+] Cyber Terrafor ransomware guard active. Detection/alerting only; no destructive remediation."); return monitor(path, interval, once)

def launch_admin(host="127.0.0.1", port=8787):
    from admin_panel import run
    run(host, port)

def main():
    p=argparse.ArgumentParser(description="Cyber Terrafor v11.0 - enterprise security assessment, exposure management and defensive platform")
    p.add_argument("--scope")
    sub=p.add_subparsers(dest="cmd")
    q=sub.add_parser("file-hash"); q.add_argument("path")
    q=sub.add_parser("malware-analyze"); q.add_argument("path")
    q=sub.add_parser("web-audit"); q.add_argument("url")
    q=sub.add_parser("deep-audit"); q.add_argument("url")
    q=sub.add_parser("deep-web-pentest"); q.add_argument("url"); q.add_argument("--profile", choices=["deep-web","enterprise"], default="deep-web")
    q=sub.add_parser("tls"); q.add_argument("host"); q.add_argument("--port",type=int,default=443)
    q=sub.add_parser("nmap"); q.add_argument("host"); q.add_argument("--profile",choices=["quick","service","os","common"],default="quick")
    q=sub.add_parser("ports"); q.add_argument("host"); q.add_argument("--ports")
    q=sub.add_parser("dns"); q.add_argument("host")
    q=sub.add_parser("geoip"); q.add_argument("host")
    q=sub.add_parser("load-check"); q.add_argument("url"); q.add_argument("--count",type=int,default=10); q.add_argument("--delay",type=float,default=.5)
    q=sub.add_parser("subdomain-intel"); q.add_argument("url")
    q=sub.add_parser("api-audit"); q.add_argument("url")
    q=sub.add_parser("cookie-audit"); q.add_argument("url")
    q=sub.add_parser("cors-audit"); q.add_argument("url")
    q=sub.add_parser("javascript-audit"); q.add_argument("url")
    q=sub.add_parser("cloud-audit"); q.add_argument("url")
    q=sub.add_parser("waf-cdn"); q.add_argument("url")
    q=sub.add_parser("auth-audit"); q.add_argument("url")
    q=sub.add_parser("api-endpoints"); q.add_argument("url")
    q=sub.add_parser("dependency-intel"); q.add_argument("url")
    q=sub.add_parser("http-methods"); q.add_argument("url")
    q=sub.add_parser("headers"); q.add_argument("url")
    q=sub.add_parser("tech-fingerprint"); q.add_argument("url")
    q=sub.add_parser("vulnerability-assessment"); q.add_argument("url")
    q=sub.add_parser("broken-links"); q.add_argument("url")
    q=sub.add_parser("sensitive-objects"); q.add_argument("url")
    q=sub.add_parser("error-misconfig"); q.add_argument("url")
    q=sub.add_parser("security-config"); q.add_argument("url")
    q=sub.add_parser("ssl-intel"); q.add_argument("url")
    q=sub.add_parser("robots-sitemap"); q.add_argument("url")
    q=sub.add_parser("redirect-security"); q.add_argument("url")
    q=sub.add_parser("risk-score"); q.add_argument("--target")
    sub.add_parser("html-report")
    sub.add_parser("module-health")
    q=sub.add_parser("article-summary"); q.add_argument("--target")
    q=sub.add_parser("adaptive-analysis"); q.add_argument("url")
    q=sub.add_parser("enterprise-posture"); q.add_argument("url")
    q=sub.add_parser("scope-check"); q.add_argument("path")
    q=sub.add_parser("malware-scan"); q.add_argument("path"); q.add_argument("--quarantine", action="store_true")
    q=sub.add_parser("ransomware-guard"); q.add_argument("path"); q.add_argument("--interval", type=float, default=2.0); q.add_argument("--once", action="store_true")
    q=sub.add_parser("baseline"); q.add_argument("path")
    q=sub.add_parser("admin"); q.add_argument("--host", default="127.0.0.1"); q.add_argument("--port", type=int, default=8787)
    q=sub.add_parser("enterprise-assets"); q.add_argument("--target"); q.add_argument("--criticality",type=int,default=50)
    q=sub.add_parser("enterprise-risk"); q.add_argument("--target")
    q=sub.add_parser("secret-scan"); q.add_argument("path")
    q=sub.add_parser("container-audit"); q.add_argument("path")
    q=sub.add_parser("enterprise-compliance"); q.add_argument("--target")
    sub.add_parser("evidence-seal")
    q=sub.add_parser("vuln-feed-import"); q.add_argument("path")
    q=sub.add_parser("schedule"); q.add_argument("target"); q.add_argument("module"); q.add_argument("schedule")
    sub.add_parser("enterprise-center")
    q=sub.add_parser("vuln-lookup"); q.add_argument("ref")
    q=sub.add_parser("remediation-create"); q.add_argument("finding_id"); q.add_argument("--owner",default="unassigned"); q.add_argument("--priority",choices=["critical","high","medium","low"],default="high"); q.add_argument("--due-days",type=int,default=14); q.add_argument("--notes",default="")
    q=sub.add_parser("remediation-update"); q.add_argument("id"); q.add_argument("status",choices=["open","in_progress","blocked","resolved","accepted","false_positive"]); q.add_argument("--notes",default="")
    q=sub.add_parser("remediation-queue")
    q=sub.add_parser("verify-finding"); q.add_argument("finding_id"); q.add_argument("--status",choices=["verified","still_open","inconclusive"],default="verified"); q.add_argument("--evidence"); q.add_argument("--notes",default="")
    q=sub.add_parser("asm-snapshot"); q.add_argument("target")
    q=sub.add_parser("continuous-check"); q.add_argument("target")
    q=sub.add_parser("cloud-export-audit"); q.add_argument("path")
    q=sub.add_parser("threat-intel-import"); q.add_argument("path")
    q=sub.add_parser("threat-intel-lookup"); q.add_argument("ioc")
    sub.add_parser("enterprise-platform-center")
    sub.add_parser("reports-list")
    a=p.parse_args()
    try:
        if not a.cmd:
            launch_admin(); return
        if a.cmd=="file-hash": file_hash(a.path)
        elif a.cmd=="malware-analyze": malware_analyze(a.path)
        elif a.cmd=="web-audit": web_audit(a.url,a.scope,True)
        elif a.cmd=="deep-audit": deep_analysis(a.url,a.scope)
        elif a.cmd=="deep-web-pentest": deep_web_pentest(a.url,a.scope,a.profile)
        elif a.cmd=="tls": tls(a.host,a.scope,a.port)
        elif a.cmd=="nmap": nmap_scan(a.host,a.scope,a.profile)
        elif a.cmd=="ports": ports(a.host,a.scope,[int(x) for x in a.ports.split(",")] if a.ports else None)
        elif a.cmd=="dns": dns(a.host,a.scope)
        elif a.cmd=="geoip": geoip(a.host,a.scope)
        elif a.cmd=="load-check": load_check(a.url,a.scope,a.count,a.delay)
        elif a.cmd=="subdomain-intel": subdomain_intelligence(a.url,a.scope)
        elif a.cmd=="api-audit": api_security_audit(a.url,a.scope)
        elif a.cmd=="cookie-audit": cookie_security_audit(a.url,a.scope)
        elif a.cmd=="cors-audit": cors_security_audit(a.url,a.scope)
        elif a.cmd=="javascript-audit": javascript_security_audit(a.url,a.scope)
        elif a.cmd=="cloud-audit": cloud_exposure_audit(a.url,a.scope)
        elif a.cmd=="waf-cdn": waf_cdn_detection(a.url,a.scope)
        elif a.cmd=="auth-audit": authentication_security_audit(a.url,a.scope)
        elif a.cmd=="api-endpoints": api_endpoint_discovery(a.url,a.scope)
        elif a.cmd=="dependency-intel": dependency_cve_intelligence(a.url,a.scope)
        elif a.cmd=="http-methods": http_method_security_audit(a.url,a.scope)
        elif a.cmd=="headers": security_headers_audit(a.url,a.scope)
        elif a.cmd=="tech-fingerprint": technology_fingerprint(a.url,a.scope)
        elif a.cmd=="vulnerability-assessment": vulnerability_assessment(a.url,a.scope)
        elif a.cmd=="broken-links": broken_link_endpoint_audit(a.url,a.scope)
        elif a.cmd=="sensitive-objects": sensitive_object_audit(a.url,a.scope)
        elif a.cmd=="error-misconfig": error_misconfiguration_audit(a.url,a.scope)
        elif a.cmd=="security-config": security_configuration_audit(a.url,a.scope)
        elif a.cmd=="ssl-intel": ssl_certificate_intelligence(a.url,a.scope)
        elif a.cmd=="robots-sitemap": robots_sitemap_audit(a.url,a.scope)
        elif a.cmd=="redirect-security": redirect_security_audit(a.url,a.scope)
        elif a.cmd=="risk-score": risk_scoring_engine(a.target)
        elif a.cmd=="html-report": export_html()
        elif a.cmd=="module-health": module_health_check()
        elif a.cmd=="article-summary": article_summary_from_target(a.target)
        elif a.cmd=="adaptive-analysis": adaptive_site_analysis(a.url,a.scope)
        elif a.cmd=="enterprise-posture": enterprise_posture_audit(a.url,a.scope)
        elif a.cmd=="scope-check": scope_check(a.path)
        elif a.cmd=="malware-scan": malware_scan(a.path, a.quarantine)
        elif a.cmd=="ransomware-guard": ransomware_guard(a.path, a.interval, a.once)
        elif a.cmd=="baseline": create_baseline(a.path)
        elif a.cmd=="admin": launch_admin(a.host, a.port)
        elif a.cmd=="enterprise-assets": enterprise_asset_inventory(a.target,a.criticality)
        elif a.cmd=="enterprise-risk": enterprise_risk_score(a.target)
        elif a.cmd=="secret-scan": enterprise_secret_scan(a.path)
        elif a.cmd=="container-audit": enterprise_container_audit(a.path)
        elif a.cmd=="enterprise-compliance": enterprise_compliance(a.target)
        elif a.cmd=="evidence-seal": enterprise_seal()
        elif a.cmd=="vuln-feed-import": print(json.dumps(import_vuln_feed(a.path),indent=2))
        elif a.cmd=="schedule": print(json.dumps(create_job(a.target,a.module,a.schedule),indent=2))
        elif a.cmd=="enterprise-center": enterprise_center()
        elif a.cmd=="vuln-lookup": platform_vuln_lookup(a.ref)
        elif a.cmd=="remediation-create": platform_remediation(a.finding_id,a.owner,a.priority,a.due_days,a.notes)
        elif a.cmd=="remediation-update": platform_remediation_update(a.id,a.status,a.notes)
        elif a.cmd=="remediation-queue": platform_queue()
        elif a.cmd=="verify-finding": platform_verify(a.finding_id,a.status,a.evidence,a.notes)
        elif a.cmd=="asm-snapshot": platform_asm(a.target)
        elif a.cmd=="continuous-check": platform_asm(a.target)
        elif a.cmd=="cloud-export-audit": platform_cloud(a.path)
        elif a.cmd=="threat-intel-import": platform_ti_import(a.path)
        elif a.cmd=="threat-intel-lookup": platform_ti_lookup(a.ioc)
        elif a.cmd=="enterprise-platform-center": platform_center()
        elif a.cmd=="reports-list": reports_list()
    except Exception as e:
        print("\033[1;31m[!]\033[0m",e); sys.exit(2)

if __name__=="__main__":
    main()

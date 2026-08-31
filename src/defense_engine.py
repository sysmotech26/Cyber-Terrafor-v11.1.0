#!/usr/bin/env python3
"""Local defensive file integrity, malware-indicator and ransomware-activity engine.

Designed for authorized defensive monitoring. It does not exploit systems or
attempt to decrypt/disable ransomware. Detection is evidence-based and the
optional quarantine action only moves a selected file into a local quarantine.
"""
import hashlib, json, math, os, shutil, time
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
REPORTS = BASE / "reports"
STATE = BASE / "state"
QUARANTINE = STATE / "quarantine"
BASELINE_DIR = STATE / "baselines"
for d in (REPORTS, STATE, QUARANTINE, BASELINE_DIR): d.mkdir(parents=True, exist_ok=True)

RISKY_EXT = {".encrypted", ".locked", ".locky", ".crypt", ".crypto", ".ryk", ".wncry", ".wannacry", ".cerber", ".zepto", ".aaa"}
EXEC_EXT = {".exe", ".dll", ".scr", ".msi", ".apk", ".elf", ".sh", ".ps1", ".bat", ".cmd", ".vbs", ".js"}
RANSOM_MARKERS = ("how_to_decrypt", "decrypt", "readme", "recover", "restore_files", "ransom")


def stamp(): return datetime.now(timezone.utc).isoformat()

def sha256(path, chunk=1024*1024):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        while True:
            b=f.read(chunk)
            if not b: break
            h.update(b)
    return h.hexdigest()

def entropy(path, max_bytes=2*1024*1024):
    data=Path(path).read_bytes()[:max_bytes]
    if not data: return 0.0
    freq=[0]*256
    for b in data: freq[b]+=1
    n=len(data)
    return -sum((c/n)*math.log2(c/n) for c in freq if c)

def inventory(root):
    root=Path(root).expanduser().resolve()
    rows=[]
    if root.is_file(): paths=[root]
    else: paths=[p for p in root.rglob('*') if p.is_file()]
    for p in paths:
        try:
            st=p.stat(); rows.append({"path":str(p),"size":st.st_size,"mtime_ns":st.st_mtime_ns,"sha256":sha256(p)})
        except (OSError, PermissionError): pass
    return rows

def baseline(root):
    root=Path(root).expanduser().resolve()
    data={"tool":"Cyber Terrafor Professional","version":"11.0.0","created_at":stamp(),"root":str(root),"files":inventory(root)}
    out=BASELINE_DIR/(hashlib.sha256(str(root).encode()).hexdigest()[:16]+".json")
    out.write_text(json.dumps(data,indent=2),encoding="utf-8")
    return data,out

def malware_indicators(path):
    p=Path(path).expanduser().resolve(); name=p.name.lower(); findings=[]
    try:
        st=p.stat(); ent=entropy(p)
    except OSError as e: return [{"severity":"error","indicator":str(e)}]
    if p.suffix.lower() in RISKY_EXT: findings.append({"severity":"high","indicator":"ransomware-like extension","evidence":p.suffix})
    if any(x in name for x in RANSOM_MARKERS): findings.append({"severity":"medium","indicator":"ransom-note-like filename","evidence":p.name})
    if p.suffix.lower() in EXEC_EXT and st.st_mode & 0o111: findings.append({"severity":"medium","indicator":"executable file","evidence":p.suffix})
    if ent >= 7.6 and st.st_size > 4096: findings.append({"severity":"medium","indicator":"high file entropy","evidence":round(ent,3)})
    return findings

def scan_file(path, quarantine=False):
    p=Path(path).expanduser().resolve(); findings=malware_indicators(p)
    result={"tool":"Cyber Terrafor Professional","version":"11.0.0","timestamp":stamp(),"path":str(p),"sha256":sha256(p),"entropy":round(entropy(p),4),"findings":findings,"disposition":"review" if findings else "no_indicators_observed"}
    if quarantine and findings:
        dest=QUARANTINE/(result["sha256"]+p.suffix)
        shutil.move(str(p),str(dest)); result["disposition"]="quarantined"; result["quarantine_path"]=str(dest)
    return result

def compare(root):
    root=Path(root).expanduser().resolve(); key=hashlib.sha256(str(root).encode()).hexdigest()[:16]; bf=BASELINE_DIR/(key+".json")
    if not bf.exists(): raise FileNotFoundError("No baseline found. Run baseline first.")
    old=json.loads(bf.read_text(encoding="utf-8")); oldmap={x["path"]:x for x in old["files"]}; new=inventory(root); newmap={x["path"]:x for x in new}
    added=[newmap[k] for k in newmap.keys()-oldmap.keys()]; removed=[oldmap[k] for k in oldmap.keys()-newmap.keys()]
    changed=[{"before":oldmap[k],"after":newmap[k]} for k in newmap.keys() & oldmap.keys() if newmap[k]["sha256"]!=oldmap[k]["sha256"]]
    suspicious=[]
    for x in added+changed:
        item=x.get("after",x); suspicious.extend([{"path":item["path"],**i} for i in malware_indicators(item["path"])])
    return {"tool":"Cyber Terrafor Professional","version":"11.0.0","timestamp":stamp(),"root":str(root),"added":added,"removed":removed,"changed":changed,"suspicious":suspicious,"ransomware_signal":len(suspicious)>=3 or any(i.get("indicator")=="ransomware-like extension" for i in suspicious)}

def monitor(root, interval=2.0, once=False):
    while True:
        result=compare(root)
        out=REPORTS/(datetime.now().strftime("%Y%m%d_%H%M%S")+"_ransomware_guard.json")
        out.write_text(json.dumps(result,indent=2),encoding="utf-8")
        print(json.dumps({"ransomware_signal":result["ransomware_signal"],"added":len(result["added"]),"changed":len(result["changed"]),"suspicious":len(result["suspicious"])},indent=2))
        if once: return result
        time.sleep(max(0.5,float(interval)))

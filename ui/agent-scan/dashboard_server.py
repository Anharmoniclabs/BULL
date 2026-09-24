#!/usr/bin/env python3
"""Local BULL dashboard adapter. Read-mostly interface over existing BULL modules."""
from __future__ import annotations
from http.server import SimpleHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
import argparse,json,os,subprocess,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/"src"))
from bulldog.agent_sentinel import AgentSentinel
from bulldog.assurance import evaluate_assurance
from bulldog.audit import AuditLedger
from bulldog.malware_scanner import MalwareScanner,MalwareScannerUnavailable
WEB=Path(__file__).resolve().parent
def git(*a):
    p=subprocess.run(["git","-C",str(ROOT),*a],capture_output=True,text=True,timeout=3)
    return (p.stdout or p.stderr).strip()
def repo_state():
    return {"root":str(ROOT),"branch":git("branch","--show-current"),"commit":git("rev-parse","--short","HEAD"),"status":git("status","--porcelain=v1").splitlines()[:100]}
def sentinel():
    r=AgentSentinel().evaluate();return {"score":r.score,"verdict":r.verdict,"signals":r.signals}
def assurance():
    try:return evaluate_assurance(dynamic=False).to_dict()
    except Exception as e:return {"error":str(e),"controls":[]}
def audit():
    raw=os.environ.get("BULL_AUDIT_LEDGER","").strip()
    if not raw:return {"configured":False}
    try:
        v=AuditLedger(raw).verify();return {"configured":True,"path":raw,"valid":v.valid,"records":v.records,"error":v.error,"head_hash":v.head_hash}
    except Exception as e:return {"configured":True,"path":raw,"error":str(e)}
def malware():
    try:
        s=MalwareScanner();return {"available":True,"engine":"clamav","bounded":s.bounded_scan}
    except MalwareScannerUnavailable as e:return {"available":False,"error":str(e)}
    except Exception as e:return {"available":False,"error":str(e)}
def system():
    a=assurance(); controls=a.get("controls",[])
    return {"time":time.time(),"repo":repo_state(),"sentinel":sentinel(),"audit":audit(),"malware":malware(),"assurance":{"profile":a.get("profile"),"source_complete":a.get("source_complete"),"deployment_complete":a.get("deployment_complete"),"controls":controls},"runtime":{"microvm_configured":bool(os.environ.get("BULL_MICROVM_CONFIG")),"policy_bundle":bool(os.environ.get("BULL_POLICY_BUNDLE")),"remote_anchor":bool(os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL") or os.environ.get("BULL_AUDIT_TRANSPORT"))}}
class H(SimpleHTTPRequestHandler):
    def __init__(self,*a,**kw):super().__init__(*a,directory=str(WEB),**kw)
    def json(self,obj,code=200):
        b=json.dumps(obj).encode();self.send_response(code);self.send_header("Content-Type","application/json");self.send_header("Cache-Control","no-store");self.send_header("Content-Length",str(len(b)));self.end_headers();self.wfile.write(b)
    def do_GET(self):
        p=urlparse(self.path).path
        if p=="/api/system":return self.json(system())
        if p=="/api/repo":return self.json(repo_state())
        if p=="/api/sentinel":return self.json(sentinel())
        if p=="/api/assurance":return self.json(assurance())
        if p=="/api/audit":return self.json(audit())
        return super().do_GET()
if __name__=="__main__":
    ap=argparse.ArgumentParser();ap.add_argument("--port",type=int,default=8000);x=ap.parse_args();print(f"BULL dashboard http://127.0.0.1:{x.port}");ThreadingHTTPServer(("127.0.0.1",x.port),H).serve_forever()

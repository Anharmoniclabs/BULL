#!/usr/bin/env python3
"""Passive public-web fetch helper for the BULL Agent Scan UI."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.request import Request,urlopen
from urllib.parse import urlparse
import argparse,ipaddress,json,re,socket
P={"agent":r"(?i)\b(agentic|autonomous\s+agent|ai[- ]agent|tool[- ]using\s+agent|function[_ -]?call|mcp\s+server|langgraph|autogen|crewai)\b","swarm":r"(?i)\b(swarm|multi[- ]agent|agent\s+cluster|orchestrator|coordinator|worker\s+agents?|delegat(?:e|ion))\b","botnet":r"(?i)\b(botnet|command[- ]and[- ]control|\bc2\b|beacon(?:ing)?|bot\s+herder|zombie\s+hosts?)\b","endpoint":r"(?i)\b(?:https?://|wss?://|/api/|/v1/|webhook|callback|endpoint)\S*"}
def public(host):
    try:
        for x in socket.getaddrinfo(host,None):
            a=ipaddress.ip_address(x[4][0])
            if a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast:return False
        return True
    except Exception:return False
def scan(url):
    u=urlparse(url)
    if u.scheme not in ("http","https") or not u.hostname or not public(u.hostname):raise ValueError("public http(s) targets only")
    q=Request(url,headers={"User-Agent":"BULL-AgentScan/0.1 passive-research"})
    with urlopen(q,timeout=8) as r:
        ct=r.headers.get("Content-Type","")
        if not any(x in ct for x in ("text/","json","javascript","xml")):raise ValueError("text-like responses only")
        data=r.read(1_000_000).decode("utf-8","replace")
    hits=[]
    for kind,p in P.items():
        for m in re.finditer(p,data):hits.append({"kind":kind,"signal":m.group(0)[:120],"offset":m.start()})
    return {"target":url,"bytes":len(data),"signals":hits[:500],"counts":{k:sum(h["kind"]==k for h in hits) for k in P},"note":"Heuristic indicators only; not proof of identity, botnet membership, or maliciousness."}
class H(BaseHTTPRequestHandler):
    def hdr(self,code=200):
        self.send_response(code);self.send_header("Content-Type","application/json");self.send_header("Access-Control-Allow-Origin","*");self.send_header("Access-Control-Allow-Headers","Content-Type");self.end_headers()
    def do_OPTIONS(self):self.hdr(204)
    def do_POST(self):
        if self.path!="/scan":self.hdr(404);return
        try:
            n=min(int(self.headers.get("Content-Length","0")),4096);o=json.loads(self.rfile.read(n));out=scan(o["url"]);self.hdr();self.wfile.write(json.dumps(out).encode())
        except Exception as e:self.hdr(400);self.wfile.write(json.dumps({"error":str(e)}).encode())
if __name__=="__main__":
    a=argparse.ArgumentParser();a.add_argument("--port",type=int,default=8765);x=a.parse_args();print(f"BULL safe fetch on 127.0.0.1:{x.port}");ThreadingHTTPServer(("127.0.0.1",x.port),H).serve_forever()

#!/usr/bin/env python3
"""BULL Command Center local interface adapter.

The product/UI is BULL. The repository's installed Python package remains the
existing internal import namespace defined by pyproject.toml.
"""
from __future__ import annotations

from dataclasses import asdict
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
import argparse, ipaddress, json, os, re, socket, subprocess, sys, time

ROOT = Path(__file__).resolve().parents[2]
WEB = Path(__file__).resolve().parent
BRAND = ROOT / "site" / "assets" / "brand"
sys.path.insert(0, str(ROOT / "src"))

from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Provenance
from bulldog.agent_sentinel import AgentSentinel
from bulldog.assurance import evaluate_assurance
from bulldog.audit import AuditLedger
from bulldog.malware_scanner import MalwareScanner, MalwareScannerUnavailable
from bulldog.adversary.registry import AdversaryRegistry
from bulldog.adversary.quarantine import QuarantineManager
from bulldog.trace_runtime import RuntimeTraceVerifier
from bulldog.multiagent.system import MultiAgentSystem

REGISTRY = AdversaryRegistry()
QUARANTINE = QuarantineManager()
SENTINEL = AgentSentinel()

SIGNALS = {
    "agent": re.compile(r"\b(agentic|autonomous\s+agent|ai[- ]agent|tool[- ]using\s+agent|function[_ -]?call|mcp\s+server|langgraph|autogen|crewai|agent\s+executor)\b", re.I),
    "swarm": re.compile(r"\b(swarm|multi[- ]agent|agent\s+cluster|orchestrator|coordinator|worker\s+agents?|delegat(?:e|ion)|agent\s+mesh)\b", re.I),
    "botnet": re.compile(r"\b(botnet|command[- ]and[- ]control|\bc2\b|beacon(?:ing)?|bot\s+herder|zombie\s+hosts?)\b", re.I),
    "endpoint": re.compile(r"\b(?:https?://|wss?://|/api/|/v1/|webhook|callback|endpoint)\S*", re.I),
}

def git(*args: str) -> str:
    p = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=4)
    return (p.stdout or p.stderr).strip()

def resolve_repo_path(raw: str) -> Path:
    raw = raw or "."
    candidate = (ROOT / raw).resolve()
    if candidate != ROOT and ROOT not in candidate.parents:
        raise ValueError("path must remain inside the BULL repository")
    return candidate

def repo_state() -> dict:
    status = git("status", "--porcelain=v1").splitlines()[:200]
    return {
        "root": str(ROOT),
        "branch": git("branch", "--show-current"),
        "commit": git("rev-parse", "--short", "HEAD"),
        "remote": git("remote", "get-url", "origin"),
        "dirty": bool(status),
        "status": status,
    }

def list_files(raw: str = ".") -> dict:
    path = resolve_repo_path(raw)
    if not path.exists() or not path.is_dir():
        raise ValueError("directory does not exist")
    items = []
    for child in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))[:400]:
        if child.name == ".git":
            continue
        st = child.stat()
        items.append({"name": child.name, "path": str(child.relative_to(ROOT)), "dir": child.is_dir(), "size": st.st_size})
    return {"path": str(path.relative_to(ROOT)) if path != ROOT else ".", "items": items}

def read_file(raw: str) -> dict:
    path = resolve_repo_path(raw)
    if not path.is_file():
        raise ValueError("not a file")
    if path.stat().st_size > 512 * 1024:
        raise ValueError("file exceeds dashboard read limit")
    data = path.read_bytes()
    if b"\x00" in data:
        raise ValueError("binary file preview disabled")
    return {"path": str(path.relative_to(ROOT)), "size": len(data), "content": data.decode("utf-8", "replace")}

def sentinel_state() -> dict:
    report = SENTINEL.evaluate()
    return {"score": round(report.score, 4), "verdict": report.verdict, "signals": report.signals}

def assurance_state(dynamic: bool = False) -> dict:
    try:
        return evaluate_assurance(dynamic=dynamic).to_dict()
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}", "controls": []}

def audit_path() -> str:
    return os.environ.get("BULL_AUDIT_LEDGER", "").strip()

def audit_state() -> dict:
    raw = audit_path()
    if not raw:
        return {"configured": False, "valid": None, "records": 0}
    try:
        v = AuditLedger(raw).verify()
        return {"configured": True, "path": raw, "valid": v.valid, "records": v.records, "error": v.error, "head_hash": v.head_hash}
    except Exception as exc:
        return {"configured": True, "path": raw, "valid": False, "records": 0, "error": f"{type(exc).__name__}: {exc}"}

def audit_events(limit: int = 60) -> list[dict]:
    raw = audit_path()
    if not raw:
        return []
    path = Path(raw)
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text("utf-8", errors="replace").splitlines()[-max(1, min(limit, 200)):]:
        try:
            x = json.loads(line)
        except Exception:
            continue
        rows.append({
            "timestamp": x.get("timestamp"),
            "record_type": x.get("record_type"),
            "actor": x.get("actor"),
            "operation": x.get("operation") or x.get("event_type"),
            "resource": x.get("resource"),
            "capability": x.get("capability"),
            "decision": x.get("decision"),
            "risk": x.get("risk"),
            "reasons": x.get("reasons", []),
            "record_hash": x.get("record_hash"),
        })
    return rows

def malware_state() -> dict:
    try:
        s = MalwareScanner()
        return {"available": True, "engine": "clamav", "bounded": s.bounded_scan, "binary": s.clamscan}
    except MalwareScannerUnavailable as exc:
        return {"available": False, "error": str(exc)}
    except Exception as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}

def runtime_state() -> dict:
    return {
        "policy_bundle": bool(os.environ.get("BULL_POLICY_BUNDLE")),
        "integrity_manifest": bool(os.environ.get("BULL_INTEGRITY_MANIFEST")),
        "microvm_configured": bool(os.environ.get("BULL_MICROVM_CONFIG") or os.environ.get("BULL_MICROVM_KERNEL")),
        "audit_ledger": bool(audit_path()),
        "remote_anchor": bool(os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL") or os.environ.get("BULL_AUDIT_TRANSPORT")),
        "seccomp_profile": os.environ.get("BULL_SECCOMP_PROFILE", "") or "unset",
        "cgroup_parent": bool(os.environ.get("BULL_CGROUP_PARENT")),
        "snapshot_root": bool(os.environ.get("BULL_SNAPSHOT_ROOT")),
        "hardware_approval": bool(os.environ.get("BULL_HARDWARE_APPROVAL") or os.environ.get("BULL_APPROVAL_CONFIG")),
    }

def system_state() -> dict:
    a = assurance_state(False)
    return {
        "product": "BULL",
        "time": time.time(),
        "repo": repo_state(),
        "sentinel": sentinel_state(),
        "audit": audit_state(),
        "malware": malware_state(),
        "runtime": runtime_state(),
        "assurance": {
            "profile": a.get("profile"),
            "source_complete": a.get("source_complete"),
            "deployment_complete": a.get("deployment_complete"),
            "release_complete": a.get("release_complete"),
            "controls": a.get("controls", []),
            "error": a.get("error"),
        },
        "adversary": REGISTRY.tabulate(),
    }

def brand_manifest() -> dict:
    path = BRAND / "manifest.json"
    data = json.loads(path.read_text("utf-8"))
    data["base_url"] = "/brand/"
    return data

def architecture() -> dict:
    mas = MultiAgentSystem()
    agents = [mas.coordinator, mas.policy, mas.executor, mas.auditor, mas.verifier, mas.honeytoken]
    multi = [{"name": a.identity.name if hasattr(a, "identity") else getattr(a, "name", a.__class__.__name__),
              "id": getattr(getattr(a, "identity", None), "agent_id", getattr(a, "agent_id", "")),
              "type": "BULL multi-agent role"} for a in agents]
    return {
        "nodes": [
            {"id":"proposal","label":"Untrusted proposal","group":"input"},
            {"id":"dispatcher","label":"Production dispatcher","group":"authority"},
            {"id":"policy","label":"Policy + command binding","group":"policy"},
            {"id":"scan","label":"Malware admission scan","group":"scan"},
            {"id":"sandbox","label":"Sandbox / MicroVM","group":"isolation"},
            {"id":"audit","label":"Authenticated audit","group":"audit"},
            {"id":"approval","label":"Human approval","group":"authority"},
            {"id":"sentinel","label":"Agent Sentinel","group":"detection"},
        ],
        "edges": [
            ["proposal","dispatcher"],["dispatcher","policy"],["policy","scan"],["scan","sandbox"],["sandbox","audit"],
            ["dispatcher","approval"],["sentinel","policy"]
        ],
        "multiagent": multi,
        "capabilities": [c.value for c in Capability],
        "provenance": [p.value for p in Provenance],
    }

def policy_evaluate(payload: dict) -> dict:
    action = ActionRequest.from_dict(payload)
    ev = BulldogEngine().evaluate(action)
    return {"decision": ev.decision.value, "risk": ev.risk, "reasons": list(ev.reasons), "hard_block": ev.hard_block}

def trace_simulate(payload: dict) -> dict:
    v = RuntimeTraceVerifier()
    states = [asdict(v.snapshot())]
    for item in payload.get("events", [])[:50]:
        state = v.emit(str(item["transition"]), **dict(item.get("data") or {}))
        states.append(asdict(state))
    return {"states": states, "events": [{"transition": e.transition, "data": e.data} for e in v.events]}

def scan_file(payload: dict) -> dict:
    path = resolve_repo_path(str(payload.get("path", "")))
    if not path.is_file():
        raise ValueError("scan target must be a file inside the BULL repository")
    r = MalwareScanner().scan_file(path, timeout_seconds=float(payload.get("timeout", 30)))
    return asdict(r)

def public_host(host: str) -> bool:
    try:
        for item in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(item[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        return True
    except Exception:
        return False

def fetch_public_text(url: str) -> str:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname or not public_host(u.hostname):
        raise ValueError("agent scan fetch accepts public http(s) targets only")
    req = Request(url, headers={"User-Agent": "BULL-AgentScan/0.2 passive-research"})
    with urlopen(req, timeout=8) as r:
        ctype = r.headers.get("Content-Type", "")
        if not any(x in ctype for x in ("text/", "json", "javascript", "xml")):
            raise ValueError("agent scan fetch accepts text-like responses only")
        return r.read(1_000_000).decode("utf-8", "replace")

def agent_scan(payload: dict) -> dict:
    text = str(payload.get("text") or "")
    source = "pasted-artifact"
    if payload.get("url"):
        source = str(payload["url"])
        text = fetch_public_text(source)
    if not text:
        raise ValueError("provide text or a public URL")
    hits = []
    for kind, regex in SIGNALS.items():
        for m in regex.finditer(text):
            hits.append({"kind": kind, "signal": m.group(0)[:120], "offset": m.start()})
    findings = sorted({h["kind"] + ":" + h["signal"].lower() for h in hits if h["kind"] != "endpoint"})[:80]
    task_signature = " ".join(sorted({h["signal"].lower() for h in hits if h["kind"] in {"agent","swarm","botnet"}}))[:1000]
    record = None
    if findings:
        record = REGISTRY.upsert(source[:200], initial_task=task_signature, findings=findings)
    counts = {k: sum(h["kind"] == k for h in hits) for k in SIGNALS}
    return {
        "source": source, "bytes": len(text.encode()), "counts": counts, "signals": hits[:500],
        "record": record.to_dict() if record else None,
        "registry": REGISTRY.tabulate(),
        "note": "Heuristic discovery evidence only; signals are not attribution or proof of maliciousness.",
    }

def adversary_state() -> dict:
    return {"summary": REGISTRY.tabulate(), "records": [r.to_dict() for r in REGISTRY.all()], "cells": [c.to_dict() for c in QUARANTINE.cells()]}

def quarantine_record(payload: dict) -> dict:
    record = REGISTRY.get(str(payload.get("attacker_id", "")))
    if record is None:
        raise ValueError("unknown observed record")
    cell = QUARANTINE.quarantine(record)
    return {"record": record.to_dict(), "cell": cell.to_dict(), "note": "This endpoint exercises BULL quarantine classification/bookkeeping; OS isolation is enforced only by the runtime path."}

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def send_json(self, obj, code=200):
        raw = json.dumps(obj, indent=None, sort_keys=False, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self, limit=1_100_000):
        n = min(int(self.headers.get("Content-Length", "0") or 0), limit)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        p, q = u.path, parse_qs(u.query)
        try:
            if p == "/api/system": return self.send_json(system_state())
            if p == "/api/repo": return self.send_json(repo_state())
            if p == "/api/files": return self.send_json(list_files(q.get("path", ["."])[0]))
            if p == "/api/file": return self.send_json(read_file(q.get("path", [""])[0]))
            if p == "/api/sentinel": return self.send_json(sentinel_state())
            if p == "/api/assurance": return self.send_json(assurance_state(q.get("dynamic", ["0"])[0] == "1"))
            if p == "/api/audit": return self.send_json(audit_state())
            if p == "/api/audit/events": return self.send_json(audit_events(int(q.get("limit", ["60"])[0])))
            if p == "/api/brand": return self.send_json(brand_manifest())
            if p == "/api/architecture": return self.send_json(architecture())
            if p == "/api/adversary": return self.send_json(adversary_state())
            if p.startswith("/brand/"):
                name = p.removeprefix("/brand/")
                if "/" in name or name not in brand_manifest().get("files", {}):
                    raise ValueError("unknown BULL brand asset")
                path = BRAND / name
                if not path.is_file(): raise ValueError("brand asset unavailable")
                data = path.read_bytes()
                ctype = "image/svg+xml" if name.endswith(".svg") else "image/png" if name.endswith(".png") else "application/octet-stream"
                self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data); return
            return super().do_GET()
        except Exception as exc:
            return self.send_json({"error": f"{type(exc).__name__}: {exc}"}, 400)

    def do_POST(self):
        p = urlparse(self.path).path
        try:
            payload = self.body()
            if p == "/api/policy/evaluate": return self.send_json(policy_evaluate(payload))
            if p == "/api/trace/simulate": return self.send_json(trace_simulate(payload))
            if p == "/api/malware/scan": return self.send_json(scan_file(payload))
            if p == "/api/agent-scan": return self.send_json(agent_scan(payload))
            if p == "/api/adversary/quarantine": return self.send_json(quarantine_record(payload))
            return self.send_json({"error": "unknown endpoint"}, 404)
        except Exception as exc:
            return self.send_json({"error": f"{type(exc).__name__}: {exc}"}, 400)

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="BULL Command Center")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    print(f"BULL Command Center: http://127.0.0.1:{args.port}")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()

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
import argparse, ipaddress, json, os, re, shutil, socket, subprocess, sys, threading, time, uuid, webbrowser

ROOT = Path(__file__).resolve().parents[2]
WEB = Path(__file__).resolve().parent
BRAND = ROOT / "site" / "assets" / "brand"
sys.path.insert(0, str(ROOT))
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
from tools.deployment_check import checked_assets, probe_kvm

REGISTRY = AdversaryRegistry()
QUARANTINE = QuarantineManager()
SENTINEL = AgentSentinel()
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
STATE_ROOT = Path(os.environ.get("BULL_COMMAND_CENTER_STATE", str(Path.home() / ".local/share/bull/command-center"))).expanduser()
STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
try:
    STATE_ROOT.chmod(0o700)
except OSError:
    pass

AUDIT_ROOT = STATE_ROOT / "audit"
SNAPSHOT_ROOT = STATE_ROOT / "snapshots"
AUDIT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
SNAPSHOT_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
os.environ.setdefault("BULL_COMMAND_CENTER_STATE", str(STATE_ROOT))
os.environ.setdefault("BULL_AUDIT_LEDGER", str(AUDIT_ROOT / "ledger.jsonl"))
os.environ.setdefault("BULL_SNAPSHOT_ROOT", str(SNAPSHOT_ROOT))

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
        "microvm_configured": bool(os.environ.get("BULL_MICROVM_CONFIG_FILE") or os.environ.get("BULL_DEPLOYMENT_ASSETS")),
        "audit_ledger": bool(audit_path()),
        "remote_anchor": bool(os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL") or os.environ.get("BULL_AUDIT_TRANSPORT")),
        "seccomp_profile": os.environ.get("BULL_SECCOMP_PROFILE", "") or "unset",
        "cgroup_parent": bool(os.environ.get("BULL_CGROUP_PARENT")),
        "snapshot_root": bool(os.environ.get("BULL_SNAPSHOT_ROOT")),
        "hardware_approval": bool(os.environ.get("BULL_HARDWARE_APPROVAL") or os.environ.get("BULL_APPROVAL_CONFIG")),
    }

def _asset_manifest_path() -> Path | None:
    raw = os.environ.get("BULL_DEPLOYMENT_ASSETS", "").strip()
    if raw:
        return Path(raw).expanduser()
    default = STATE_ROOT / "guest-2026-09-22" / "assets-local.json"
    return default if default.exists() else None

def vm_state() -> dict:
    readiness = probe_kvm()
    manifest = _asset_manifest_path()
    assets = None
    asset_error = None
    if manifest is not None:
        try:
            assets = checked_assets(manifest.resolve(strict=True))
        except Exception as exc:
            asset_error = f"{type(exc).__name__}: {exc}"
    tools = {
        name: shutil.which(name)
        for name in ("qemu-system-x86_64", "openssl", "mkfs.ext4", "debugfs")
    }
    config_raw = os.environ.get("BULL_MICROVM_CONFIG_FILE", "").strip()
    config = None
    config_error = None
    if config_raw:
        try:
            config = str(Path(config_raw).expanduser().resolve(strict=True))
        except Exception as exc:
            config_error = f"{type(exc).__name__}: {exc}"
    return {
        "kvm": readiness,
        "asset_manifest": str(manifest) if manifest else None,
        "assets_verified": assets is not None,
        "assets": assets,
        "asset_error": asset_error,
        "tools": tools,
        "microvm_config": config,
        "config_error": config_error,
        "architecture": {
            "mode": "one-shot KVM guest",
            "persistent_session": False,
            "software_emulation_fallback": False,
            "guest_network_device": False,
            "control_channel": "virtio-serial when configured",
            "audit_channel": "virtio-serial when configured",
        },
    }

def _job_public(job: dict) -> dict:
    return {
        "id": job["id"],
        "kind": job["kind"],
        "status": job["status"],
        "started": job["started"],
        "finished": job.get("finished"),
        "returncode": job.get("returncode"),
        "output_dir": job["output_dir"],
        "log": job["log"],
        "command_label": job["command_label"],
    }

def _job_runner(job_id: str, command: list[str], env: dict[str, str]) -> None:
    with JOBS_LOCK:
        job = JOBS[job_id]
        log_path = Path(job["log"])
    try:
        with log_path.open("wb") as stream:
            proc = subprocess.Popen(
                command,
                cwd=ROOT,
                env=env,
                stdout=stream,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            with JOBS_LOCK:
                JOBS[job_id]["pid"] = proc.pid
            code = proc.wait()
        with JOBS_LOCK:
            JOBS[job_id]["returncode"] = code
            JOBS[job_id]["status"] = "PASS" if code == 0 else "FAIL"
            JOBS[job_id]["finished"] = time.time()
    except Exception as exc:
        try:
            with log_path.open("ab") as stream:
                stream.write(("\nJOB ERROR: " + f"{type(exc).__name__}: {exc}" + "\n").encode())
        except OSError:
            pass
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "FAIL"
            JOBS[job_id]["error"] = f"{type(exc).__name__}: {exc}"
            JOBS[job_id]["finished"] = time.time()

def _start_job(kind: str, command: list[str], output_dir: Path, label: str) -> dict:
    output_dir = output_dir.expanduser().resolve()
    if ROOT == output_dir or ROOT in output_dir.parents:
        raise ValueError("runtime evidence must remain outside the repository")
    output_dir.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if output_dir.exists():
        raise ValueError("job output path already exists")
    log_path = output_dir.parent / (output_dir.name + ".log")
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "kind": kind,
        "status": "RUNNING",
        "started": time.time(),
        "output_dir": str(output_dir),
        "log": str(log_path),
        "command_label": label,
    }
    with JOBS_LOCK:
        JOBS[job_id] = job
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    thread = threading.Thread(target=_job_runner, args=(job_id, command, env), daemon=True)
    thread.start()
    return _job_public(job)

def jobs_state() -> list[dict]:
    with JOBS_LOCK:
        return [_job_public(JOBS[key]) for key in sorted(JOBS, key=lambda x: JOBS[x]["started"], reverse=True)]

def job_state(job_id: str) -> dict:
    with JOBS_LOCK:
        if job_id not in JOBS:
            raise ValueError("unknown command-center job")
        return _job_public(JOBS[job_id])

def job_log(job_id: str) -> dict:
    job = job_state(job_id)
    path = Path(job["log"])
    if not path.exists():
        return {"id": job_id, "log": ""}
    data = path.read_bytes()
    if len(data) > 256 * 1024:
        data = data[-256 * 1024:]
    return {"id": job_id, "log": data.decode("utf-8", "replace")}

def start_guest_install_job() -> dict:
    target = STATE_ROOT / "guest-2026-09-22"
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    marker = STATE_ROOT / f"guest-install-{stamp}-{uuid.uuid4().hex[:6]}"
    cmd = [
        sys.executable,
        str(WEB / "install_guest_assets.py"),
        "--output",
        str(target),
    ]
    return _start_job(
        "guest-asset-install",
        cmd,
        marker,
        "Download + verify published BULL guest",
    )

def start_vm_job(payload: dict) -> dict:
    case = str(payload.get("case", "all"))
    if case not in {"all", "allowed", "denied", "timeout", "cancel", "missing-protection"}:
        raise ValueError("invalid KVM integration case")
    state = vm_state()
    if state["kvm"].get("status") != "PASS":
        raise ValueError("KVM is not ready: " + str(state["kvm"].get("reason", "unknown")))
    missing = [name for name, value in state["tools"].items() if not value]
    if missing:
        raise ValueError("missing required VM tools: " + ", ".join(missing))
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = STATE_ROOT / f"kvm-{case}-{stamp}-{uuid.uuid4().hex[:6]}"

    # Custom/operator-provided verified assets remain supported. Otherwise the
    # one-click wrapper transparently fetches the pinned published BULL guest
    # release into private command-center state, verifies hashes, and boots it.
    if state["assets_verified"]:
        cmd = [
            sys.executable, "microvm/integration.py",
            "--case", case,
            "--output", str(out),
            "--cpu-profile", os.environ.get("BULL_MICROVM_CPU_PROFILE", "host"),
        ]
        for name, entry in state["assets"].items():
            cmd.extend(["--" + name, entry["path"]])
        label = f"BULL KVM {case}"
    else:
        asset_dir = STATE_ROOT / "guest-2026-09-22"
        cmd = [
            sys.executable, str(WEB / "run_release_kvm.py"),
            "--case", case,
            "--output", str(out),
            "--asset-dir", str(asset_dir),
            "--cpu-profile", os.environ.get("BULL_MICROVM_CPU_PROFILE", "host"),
        ]
        label = f"BULL KVM {case} (auto-pull published guest)"
    return _start_job("kvm-integration", cmd, out, label)

def start_deployment_job() -> dict:
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = STATE_ROOT / f"deployment-{stamp}-{uuid.uuid4().hex[:6]}"
    cmd = [sys.executable, "tools/deployment_check.py", "--output", str(out)]
    assets = _asset_manifest_path()
    if assets is not None:
        cmd.extend(["--assets", str(assets.expanduser().resolve(strict=True))])
    tla = os.environ.get("BULL_TLA_JAR", "").strip()
    if tla:
        cmd.extend(["--tla-jar", str(Path(tla).expanduser().resolve(strict=True))])
    deployment = os.environ.get("BULL_DEPLOYMENT_STATE", "").strip()
    if deployment:
        cmd.extend(["--deployment", str(Path(deployment).expanduser().resolve(strict=True))])
    return _start_job("deployment-check", cmd, out, "BULL deployment check")

def microvm_plan() -> dict:
    raw = os.environ.get("BULL_MICROVM_CONFIG_FILE", "").strip()
    if not raw:
        raise ValueError("BULL_MICROVM_CONFIG_FILE is not configured")
    config = Path(raw).expanduser().resolve(strict=True)
    proc = subprocess.run(
        [str(ROOT / "microvm/run-bull-microvm.sh"), "--config", str(config), "--print-command"],
        cwd=ROOT,
        env=dict(os.environ, PYTHONPATH=str(ROOT / "src")),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=30,
        check=False,
    )
    return {"returncode": proc.returncode, "output": proc.stdout, "validated": proc.returncode == 0}

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
        "vm": vm_state(),
        "jobs": jobs_state(),
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
            if p == "/api/vm": return self.send_json(vm_state())
            if p == "/api/jobs": return self.send_json(jobs_state())
            if p == "/api/job": return self.send_json(job_state(q.get("id", [""])[0]))
            if p == "/api/job/log": return self.send_json(job_log(q.get("id", [""])[0]))
            if p == "/api/microvm/plan": return self.send_json(microvm_plan())
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
            if p == "/api/vm/install-assets": return self.send_json(start_guest_install_job(), 202)
            if p == "/api/vm/run": return self.send_json(start_vm_job(payload), 202)
            if p == "/api/deployment/run": return self.send_json(start_deployment_job(), 202)
            return self.send_json({"error": "unknown endpoint"}, 404)
        except Exception as exc:
            return self.send_json({"error": f"{type(exc).__name__}: {exc}"}, 400)

def _codespaces_url(port: int) -> str | None:
    if os.environ.get("CODESPACES", "").lower() != "true":
        return None
    name = os.environ.get("CODESPACE_NAME", "").strip()
    if not name:
        return None
    domain = os.environ.get(
        "GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN",
        "app.github.dev",
    ).strip()
    return f"https://{name}-{port}.{domain}/"


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="BULL Command Center")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--open-browser", action="store_true")
    args = ap.parse_args()

    codespaces = os.environ.get("CODESPACES", "").lower() == "true"
    host = args.host or ("0.0.0.0" if codespaces else "127.0.0.1")
    local_url = f"http://127.0.0.1:{args.port}/"
    operator_url = _codespaces_url(args.port) or local_url

    print("=" * 78)
    print("BULL COMMAND CENTER")
    print("=" * 78)
    print("bind:", f"{host}:{args.port}")
    print("open:", operator_url)
    print("state:", STATE_ROOT)
    print("audit:", os.environ.get("BULL_AUDIT_LEDGER"))
    print("snapshot scratch:", os.environ.get("BULL_SNAPSHOT_ROOT"))
    if host not in {"127.0.0.1", "::1", "localhost"}:
        print("network note: keep the forwarded/listening port private and authenticated")
    print("=" * 78)

    if args.open_browser and not codespaces and host in {"127.0.0.1", "::1", "localhost"}:
        threading.Thread(target=webbrowser.open, args=(local_url,), daemon=True).start()

    ThreadingHTTPServer((host, args.port), Handler).serve_forever()

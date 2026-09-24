from __future__ import annotations

"""Local operator console for BULL.

The console is intentionally a thin presentation/control plane over BULL's
existing runtime components. It does not replace the policy engine, sandbox,
audit ledger, malware scanner, MicroVM launcher, or assurance gates.

Security properties:
- loopback bind by default;
- no arbitrary shell endpoint;
- no secret/environment dump;
- process command lines are reduced to executable names;
- operator actions are bounded to scan/verify/attest/policy-evaluate probes.
"""

from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Any
from urllib.parse import urlparse, urlsplit, urlunsplit
import json
import os
import platform
import shutil
import socket
import time

from .assurance import evaluate_assurance
from .audit import AuditLedger
from .malware_scanner import MalwareScanner, MalwareScannerError, MalwareScannerUnavailable
from .models import ActionRequest, Capability, Decision, Provenance
from .policy import DeterministicPolicy


@dataclass(frozen=True)
class ObservedEntity:
    entity_id: str
    pid: int
    ppid: int | None
    family: str
    kind: str
    executable: str
    source: str
    confidence: float
    behavior: tuple[str, ...]
    child_count: int
    socket_count: int
    state: str
    last_seen: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["behavior"] = list(self.behavior)
        return data


AGENT_MARKERS: tuple[tuple[str, str, str, float], ...] = (
    ("claude", "Claude", "agent", 0.94),
    ("cursor", "Cursor", "agent", 0.90),
    ("aider", "Aider", "agent", 0.94),
    ("copilot", "Copilot", "agent", 0.88),
    ("codeium", "Codeium", "agent", 0.86),
    ("codex", "Codex", "agent", 0.92),
    ("ollama", "Ollama", "model-runtime", 0.82),
    ("lmstudio", "LM Studio", "model-runtime", 0.82),
    ("open-webui", "Open WebUI", "agent-ui", 0.80),
    ("langgraph", "LangGraph", "agent-framework", 0.82),
    ("langchain", "LangChain", "agent-framework", 0.74),
    ("autogen", "AutoGen", "agent-framework", 0.82),
    ("crewai", "CrewAI", "agent-framework", 0.82),
    ("mcp", "MCP", "agent-protocol", 0.70),
    ("anrii", "ANRII", "agent-harness", 0.92),
    ("eldrae", "ELDRAE", "agent-harness", 0.92),
)

RUNTIME_MARKERS: tuple[tuple[str, str, str, float], ...] = (
    ("qemu-system", "QEMU/KVM", "microvm", 0.98),
    ("bull", "BULL", "security-runtime", 0.85),
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_text(path: Path, limit: int = 4096) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def _package_version() -> str:
    try:
        return version("bulldog-ai-firewall")
    except PackageNotFoundError:
        return "source"


def _redact_resource(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value)
    except Exception:
        return value[:240]
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        query = "[redacted]" if parsed.query else ""
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))
    return value[:240]


def _tail_records(path: Path, limit: int = 120) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: deque[dict[str, Any]] = deque(maxlen=limit)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except Exception:
                    continue
                if isinstance(item, dict):
                    rows.append(item)
    except OSError:
        return []
    return list(rows)


class ProcObserver:
    """Read-only Linux process discovery with deliberately narrow exposure."""

    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = Path(proc_root)

    def _children(self, pid: int) -> int:
        raw = _safe_text(self.proc_root / str(pid) / "task" / str(pid) / "children")
        if not raw.strip():
            return 0
        return len(raw.split())

    def _socket_count(self, pid: int) -> int:
        fd_root = self.proc_root / str(pid) / "fd"
        count = 0
        try:
            for item in fd_root.iterdir():
                try:
                    target = os.readlink(item)
                except OSError:
                    continue
                if target.startswith("socket:["):
                    count += 1
        except OSError:
            return 0
        return count

    def _ppid(self, pid: int) -> int | None:
        for line in _safe_text(self.proc_root / str(pid) / "status").splitlines():
            if line.startswith("PPid:"):
                try:
                    return int(line.split(":", 1)[1].strip())
                except ValueError:
                    return None
        return None

    def _identity(self, pid: int) -> tuple[str, str]:
        comm = _safe_text(self.proc_root / str(pid) / "comm", 256).strip()
        executable = ""
        try:
            executable = Path(os.readlink(self.proc_root / str(pid) / "exe")).name
        except OSError:
            pass
        if not executable:
            raw = b""
            try:
                raw = (self.proc_root / str(pid) / "cmdline").read_bytes()[:1024]
            except OSError:
                pass
            first = raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            executable = Path(first).name if first else comm
        return comm, executable

    @staticmethod
    def _classify(text: str) -> tuple[str, str, float] | None:
        lower = text.lower()
        for marker, family, kind, confidence in AGENT_MARKERS:
            if marker in lower:
                return family, kind, confidence
        for marker, family, kind, confidence in RUNTIME_MARKERS:
            if marker in lower:
                return family, kind, confidence
        return None

    def discover(self, limit: int = 160) -> list[ObservedEntity]:
        if not self.proc_root.is_dir():
            return []
        found: list[ObservedEntity] = []
        now = _utcnow()
        try:
            entries = sorted(
                (p for p in self.proc_root.iterdir() if p.name.isdigit()),
                key=lambda p: int(p.name),
            )
        except OSError:
            return []
        for entry in entries:
            pid = int(entry.name)
            comm, executable = self._identity(pid)
            classification = self._classify(f"{comm} {executable}")
            if classification is None:
                continue
            family, kind, confidence = classification
            child_count = self._children(pid)
            socket_count = self._socket_count(pid)
            score = min(0.99, confidence + min(child_count, 4) * 0.015 + min(socket_count, 6) * 0.01)
            behavior: list[str] = []
            if child_count:
                behavior.append(f"{child_count} child process{'es' if child_count != 1 else ''}")
            if socket_count:
                behavior.append(f"{socket_count} open socket{'s' if socket_count != 1 else ''}")
            if not behavior:
                behavior.append("process marker observed")
            state = "Runtime" if kind in {"microvm", "security-runtime"} else "Observe"
            found.append(
                ObservedEntity(
                    entity_id=f"pid-{pid}",
                    pid=pid,
                    ppid=self._ppid(pid),
                    family=family,
                    kind=kind,
                    executable=executable or comm or "unknown",
                    source="local /proc",
                    confidence=round(score, 3),
                    behavior=tuple(behavior),
                    child_count=child_count,
                    socket_count=socket_count,
                    state=state,
                    last_seen=now,
                )
            )
            if len(found) >= limit:
                break
        return found

    def service_summary(self) -> dict[str, Any]:
        listeners = 0
        connections = 0
        for name in ("tcp", "tcp6"):
            path = self.proc_root / "net" / name
            text = _safe_text(path, 2_000_000)
            lines = text.splitlines()[1:]
            for line in lines:
                cols = line.split()
                if len(cols) < 4:
                    continue
                state = cols[3]
                if state == "0A":
                    listeners += 1
                elif state == "01":
                    connections += 1
        return {
            "listening_tcp": listeners,
            "established_tcp": connections,
            "source": "/proc/net/tcp*",
        }


class ControlPlane:
    def __init__(
        self,
        *,
        workspace: str | Path | None = None,
        refresh_seconds: float = 2.0,
        auto_scan: bool = True,
        dynamic_attestation: bool = True,
        proc_root: str | Path = "/proc",
    ) -> None:
        self.workspace = Path(workspace or os.getcwd()).resolve()
        self.refresh_seconds = max(0.5, float(refresh_seconds))
        self.auto_scan = bool(auto_scan)
        self.dynamic_attestation = bool(dynamic_attestation)
        self.proc = ProcObserver(proc_root)
        self._lock = Lock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._events: deque[dict[str, Any]] = deque(maxlen=200)
        self._entities: list[ObservedEntity] = []
        self._services: dict[str, Any] = {}
        self._assurance: dict[str, Any] = {
            "status": "pending",
            "dynamic": False,
            "controls": [],
            "updated_at": None,
            "error": None,
        }
        self._malware: dict[str, Any] = {
            "status": "initializing",
            "engine": "clamav",
            "available": False,
            "running": False,
            "clean": None,
            "files_scanned": 0,
            "detections": [],
            "updated_at": None,
            "error": None,
        }
        self._last_refresh = 0.0
        self.refresh()
        self._probe_malware_availability()

    def _event(self, event_type: str, message: str, *, level: str = "info") -> None:
        with self._lock:
            self._events.appendleft(
                {
                    "timestamp": _utcnow(),
                    "type": event_type,
                    "level": level,
                    "message": message[:500],
                }
            )

    def _probe_malware_availability(self) -> None:
        try:
            scanner = MalwareScanner()
        except MalwareScannerUnavailable as exc:
            with self._lock:
                self._malware.update(
                    {
                        "status": "unavailable",
                        "available": False,
                        "running": False,
                        "error": str(exc),
                        "updated_at": _utcnow(),
                    }
                )
            return
        except Exception as exc:
            with self._lock:
                self._malware.update(
                    {
                        "status": "error",
                        "available": False,
                        "running": False,
                        "error": f"{type(exc).__name__}: {exc}",
                        "updated_at": _utcnow(),
                    }
                )
            return
        with self._lock:
            self._malware.update(
                {
                    "status": "ready",
                    "available": True,
                    "running": False,
                    "engine_path": scanner.clamscan,
                    "error": None,
                    "updated_at": _utcnow(),
                }
            )

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = Thread(target=self._run, name="bull-control-plane", daemon=True)
        self._thread.start()
        if self.auto_scan:
            self.start_malware_scan()
        if self.dynamic_attestation:
            self.start_attestation(dynamic=True)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.refresh_seconds * 2))

    def _run(self) -> None:
        while not self._stop.wait(self.refresh_seconds):
            try:
                self.refresh()
            except Exception as exc:
                self._event("observer", f"Live refresh failed: {type(exc).__name__}: {exc}", level="error")

    def refresh(self) -> None:
        entities = self.proc.discover()
        services = self.proc.service_summary()
        with self._lock:
            self._entities = entities
            self._services = services
            self._last_refresh = time.monotonic()

    def start_attestation(self, *, dynamic: bool = True) -> bool:
        with self._lock:
            if self._assurance.get("status") == "running":
                return False
            self._assurance.update(
                {
                    "status": "running",
                    "dynamic": bool(dynamic),
                    "updated_at": _utcnow(),
                    "error": None,
                }
            )
        Thread(
            target=self._attest_worker,
            kwargs={"dynamic": dynamic},
            name="bull-assurance-probe",
            daemon=True,
        ).start()
        return True

    def _attest_worker(self, *, dynamic: bool) -> None:
        self._event("attestation", "Runtime assurance probe started.")
        try:
            report = evaluate_assurance(dynamic=dynamic)
            data = report.to_dict()
            with self._lock:
                self._assurance = {
                    "status": "complete",
                    "dynamic": bool(dynamic),
                    "source_complete": report.source_complete,
                    "deployment_complete": report.deployment_complete,
                    "release_complete": report.release_complete,
                    "certified": report.certified,
                    "profile": report.profile_id,
                    "profile_digest": report.profile_digest,
                    "controls": data["controls"],
                    "updated_at": _utcnow(),
                    "error": None,
                }
            self._event(
                "attestation",
                "Runtime assurance probe completed."
                if report.deployment_complete
                else "Runtime assurance probe completed with blocked or failed controls.",
                level="info" if report.deployment_complete else "warning",
            )
        except Exception as exc:
            with self._lock:
                self._assurance.update(
                    {
                        "status": "error",
                        "updated_at": _utcnow(),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            self._event("attestation", f"Assurance probe failed: {type(exc).__name__}: {exc}", level="error")

    def start_malware_scan(self) -> bool:
        with self._lock:
            if self._malware.get("running"):
                return False
            if not self._malware.get("available"):
                return False
            self._malware.update(
                {
                    "status": "running",
                    "running": True,
                    "clean": None,
                    "files_scanned": 0,
                    "detections": [],
                    "error": None,
                    "updated_at": _utcnow(),
                }
            )
        Thread(target=self._malware_worker, name="bull-malware-scan", daemon=True).start()
        return True

    def _malware_worker(self) -> None:
        self._event("malware", f"Bounded ClamAV scan started for {self.workspace}.")
        try:
            scanner = MalwareScanner()
            result = scanner.scan_project(
                self.workspace,
                timeout_seconds=float(os.environ.get("BULL_CONSOLE_SCAN_TIMEOUT", "180")),
                max_total_bytes=int(os.environ.get("BULL_CONSOLE_SCAN_MAX_BYTES", str(256 * 1024 * 1024))),
                max_files=int(os.environ.get("BULL_CONSOLE_SCAN_MAX_FILES", "10000")),
            )
            detections = [
                {
                    "path": item.path,
                    "sha256": item.sha256,
                    "size": item.size,
                    "signature": item.signature or "detected",
                }
                for item in result.detections[:100]
            ]
            with self._lock:
                self._malware.update(
                    {
                        "status": "clean" if result.clean else "detections",
                        "running": False,
                        "clean": result.clean,
                        "files_scanned": result.files_scanned,
                        "detections": detections,
                        "error": None,
                        "updated_at": _utcnow(),
                    }
                )
            self._event(
                "malware",
                f"Malware scan completed: {result.files_scanned} files, {len(result.detections)} detections.",
                level="info" if result.clean else "error",
            )
        except (MalwareScannerUnavailable, MalwareScannerError, OSError, ValueError) as exc:
            with self._lock:
                self._malware.update(
                    {
                        "status": "error",
                        "running": False,
                        "clean": None,
                        "error": f"{type(exc).__name__}: {exc}",
                        "updated_at": _utcnow(),
                    }
                )
            self._event("malware", f"Malware scan failed: {type(exc).__name__}: {exc}", level="error")

    def _audit_snapshot(self) -> dict[str, Any]:
        raw = os.environ.get("BULL_AUDIT_LEDGER", "").strip()
        if not raw:
            return {
                "configured": False,
                "path": None,
                "valid": None,
                "records": 0,
                "head_hash": None,
                "error": "BULL_AUDIT_LEDGER is not configured",
                "recent": [],
                "decisions": {name: 0 for name in ("ALLOW", "SANDBOX", "ESCALATE", "DENY")},
                "remote_anchor_configured": bool(
                    os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL")
                    or os.environ.get("BULL_AUDIT_TRANSPORT")
                ),
            }
        path = Path(raw)
        result_valid: bool | None = None
        records = 0
        head_hash = None
        error = None
        try:
            verification = AuditLedger(path).verify(verify_anchor=False)
            result_valid = verification.valid
            records = verification.records
            head_hash = verification.head_hash
            error = verification.error
        except Exception as exc:
            error = f"{type(exc).__name__}: {exc}"
            result_valid = False

        recent_rows = _tail_records(path)
        decisions: Counter[str] = Counter()
        recent: list[dict[str, Any]] = []
        for item in recent_rows:
            decision = str(item.get("decision", "")).upper()
            if decision in {"ALLOW", "SANDBOX", "ESCALATE", "DENY"}:
                decisions[decision] += 1
            recent.append(
                {
                    "timestamp": item.get("timestamp"),
                    "record_type": item.get("record_type", "unknown"),
                    "actor": item.get("actor", ""),
                    "operation": item.get("operation", item.get("event_type", "")),
                    "resource": _redact_resource(str(item.get("resource", ""))),
                    "capability": item.get("capability", ""),
                    "decision": decision,
                    "risk": item.get("risk"),
                    "reasons": list(item.get("reasons") or [])[:4],
                }
            )
        return {
            "configured": True,
            "path": str(path),
            "valid": result_valid,
            "records": records,
            "head_hash": head_hash,
            "error": error,
            "recent": list(reversed(recent[-30:])),
            "decisions": {name: decisions.get(name, 0) for name in ("ALLOW", "SANDBOX", "ESCALATE", "DENY")},
            "remote_anchor_configured": bool(
                os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL")
                or os.environ.get("BULL_AUDIT_TRANSPORT")
            ),
        }

    def _policy(self) -> tuple[DeterministicPolicy, dict[str, Any]]:
        signed = False
        ceiling: frozenset[Capability] | None = None
        root = str(self.workspace)
        path = os.environ.get("BULL_POLICY_BUNDLE", "").strip()
        key = os.environ.get("BULL_POLICY_BUNDLE_KEY", "")
        detail = "Development policy: no signed global capability ceiling is active."
        if path and key:
            try:
                from .policy_bundle import load_policy_bundle

                bundle = load_policy_bundle(path, key)
                root = bundle.project_root
                ceiling = bundle.capability_ceiling
                signed = True
                detail = f"Signed capability ceiling loaded from {Path(path).name}."
            except Exception as exc:
                detail = f"Signed policy configured but unavailable: {type(exc).__name__}: {exc}"
        return DeterministicPolicy(project_root=root, global_capability_ceiling=ceiling), {
            "signed": signed,
            "project_root": root,
            "detail": detail,
            "ceiling": sorted(cap.value for cap in ceiling) if ceiling is not None else None,
        }

    def _capabilities(self) -> dict[str, Any]:
        _, meta = self._policy()
        ceiling = set(meta["ceiling"] or [])
        signed = meta["signed"]

        def state(*caps: Capability) -> dict[str, Any]:
            names = [cap.value for cap in caps]
            if not signed:
                return {
                    "status": "development",
                    "enabled": None,
                    "detail": "No signed deployment ceiling loaded.",
                    "capabilities": names,
                }
            allowed = [name for name in names if name in ceiling]
            return {
                "status": "active" if allowed else "blocked",
                "enabled": bool(allowed),
                "detail": f"{len(allowed)}/{len(names)} mapped capabilities present in signed ceiling.",
                "capabilities": names,
            }

        return {
            "policy": meta,
            "items": [
                {"id": "filesystem", "title": "Filesystem", **state(Capability.FS_READ_PROJECT, Capability.FS_WRITE_PROJECT)},
                {"id": "network", "title": "Network", **state(Capability.NETWORK_OUTBOUND, Capability.NETWORK_POST)},
                {"id": "process", "title": "Process Exec", **state(Capability.PROCESS_EXEC)},
                {"id": "secrets", "title": "Secrets", **state(Capability.CREDENTIAL_READ)},
                {"id": "persistence", "title": "Persistence", **state(Capability.FS_WRITE_HOME, Capability.SECURITY_CONTROL_WRITE)},
                {"id": "spawn", "title": "Agent Spawn", **state(Capability.AGENT_SPAWN, Capability.AGENT_MESSAGE)},
            ],
        }

    def _microvm(self, entities: list[ObservedEntity]) -> dict[str, Any]:
        config_raw = os.environ.get("BULL_MICROVM_CONFIG_FILE", "").strip()
        qemu_name = os.environ.get("BULL_MICROVM_QEMU", "qemu-system-x86_64")
        kvm = Path("/dev/kvm")
        qemu_path = shutil.which(qemu_name)
        running = any(entity.kind == "microvm" for entity in entities)
        config_exists = bool(config_raw and Path(config_raw).is_file())
        kernel_raw = os.environ.get("BULL_MICROVM_KERNEL", "")
        rootfs_raw = os.environ.get("BULL_MICROVM_ROOTFS", "")
        return {
            "running": running,
            "kvm_available": kvm.exists() and os.access(kvm, os.R_OK | os.W_OK),
            "qemu_available": bool(qemu_path),
            "qemu_path": qemu_path,
            "config_file": config_raw or None,
            "config_exists": config_exists,
            "kernel_configured": bool(kernel_raw),
            "rootfs_configured": bool(rootfs_raw),
            "accel": os.environ.get("BULL_MICROVM_ACCEL", "kvm"),
            "memory_mib": os.environ.get("BULL_MICROVM_MEMORY_MIB", "4096"),
            "cpus": os.environ.get("BULL_MICROVM_CPUS", "2"),
            "ready": bool(
                kvm.exists()
                and os.access(kvm, os.R_OK | os.W_OK)
                and qemu_path
                and (config_exists or (kernel_raw and rootfs_raw))
            ),
        }

    @staticmethod
    def _swarm_snapshot(entities: list[ObservedEntity]) -> dict[str, Any]:
        groups: dict[str, list[ObservedEntity]] = defaultdict(list)
        for entity in entities:
            if entity.kind in {"microvm", "security-runtime"}:
                continue
            if entity.ppid is not None and entity.ppid > 1:
                groups[f"parent:{entity.ppid}"].append(entity)
            groups[f"family:{entity.family.lower()}"].append(entity)

        clusters: list[dict[str, Any]] = []
        seen: set[tuple[str, ...]] = set()
        for key, members in groups.items():
            if len(members) < 2:
                continue
            member_ids = tuple(sorted(member.entity_id for member in members))
            if member_ids in seen:
                continue
            seen.add(member_ids)
            evidence = []
            if key.startswith("parent:"):
                evidence.append(f"shared parent process {key.split(':', 1)[1]}")
            else:
                evidence.append(f"shared observed family {members[0].family}")
            if any(member.socket_count for member in members):
                evidence.append("network-capable processes present")
            confidence = min(0.95, sum(member.confidence for member in members) / len(members))
            clusters.append(
                {
                    "cluster_id": f"cluster-{len(clusters)+1}",
                    "members": [member.entity_id for member in members],
                    "label": key,
                    "evidence": evidence,
                    "confidence": round(confidence, 3),
                }
            )
        return {"clusters": clusters[:20], "count": len(clusters)}

    def _isolation(self, assurance: dict[str, Any]) -> dict[str, Any]:
        controls = {str(item.get("id")): item for item in assurance.get("controls", [])}
        mapping = [
            ("namespaces", "Namespaces", "SANDBOX.PID_NAMESPACE"),
            ("seccomp", "Seccomp", "SANDBOX.SECCOMP_STRICT"),
            ("landlock", "Landlock", "SANDBOX.LANDLOCK"),
            ("cgroup", "cgroup v2", "SANDBOX.CGROUP_DELEGATION"),
            ("no_new_privs", "no_new_privs", "SANDBOX.NO_NEW_PRIVS"),
            ("network", "Network isolation", "SANDBOX.NETWORK_ISOLATION"),
            ("signed_policy", "Signed policy", "INTEGRITY.SIGNED_POLICY"),
            ("signed_runtime", "Runtime integrity", "INTEGRITY.SIGNED_RUNTIME"),
        ]
        items = []
        for item_id, title, control_id in mapping:
            control = controls.get(control_id, {})
            items.append(
                {
                    "id": item_id,
                    "title": title,
                    "control_id": control_id,
                    "status": str(control.get("status", "PENDING")),
                    "detail": str(control.get("detail", "Awaiting assurance probe.")),
                }
            )
        return {"items": items}

    def evaluate_policy(self, payload: dict[str, Any]) -> dict[str, Any]:
        policy, policy_meta = self._policy()
        capability = Capability(str(payload.get("capability", Capability.PROCESS_EXEC.value)))
        provenance_raw = payload.get("provenance") or [Provenance.UNKNOWN.value]
        if isinstance(provenance_raw, str):
            provenance_raw = [provenance_raw]
        granted_raw = payload.get("granted_capabilities") or [capability.value]
        if isinstance(granted_raw, str):
            granted_raw = [granted_raw]
        action = ActionRequest(
            actor=str(payload.get("actor") or "operator-simulation")[:120],
            task=str(payload.get("task") or "console policy evaluation")[:240],
            operation=str(payload.get("operation") or "process.exec")[:160],
            resource=str(payload.get("resource") or "/workspace/tool")[:2048],
            capability=capability,
            granted_capabilities=frozenset(Capability(str(value)) for value in granted_raw),
            provenance=tuple(Provenance(str(value)) for value in provenance_raw),
            irreversible=bool(payload.get("irreversible", False)),
            external_side_effect=bool(payload.get("external_side_effect", False)),
        )
        result = policy.evaluate(action)
        self._event("policy", f"Policy simulation returned {result.decision.value}.")
        return {
            "decision": result.decision.value,
            "risk": result.risk,
            "reasons": list(result.reasons),
            "hard_block": result.hard_block,
            "policy": policy_meta,
        }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            entities = list(self._entities)
            services = dict(self._services)
            assurance = json.loads(json.dumps(self._assurance))
            malware = json.loads(json.dumps(self._malware))
            events = list(self._events)[:40]
        audit = self._audit_snapshot()
        capabilities = self._capabilities()
        microvm = self._microvm(entities)
        swarms = self._swarm_snapshot(entities)
        isolation = self._isolation(assurance)

        denied = int(audit["decisions"].get("DENY", 0))
        escalated = int(audit["decisions"].get("ESCALATE", 0))
        detections = len(malware.get("detections") or [])
        running_protections = sum(1 for item in isolation["items"] if item["status"] == "PASS")
        total_protections = len(isolation["items"])

        return {
            "meta": {
                "product": "BULL",
                "expansion": "Blocking Unauthorized Logic Loopholes",
                "version": _package_version(),
                "workspace": str(self.workspace),
                "hostname": socket.gethostname(),
                "platform": platform.system(),
                "updated_at": _utcnow(),
                "refresh_seconds": self.refresh_seconds,
            },
            "system_health": {
                "observed_entities": len(entities),
                "denied_actions": denied,
                "review_actions": escalated,
                "malware_detections": detections,
                "audit_records": int(audit.get("records") or 0),
                "protections_passing": running_protections,
                "protections_total": total_protections,
                "operational": bool(
                    audit.get("valid") is not False
                    and malware.get("status") != "error"
                    and assurance.get("status") != "error"
                ),
            },
            "discovery": {
                "active": True,
                "services": services,
                "entity_count": len(entities),
                "last_scan": _utcnow(),
            },
            "entities": [entity.to_dict() for entity in entities],
            "policy": {
                "decisions": audit["decisions"],
                "source": "audit ledger tail",
                "policy_meta": capabilities["policy"],
            },
            "capabilities": capabilities,
            "isolation": isolation,
            "audit": audit,
            "malware": malware,
            "microvm": microvm,
            "swarms": swarms,
            "attestation": assurance,
            "events": events,
        }


class _ConsoleServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], handler, control: ControlPlane):
        super().__init__(address, handler)
        self.control = control


class ConsoleHandler(BaseHTTPRequestHandler):
    server_version = "BULLConsole/1"
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:
        print(f"BULL console: {self.address_string()} - {format % args}")

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: dict[str, Any], status: int = 200) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status)

    @staticmethod
    def _asset(name: str) -> bytes:
        return resources.files("bulldog").joinpath("console_static", name).read_bytes()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path in {"/", "/index.html"}:
            self._send_bytes(self._asset("index.html"), "text/html; charset=utf-8")
            return
        assets = {
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/styles.css": ("styles.css", "text/css; charset=utf-8"),
            "/bull-mark.svg": ("bull-mark.svg", "image/svg+xml"),
        }
        if parsed.path in assets:
            name, content_type = assets[parsed.path]
            self._send_bytes(self._asset(name), content_type)
            return
        if parsed.path == "/api/v1/snapshot":
            self._json(self.server.control.snapshot())
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def _body(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = min(int(raw_length), 64 * 1024)
        except ValueError:
            length = 0
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("request body must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("request body must be an object")
        return value

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        control: ControlPlane = self.server.control
        try:
            body = self._body()
            if parsed.path == "/api/v1/actions/rescan":
                control.refresh()
                self._json({"ok": True, "message": "Live discovery refreshed."})
                return
            if parsed.path == "/api/v1/actions/malware-scan":
                started = control.start_malware_scan()
                status = control.snapshot()["malware"]["status"]
                self._json(
                    {
                        "ok": started or status == "running",
                        "message": "Malware scan started." if started else f"Malware scanner state: {status}.",
                    }
                )
                return
            if parsed.path == "/api/v1/actions/attest":
                started = control.start_attestation(dynamic=True)
                self._json(
                    {
                        "ok": started or control.snapshot()["attestation"]["status"] == "running",
                        "message": "Dynamic assurance probe started." if started else "Assurance probe already running.",
                    }
                )
                return
            if parsed.path == "/api/v1/actions/audit-verify":
                audit = control.snapshot()["audit"]
                configured = bool(audit.get("configured"))
                valid = audit.get("valid") is True
                self._json(
                    {
                        "ok": configured and valid,
                        "message": (
                            "Audit ledger verified."
                            if configured and valid
                            else (audit.get("error") or "Audit ledger is not configured.")
                        ),
                    }
                )
                return
            if parsed.path == "/api/v1/actions/microvm-probe":
                microvm = control.snapshot()["microvm"]
                self._json(
                    {
                        "ok": True,
                        "message": "MicroVM readiness refreshed.",
                        "ready": microvm["ready"],
                        "running": microvm["running"],
                    }
                )
                return
            if parsed.path == "/api/v1/actions/policy-evaluate":
                result = control.evaluate_policy(body)
                self._json({"ok": True, "result": result})
                return
        except (ValueError, KeyError) as exc:
            self._json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return
        except Exception as exc:
            self._json({"error": f"{type(exc).__name__}: {exc}"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)


def serve_console(
    *,
    host: str = "127.0.0.1",
    port: int = 11510,
    workspace: str | Path | None = None,
    refresh_seconds: float = 2.0,
    auto_scan: bool = True,
    dynamic_attestation: bool = True,
) -> int:
    control = ControlPlane(
        workspace=workspace,
        refresh_seconds=refresh_seconds,
        auto_scan=auto_scan,
        dynamic_attestation=dynamic_attestation,
    )
    server = _ConsoleServer((host, int(port)), ConsoleHandler, control)
    control.start()
    bind_host, bind_port = server.server_address[:2]
    print("=" * 78)
    print("BULL COMMAND / CONTROL")
    print("=" * 78)
    print(f"workspace: {control.workspace}")
    print(f"listening: http://{bind_host}:{bind_port}")
    if host not in {"127.0.0.1", "::1", "localhost"}:
        print("warning: console is not bound to loopback; rely on a private trusted port tunnel.")
    print("live discovery: active")
    print("malware scanner: initialized; bounded startup scan requested" if auto_scan else "malware scanner: initialized; auto scan disabled")
    print("runtime assurance: dynamic background probe requested" if dynamic_attestation else "runtime assurance: background dynamic probe disabled")
    print("=" * 78)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        return 0
    finally:
        control.stop()
        server.server_close()
    return 0

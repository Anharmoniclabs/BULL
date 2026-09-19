"""One governed command per boot, with a bounded execution report export."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from .dispatcher import DispatchDenied, DispatchRequest
from .models import Decision, Provenance
from .profiles import ProductionDispatcher, ProductionRuntime
from .secure_fs import open_beneath, trusted_root_fd
from .security_domain import SecurityDomainRegistry


class BootstrapFailure(RuntimeError):
    """No workload was dispatched because production construction failed."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate workload key")
        result[key] = value
    return result


def load_workload(runtime: Path) -> dict:
    with trusted_root_fd(Path("/")) as root:
        fd = open_beneath(root, str(runtime.absolute() / "workload.json").lstrip("/"), flags=os.O_RDONLY | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384:
            raise ValueError("workload.json must be a bounded, single-link regular file")
        payload = stream.read(16385)
    if len(payload) > 16384:
        raise ValueError("workload.json exceeds size limit")
    spec = json.loads(payload, object_pairs_hook=_unique_object)
    if not isinstance(spec, dict) or set(spec) - {"version", "argv", "task", "timeout_seconds"}:
        raise ValueError("unsupported workload keys")
    if type(spec.get("version")) is not int or spec["version"] != 1:
        raise ValueError("workload version must be 1")
    argv = spec.get("argv")
    if not isinstance(argv, list) or not 1 <= len(argv) <= 128:
        raise ValueError("argv must be an explicit nonempty array, at most 128 arguments")
    if any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 4096 for arg in argv):
        raise ValueError("invalid argv element")
    if not argv[0].startswith("/") or ".." in Path(argv[0]).parts:
        raise ValueError("argv executable must be an absolute path without traversal")
    timeout = spec.setdefault("timeout_seconds", 30)
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError("timeout_seconds must be an integer between 1 and 300")
    task = spec.setdefault("task", "Execute the deployment workload")
    if not isinstance(task, str) or not task.strip() or len(task) > 4096:
        raise ValueError("task must be a bounded nonempty string")
    return spec


def execute_workload(spec: dict, workspace: Path):
    try:
        runtime = ProductionRuntime()
        registry = SecurityDomainRegistry(ledger=runtime.engine.ledger, strict_identity_binding=True)
        ceiling = runtime.engine.policy.global_capability_ceiling
        domain = registry.create_root(
            actor="microvm-deployment", model_id="trusted-one-shot-adapter-v1",
            initial_prompt=spec["task"], initial_command=spec["argv"],
            capability_ceiling=ceiling, provenance=(Provenance.LOCAL_TRUSTED,),
        )
        dispatcher = ProductionDispatcher(runtime=runtime, domain_registry=registry)
    except Exception as exc:
        raise BootstrapFailure(type(exc).__name__) from exc
    request = DispatchRequest(
        proposal={"operation": "execute", "resource": spec["argv"][0], "task": spec["task"]},
        trusted=registry.trusted_context(domain.domain_id), granted_capabilities=ceiling,
        domain_id=domain.domain_id, authorized_command=tuple(spec["argv"]),
    )
    return dispatcher.execute(request, spec["argv"], project_root=workspace, timeout=spec["timeout_seconds"])


def result_report(result) -> dict:
    if result.review_required or result.evaluation.decision == Decision.ESCALATE:
        status = "review_required"
    elif result.evaluation.decision == Decision.DENY:
        status = "policy_denied"
    elif not result.executed:
        status = "infrastructure_failure"
    elif result.returncode != 0:
        status = "execution_failed"
    else:
        status = "success"
    return {
        "status": status, "executed": result.executed, "returncode": result.returncode,
        "decision": result.evaluation.decision.value,
        "reasons": [str(reason)[:1024] for reason in result.evaluation.reasons[:16]],
        "stdout": result.stdout[:8192], "stderr": result.stderr[:8192],
        "stdout_truncated": len(result.stdout) > 8192,
        "stderr_truncated": len(result.stderr) > 8192,
        "sandboxed": result.sandboxed,
    }


def run_session(workspace: Path, runtime: Path, outputs: Path) -> int:
    # Acquire the report slot before doing anything that could execute a command.
    # Pin every component; only this trusted adapter receives the output handle.
    with trusted_root_fd(Path("/")) as root:
        directory = open_beneath(root, str(outputs.absolute()).lstrip("/"), directory=True)
    pending = ".bull-summary.pending"
    fd = None
    try:
        if os.listdir(directory):
            raise ValueError("output directory must be empty; refusing to overwrite artifacts")
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        started = time.monotonic()
        report = {"status": "infrastructure_failure", "executed": False, "returncode": None}
        dispatch_started = False
        try:
            spec = load_workload(runtime)
            dispatch_started = True
            report = result_report(execute_workload(spec, workspace))
        except BootstrapFailure:
            report.update(error="production bootstrap failed; workload was not dispatched")
        except subprocess.TimeoutExpired:
            report.update(status="timeout", executed=None, error="execution duration exceeded")
        except DispatchDenied:
            report.update(status="policy_denied", error="production dispatcher denied this request")
        except Exception as exc:
            # Never serialize environment values, credentials, or exception text.
            # An infrastructure failure during dispatch has an unknown outcome.
            report.update(executed=None if dispatch_started else False, error_type=type(exc).__name__,
                          error="production configuration or execution infrastructure unavailable; no automatic retry")
        report.update(version=1, duration_seconds=round(time.monotonic() - started, 3))
        payload = (json.dumps(report, ensure_ascii=True, sort_keys=True) + "\n").encode()
        with os.fdopen(fd, "wb") as stream:
            fd = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic publication with no replacement, including links created by a
        # concurrent host writer. Interrupted reports retain the pending file.
        os.link(pending, "summary.json", src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink(pending, dir_fd=directory)
        os.fsync(directory)
        return 0 if report["status"] == "success" else 1
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--outputs", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return run_session(args.workspace, args.runtime, args.outputs)
    except (OSError, ValueError, RuntimeError) as exc:
        # Guest console reports class only; secrets never belong in console logs.
        parser.exit(2, f"bull-engine: report export failed ({type(exc).__name__})\n")


if __name__ == "__main__":
    raise SystemExit(main())

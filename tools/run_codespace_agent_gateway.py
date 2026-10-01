#!/usr/bin/env python3
"""Run one fixed command through real MCP and an enforced Unix authority.

Run as the Codespace operator. A bounded sudo helper creates a temporary locked
agent account and delegates the existing BULL cgroup. The authority remains the
operator's non-root account. The external profile requires an HTTPS collector;
--local uses an installation-specific authenticated local audit checkpoint.
No listener is exposed on TCP and no firewall is changed.
"""

from __future__ import annotations

import argparse
import ctypes
import grp
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

# Isolated Python (-I) ignores PYTHONDONTWRITEBYTECODE. Helpers must not create
# root-owned caches in the operator's verified source, including on direct runs.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]


def write_json(path, value):
    path = Path(path)
    with path.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
    path.chmod(0o600)


def clean_env(user):
    return {
        "PATH": "/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
        "HOME": user.pw_dir,
        "USER": user.pw_name,
        "LOGNAME": user.pw_name,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


def private_path(path, uid, *, directory=False):
    path = Path(path).absolute()
    if path.resolve(strict=True) != path:
        raise ValueError("private input must be canonical without symlinks")
    info = path.lstat()
    correct_type = (
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    )
    if not correct_type or info.st_uid != uid or info.st_mode & 0o077:
        raise ValueError(
            "private input must belong to the operator and deny other accounts"
        )
    if not directory and (info.st_nlink != 1 or info.st_size > 65536):
        raise ValueError("private input must be a bounded single-link file")
    return path


def public_runtime_entries(run, operator_uid):
    """Inventory only the newly installed source and libraries, never evidence."""
    entries = []
    for name in ("source", "venv"):
        root = run / name
        if root.is_symlink() or not root.is_dir():
            raise ValueError("public runtime must be a real directory: " + str(root))
        for path in (root, *root.rglob("*")):
            info = path.lstat()
            if info.st_uid != operator_uid:
                raise ValueError("public runtime has a foreign owner: " + str(path))
            if stat.S_ISLNK(info.st_mode):
                # venv's lib64 -> lib is expected. Never chmod a link target or
                # allow links into private evidence or another installation.
                if not path.resolve(strict=True).is_relative_to(root):
                    raise ValueError(
                        "public runtime link leaves its tree: " + str(path)
                    )
                continue
            if stat.S_ISDIR(info.st_mode):
                mode = 0o755
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                mode = 0o755 if info.st_mode & stat.S_IXUSR else 0o644
            else:
                raise ValueError("unexpected public runtime entry: " + str(path))
            entries.append((path, mode))
    return entries


def verify_public_runtime(run, operator_uid, *, parent_mode=0o711):
    """Refuse inaccessible or agent-writable code before account provisioning."""
    info = run.lstat()
    if (
        run.resolve(strict=True) != run
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != operator_uid
        or stat.S_IMODE(info.st_mode) != parent_mode
    ):
        raise ValueError(
            f"runtime parent must be operator-owned and mode {parent_mode:04o}"
        )
    private_path(run / "private", operator_uid, directory=True)
    for path, mode in public_runtime_entries(run, operator_uid):
        actual = stat.S_IMODE(path.lstat().st_mode)
        if actual != mode:
            raise ValueError(
                f"public runtime permissions {actual:04o}, expected {mode:04o}: {path}"
            )
    for name in ("python", "bull-mcp"):
        path = run / "venv/bin" / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o755:
            raise ValueError(
                "runtime entry point must be a mode 0755 file: " + str(path)
            )


def prepare_public_runtime(run):
    """Set public code permissions while its parent is still private."""
    operator_uid = os.geteuid()
    private_path(run, operator_uid, directory=True)
    private_path(run / "private", operator_uid, directory=True)
    # Validate every entry before changing any permissions. Keep the parent
    # private until both public trees have been prepared and checked.
    entries = public_runtime_entries(run, operator_uid)
    for path, mode in entries:
        os.chmod(path, mode, follow_symlinks=False)
    verify_public_runtime(run, operator_uid, parent_mode=0o700)
    run.chmod(0o711)
    try:
        verify_public_runtime(run, operator_uid)
    except BaseException:
        run.chmod(0o700)
        raise


def collector_locations(user):
    """Inspect only BULL's state directories; never read or print key contents."""
    deployments, keys = set(), set()
    for name in ("bull", "bull-production"):
        base = Path(user.pw_dir) / ".local/share" / name
        for pattern in ("deployment.json", "*/deployment.json", "*/*/deployment.json"):
            for path in sorted(base.glob(pattern))[:64]:
                try:
                    private_path(path.parent, user.pw_uid, directory=True)
                    private_path(path, user.pw_uid)
                    config = json.loads(path.read_text())
                    if (
                        isinstance(config, dict)
                        and config.get("format") == "bull-deployment-config-v1"
                        and config.get("collector_url")
                    ):
                        deployments.add(path.parent)
                except (OSError, ValueError):
                    continue
        for filename in ("collector.key", "cloudflare-anchor.key"):
            for prefix in ("", "*/", "*/*/"):
                for path in sorted(base.glob(prefix + "secrets/" + filename))[:64]:
                    try:
                        keys.add(private_path(path, user.pw_uid))
                    except (OSError, ValueError):
                        continue
    return sorted(deployments), sorted(keys)


def collector_configuration(user):
    deployments, keys = collector_locations(user)
    return {
        "environment_present": {
            name: bool(os.environ.get(name))
            for name in (
                "BULL_REMOTE_AUDIT_ANCHOR_URL",
                "BULL_REMOTE_AUDIT_ANCHOR_KEY",
                "BULL_ANCHOR_MASTER_KEY",
                "BULL_DEPLOYMENT_ANCHOR_KEY_FILE",
            )
        },
        "deployment_paths": [str(path) for path in deployments],
        "private_key_paths": [str(path) for path in keys],
        "scope": "configuration locations only; no collector authentication performed",
    }


def select_environment_collector(user, secret_destination=None):
    """Read explicitly selected Codespaces secrets without logging their values."""
    from tools.deployment_setup import (
        collector_url,
        private_read,
        secret_text,
        write_new,
    )

    url = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL")
    value = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY")
    worker_value = os.environ.get("BULL_ANCHOR_MASTER_KEY")
    filename = os.environ.get("BULL_DEPLOYMENT_ANCHOR_KEY_FILE")
    if not url or not (value or worker_value or filename):
        raise ValueError(
            "--collector-from-env requires BULL_REMOTE_AUDIT_ANCHOR_URL and either "
            "BULL_REMOTE_AUDIT_ANCHOR_KEY, BULL_ANCHOR_MASTER_KEY, or "
            "BULL_DEPLOYMENT_ANCHOR_KEY_FILE; "
            "restore the existing collector configuration as Codespaces secrets"
        )
    url = collector_url(url)
    if (
        value
        and worker_value
        and not hmac.compare_digest(value.encode("utf-8"), worker_value.encode("utf-8"))
    ):
        raise ValueError("collector environment keys disagree")
    value = value or worker_value
    raw = value.encode("utf-8") if value else None
    if raw is not None:
        secret_text(raw)
    if filename:
        key = private_path(filename, user.pw_uid)
        file_raw = private_read(key, maximum=4096)
        secret_text(file_raw)
        if raw is not None and not hmac.compare_digest(raw, file_raw):
            raise ValueError("collector environment key and key file disagree")
        return url, key
    if secret_destination is None:
        # Preflight is read-only. A real run stages the exact bytes privately.
        return url, None
    private_path(secret_destination.parent, user.pw_uid, directory=True)
    write_new(secret_destination, raw)
    return url, private_path(secret_destination, user.pw_uid)


def select_collector(args, user, *, secret_destination=None):
    """Select only explicit inputs or one existing BULL deployment, never keys in logs."""
    from tools.deployment_setup import collector_url, private_read, secret_text

    if getattr(args, "collector_from_env", False):
        if args.deployment or args.collector_url or args.collector_key_file:
            raise ValueError("choose --collector-from-env or explicit collector inputs")
        return select_environment_collector(user, secret_destination)
    if bool(args.collector_url) != bool(args.collector_key_file):
        raise ValueError("provide both --collector-url and --collector-key-file")
    if args.deployment and args.collector_url:
        raise ValueError("choose --deployment or the explicit collector inputs")
    if args.collector_url:
        url = collector_url(args.collector_url)
        key = private_path(args.collector_key_file, user.pw_uid)
        secret_text(private_read(key, maximum=4096))
        return url, key

    candidates = [args.deployment] if args.deployment else []
    if not candidates:
        candidates, _ = collector_locations(user)
    if len(candidates) != 1:
        raise ValueError(
            "select one existing production collector with --deployment /PRIVATE/BULL/STATE; "
            "use --collector-from-env for existing Codespaces secrets, or provide "
            "--collector-url and --collector-key-file (never paste the key)"
        )
    state = private_path(candidates[0], user.pw_uid, directory=True)
    config_file = private_path(state / "deployment.json", user.pw_uid)
    config = json.loads(config_file.read_text())
    if (
        not isinstance(config, dict)
        or config.get("format") != "bull-deployment-config-v1"
    ):
        raise ValueError("not a BULL deployment configuration")
    url = collector_url(config.get("collector_url"))
    if not url:
        raise ValueError("selected deployment has no external HTTPS collector")
    private_path(state / "secrets", user.pw_uid, directory=True)
    key = private_path(state / "secrets/collector.key", user.pw_uid)
    secret_text(private_read(key, maximum=4096))
    return url, key


def select_audit(args, user, *, secret_destination=None):
    if getattr(args, "local", False):
        if any(
            (
                args.deployment,
                args.collector_url,
                args.collector_key_file,
                args.collector_from_env,
            )
        ):
            raise ValueError(
                "choose local auditing or explicit external collector inputs"
            )
        # Do not discover, read or reuse the operator's external collector keys.
        return None, None
    return select_collector(args, user, secret_destination=secret_destination)


def pass_status(mode):
    if mode not in {"local", "external"}:
        raise ValueError("unknown audit profile")
    return "LOCAL TOOL PASS" if mode == "local" else "CONNECTED TOOL PASS"


def endpoint_ready(path, authority_uid, agent_gid):
    # bind() creates the node before the authority grants the agent group access.
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    return (
        stat.S_ISSOCK(info.st_mode)
        and info.st_uid == authority_uid
        and info.st_gid == agent_gid
        and stat.S_IMODE(info.st_mode) == 0o660
    )


def host_checks():
    checks = {"nonroot_operator": os.geteuid() != 0}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM):
            checks["unix_sockets"] = True
    except OSError:
        checks["unix_sockets"] = False
    command = [
        "unshare",
        "--user",
        "--map-root-user",
        "--mount",
        "--pid",
        "--fork",
        "--net",
        "--ipc",
        "true",
    ]
    try:
        result = subprocess.run(command, capture_output=True, timeout=10)
        checks["linux_namespaces"] = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        checks["linux_namespaces"] = False
    checks["cgroup_v2"] = Path("/sys/fs/cgroup/cgroup.controllers").is_file()
    return checks


def drop_identity(user, groups, cgroup=None):
    if cgroup:
        (Path(cgroup) / "coordinator/cgroup.procs").write_text(str(os.getpid()))
    os.setgroups(groups)
    os.setresgid(user.pw_gid, user.pw_gid, user.pw_gid)
    os.setresuid(user.pw_uid, user.pw_uid, user.pw_uid)
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "could not set no_new_privs")


def stop_child(child):
    if child is None or child.poll() is not None:
        return
    # Only this runner's new process group, never a username or host-wide kill.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=8)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def account_command(name, *arguments):
    binary = shutil.which(name, path="/usr/sbin:/usr/bin:/sbin:/bin")
    if not binary or name not in {"useradd", "userdel", "groupdel"}:
        raise ValueError("required account administration command is unavailable")
    subprocess.run(
        [binary, *arguments],
        check=True,
        timeout=15,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )


def authority_role(run):
    cfg = json.loads((run / "config.json").read_text())
    if os.geteuid() != cfg["operator_uid"] or os.geteuid() == 0:
        raise ValueError("authority must be the selected non-root operator")
    from tools.deployment_setup import initialize, isolated_environment
    from bulldog.production_gate import evaluate_production_environment
    from bulldog.local_gate import evaluate_local_environment
    from bulldog.gateway_cli import run_service

    binary = Path("/usr/bin/true").resolve(strict=True)
    registry = {
        "format": "bull-agent-gateway-v1",
        "tenant_id": "local-qualification",
        "project_id": "harmless-command",
        "session_id": secrets.token_hex(16),
        "agent_uid": cfg["agent_uid"],
        "expires_at": int(time.time()) + 600,
        "max_calls": 2,
        "tools": [
            {
                "name": "installation_check",
                "description": "Run only the fixed true executable",
                "operation": "process.execute",
                "argv": [str(binary)],
                "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "timeout": 10,
            }
        ],
    }
    write_json(run / "registry.json", registry)
    initialize(
        run / "private/deployment",
        run / "project",
        url=cfg["collector_url"],
        existing_collector_key=(
            Path(cfg["collector_key_file"]) if cfg["collector_key_file"] else None
        ),
        cgroup_parent=cfg["cgroup_parent"],
        gateway_registry=run / "registry.json",
        audit_mode=cfg.get("audit_mode", "external"),
    )
    env = isolated_environment(
        run / "private/deployment", clean_env(pwd.getpwuid(os.geteuid()))
    )
    os.environ.clear()
    os.environ.update(env)
    local = cfg.get("audit_mode") == "local"
    evaluate = evaluate_local_environment if local else evaluate_production_environment
    gates = evaluate(package_root=ROOT / "src/bulldog")
    write_json(
        run
        / ("private/local-gates.json" if local else "private/production-gates.json"),
        gates,
    )
    if not gates["passed"]:
        return 1
    return run_service(
        argparse.Namespace(
            state=run / "private/lease",
            socket=run / "endpoint/agent.sock",
            agent_gid=cfg["agent_gid"],
            egress_socket=None,
            audit_mode=cfg.get("audit_mode", "external"),
        )
    )


def agent_role(run):
    # This file contains only public test identities and endpoint paths.
    cfg = json.loads((run / "agent-config.json").read_text())
    if os.geteuid() != cfg["agent_uid"] or os.geteuid() in {0, cfg["operator_uid"]}:
        raise ValueError("wrong agent identity")
    if set(os.getgroups()) - {os.getegid()}:
        raise ValueError("agent inherited extra host groups")
    for path in (
        run / "private/deployment/secrets/collector.key",
        run / "private/deployment/secrets/local-audit.key",
        run / "private/lease",
    ):
        if os.access(path, os.R_OK):
            raise ValueError("agent can read authority state")
    for path in (ROOT, ROOT / "src/bulldog/agent_gateway.py", run / "venv"):
        if os.access(path, os.W_OK):
            raise ValueError("agent can modify the installed authority")
    if os.access("/var/run/docker.sock", os.R_OK | os.W_OK):
        raise ValueError("agent can access the Docker control socket")
    from tools.qualify_agent_gateway import main as qualify

    sys.argv = [
        str(ROOT / "tools/qualify_agent_gateway.py"),
        "--socket",
        str(run / "endpoint/agent.sock"),
        "--server-uid",
        str(cfg["operator_uid"]),
        "--bridge",
        str(run / "venv/bin/bull-mcp"),
        "--tool",
        "installation_check",
        "--expect-argv-json",
        json.dumps(cfg["argv"]),
        "--output",
        str(run / "agent/result.json"),
        "--audit-mode",
        cfg.get("audit_mode", "external"),
    ]
    return qualify()


def verify_retained_audit(run, result, *, audit_mode="external"):
    from bulldog.audit import AuditLedger
    from bulldog.anchor_service import session_key
    from bulldog.audit_transport import AnchorIdentity

    pass_status(audit_mode)
    deployment = run / "private/deployment"
    if audit_mode == "local":
        from bulldog.local_audit import LocalAuditLedger

        ledger = LocalAuditLedger(
            deployment / "audit/ledger.jsonl",
            anchor_path=deployment / "audit/local-checkpoint.json",
            anchor_key=private_path(
                deployment / "secrets/local-audit.key", run.stat().st_uid
            ).read_bytes(),
        )
    else:
        ledger = AuditLedger(
            deployment / "audit/ledger.jsonl",
            remote_anchor_url="",
            remote_anchor_key=b"",
        )
    verification = ledger.verify()
    if not verification.valid or not verification.records:
        raise ValueError("retained authority audit did not verify")
    records = [json.loads(line) for line in ledger.path.read_text().splitlines()]
    attempts = [r for r in records if r.get("event_type") == "gateway_attempt"]
    results = [r for r in records if r.get("event_type") == "gateway_result"]
    if len(attempts) != 1 or len(results) != 1:
        raise ValueError("audit does not contain exactly one gateway effect")
    data = results[0]["data"]
    if (
        data.get("executed") is not True
        or attempts[0]["data"].get("call_id") != result["call_id"]
        or data.get("call_id") != result["call_id"]
        or data.get("result_digest") != result["result_sha256"]
    ):
        raise ValueError("MCP result is not bound to the retained authority audit")
    if audit_mode == "local":
        return {
            "records": verification.records,
            "head_hash": verification.head_hash,
            "audit_mode": "local",
            "external_receipt": False,
        }
    checkpoint = json.loads(ledger.remote_checkpoint_path.read_text())
    if (
        checkpoint.get("sequence") != verification.records
        or checkpoint.get("head_hash") != verification.head_hash
    ):
        raise ValueError("external audit checkpoint did not reach the ledger head")
    session = json.loads((deployment / "deployment.json").read_text())["audit_session"]
    identity = AnchorIdentity(
        session,
        session_key((deployment / "secrets/collector.key").read_bytes(), session),
    )
    identity.check_ack(checkpoint, verification.records, verification.head_hash)
    return {"records": verification.records, "head_hash": verification.head_hash}


def root_worker(run):
    if os.geteuid() != 0:
        raise ValueError("account provisioning requires the explicit sudo helper")
    info = run.lstat()
    if (
        run.is_symlink()
        or not run.name.startswith("bull-mcp-live-")
        or info.st_uid == 0
        or info.st_mode & 0o022
    ):
        raise ValueError("unexpected live-test directory")
    operator = pwd.getpwuid(info.st_uid)
    config_path = private_path(run / "config.json", operator.pw_uid)
    cfg = json.loads(config_path.read_text())
    audit_mode = cfg.get("audit_mode", "external")
    expected_status = pass_status(audit_mode)
    if cfg["operator_uid"] != operator.pw_uid or Path(cfg["source"]) != ROOT:
        raise ValueError("live-test source or operator mismatch")
    report = {
        "status": "BLOCKED",
        "scope": "live host MCP connected-tool qualification",
        "source_commit": cfg["source_commit"],
        "enterprise_qualified": False,
        "audit_mode": audit_mode,
        "checks": {},
    }
    authority = agent_process = None
    account = None
    account_created = False
    logs = []

    def interrupted(*_):
        raise KeyboardInterrupt("live test interrupted or exceeded its deadline")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGALRM, interrupted)
    signal.alarm(370)
    try:
        verify_public_runtime(run, operator.pw_uid)
        report["checks"]["public_runtime_permissions"] = True
        from tools.host_setup import provision_cgroup

        parent = provision_cgroup(operator)
        account = "bull-gw-" + secrets.token_hex(4)
        account_command(
            "useradd",
            "--system",
            "--user-group",
            "--no-create-home",
            "--home-dir",
            "/nonexistent",
            "--shell",
            "/usr/sbin/nologin",
            account,
        )
        account_created = True
        agent = pwd.getpwnam(account)
        cfg.update(
            agent_uid=agent.pw_uid, agent_gid=agent.pw_gid, cgroup_parent=str(parent)
        )
        write_json(config_path, cfg)
        os.chown(config_path, operator.pw_uid, operator.pw_gid)
        agent_cfg = {k: cfg[k] for k in ("agent_uid", "operator_uid")}
        agent_cfg["audit_mode"] = audit_mode
        agent_cfg["argv"] = [str(Path("/usr/bin/true").resolve(strict=True))]
        write_json(run / "agent-config.json", agent_cfg)
        (run / "agent-config.json").chmod(0o644)
        for name, uid, gid, directory_mode in (
            # GatewayServer grants group traversal only after binding the
            # private socket. Default ACL inheritance can bypass the umask,
            # so request the private mode here rather than relying on 077.
            ("endpoint", operator.pw_uid, agent.pw_gid, 0o700),
            ("agent", agent.pw_uid, agent.pw_gid, 0o700),
        ):
            path = run / name
            path.mkdir(mode=directory_mode)
            os.chown(path, uid, gid)
            path.chmod(directory_mode)
        python = str(run / "venv/bin/python")
        script = str(ROOT / "tools/run_codespace_agent_gateway.py")
        authority_log = (run / "private/authority.log").open("xb")
        logs.append(authority_log)
        os.chown(authority_log.name, operator.pw_uid, operator.pw_gid)
        groups = sorted(
            set(os.getgrouplist(operator.pw_name, operator.pw_gid)) | {agent.pw_gid}
        )
        authority = subprocess.Popen(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                script,
                "--_role",
                "authority",
                "--_run",
                str(run),
            ],
            stdout=authority_log,
            stderr=subprocess.STDOUT,
            env=clean_env(operator),
            cwd=ROOT,
            start_new_session=True,
            preexec_fn=lambda: drop_identity(operator, groups, parent),
        )
        deadline = time.monotonic() + 120
        while not endpoint_ready(
            run / "endpoint/agent.sock", operator.pw_uid, agent.pw_gid
        ):
            if authority.poll() is not None or time.monotonic() >= deadline:
                gate_file = run / (
                    "private/local-gates.json"
                    if audit_mode == "local"
                    else "private/production-gates.json"
                )
                if gate_file.exists():
                    report["gate_failures"] = json.loads(gate_file.read_text()).get(
                        "failures", []
                    )
                raise RuntimeError(
                    "authority did not become ready; inspect private authority.log and the profile gate report"
                )
            time.sleep(0.2)
        report["checks"][audit_mode + "_authority_started"] = True
        report["checks"]["distinct_nonroot_uids"] = (
            agent.pw_uid != operator.pw_uid and agent.pw_uid > 0
        )
        agent_log = (run / "private/agent.log").open("xb")
        logs.append(agent_log)
        os.chown(agent_log.name, operator.pw_uid, operator.pw_gid)
        agent_env = clean_env(agent)
        agent_env.update(
            GIT_CONFIG_COUNT="1",
            GIT_CONFIG_KEY_0="safe.directory",
            GIT_CONFIG_VALUE_0=str(ROOT),
        )
        agent_process = subprocess.Popen(
            [python, "-I", "-B", script, "--_role", "agent", "--_run", str(run)],
            stdout=agent_log,
            stderr=subprocess.STDOUT,
            env=agent_env,
            cwd=ROOT,
            start_new_session=True,
            preexec_fn=lambda: drop_identity(agent, [agent.pw_gid]),
        )
        rc = agent_process.wait(timeout=210)
        result_path = run / "agent/result.json"
        if result_path.exists():
            private_path(result_path, agent.pw_uid)
            report["agent_result"] = json.loads(result_path.read_text())
        if (
            rc != 0
            or report.get("agent_result", {}).get("status") != expected_status
            or report.get("agent_result", {}).get("audit_mode") != audit_mode
        ):
            raise RuntimeError(
                "live client refused or failed; inspect private agent.log and agent result"
            )
        report["checks"]["agent_cannot_modify_authority_or_read_keys"] = True
        report["checks"].update(report["agent_result"]["checks"])
        stop_child(authority)
        authority = None
        report["audit"] = verify_retained_audit(
            run, report["agent_result"], audit_mode=audit_mode
        )
        report["checks"]["retained_audit_matches_mcp_result"] = True
        report["checks"][audit_mode + "_checkpoint_reached_head"] = True
        if not all(report["checks"].values()):
            raise ValueError("one or more live evidence checks failed")
        report["status"] = expected_status
    except (Exception, KeyboardInterrupt) as exc:
        report["status"] = "BLOCKED"
        report["reason"] = type(exc).__name__ + ": " + str(exc)[:700]
    finally:
        signal.alarm(0)
        for child in (agent_process, authority):
            try:
                stop_child(child)
            except (OSError, subprocess.SubprocessError) as exc:
                report["cleanup_error"] = type(exc).__name__
                report["status"] = "BLOCKED"
        for log in logs:
            log.close()
        if account_created:
            try:
                account_command("userdel", account)
                try:
                    grp.getgrnam(account)
                except KeyError:
                    pass
                else:
                    account_command("groupdel", account)
                report["checks"]["temporary_agent_removed"] = True
            except (OSError, ValueError, subprocess.SubprocessError):
                report["cleanup_error"] = "temporary account still exists: " + account
                report["status"] = "BLOCKED"
        agent_dir = run / "agent"
        if agent_dir.exists():
            for path in (agent_dir / "result.json", agent_dir):
                if path.exists() and not path.is_symlink():
                    os.chown(
                        path, operator.pw_uid, operator.pw_gid, follow_symlinks=False
                    )
        report_path = run / "report.json"
        write_json(report_path, report)
        os.chown(report_path, operator.pw_uid, operator.pw_gid)
    return 0 if report["status"] == expected_status else 1


def main(*, default_local=False):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment", type=Path)
    parser.add_argument(
        "--local",
        action="store_true",
        default=default_local,
        help="generate private local audit authority; no collector credentials",
    )
    parser.add_argument("--collector-url")
    parser.add_argument("--collector-key-file", type=Path)
    parser.add_argument(
        "--collector-from-env",
        action="store_true",
        help="explicitly use existing BULL_REMOTE_AUDIT_ANCHOR_* Codespaces secrets",
    )
    parser.add_argument("--install-deps", action="store_true")
    parser.add_argument(
        "--preflight", action="store_true", help="read-only host and collector checks"
    )
    parser.add_argument(
        "--_role", choices=("root", "authority", "agent"), help=argparse.SUPPRESS
    )
    parser.add_argument("--_run", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    if args._role:
        return {"root": root_worker, "authority": authority_role, "agent": agent_role}[
            args._role
        ](args._run)
    checks = host_checks()
    user = pwd.getpwuid(os.geteuid())
    mode = "local" if args.local else "external"
    expected_status = pass_status(mode)
    configuration = (
        {"mode": "local", "external_collector_required": False}
        if args.local
        else collector_configuration(user)
    )
    if args.preflight:
        report = {
            "status": "BLOCKED",
            "checks": checks,
            "collector_configuration": configuration,
            "certified": False,
        }
        try:
            select_audit(args, user)
            report["checks"][
                (
                    "local_audit_selected"
                    if args.local
                    else "external_collector_configured"
                )
            ] = True
        except (OSError, ValueError) as exc:
            report["checks"]["audit_configuration"] = False
            report["reason"] = str(exc)
        if all(checks.values()):
            report["status"] = (
                "READY_FOR_LOCAL_CHECKS"
                if args.local
                else "READY_FOR_PRODUCTION_CHECKS"
            )
        print(json.dumps(report, indent=2))
        return 0 if all(checks.values()) else 1

    run = Path(tempfile.mkdtemp(prefix="bull-mcp-live-"))
    print("Evidence directory: " + str(run), flush=True)
    report = {
        "status": "BLOCKED",
        "checks": checks,
        "enterprise_qualified": False,
        "audit_mode": mode,
    }
    try:
        if not all(checks.values()):
            raise ValueError(
                "host prerequisites failed: "
                + ", ".join(k for k, v in checks.items() if not v)
            )
        (run / "private").mkdir(mode=0o700)
        url, key = select_audit(
            args, user, secret_destination=run / "private/input-collector.key"
        )
        # The authority gets the key from its private deployment. Never forward
        # the injected master secret into installers or the separate agent.
        os.environ.pop("BULL_REMOTE_AUDIT_ANCHOR_KEY", None)
        os.environ.pop("BULL_ANCHOR_MASTER_KEY", None)
        revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
        if subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=ROOT, text=True
        ).strip():
            raise ValueError("run from a clean reviewed source checkout")
        report["source_commit"] = revision
        env = clean_env(user)
        subprocess.run(["sudo", "-v"], check=True, timeout=60)
        if args.install_deps:
            subprocess.run(["sudo", "-n", "apt-get", "update"], check=True, timeout=240)
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "apt-get",
                    "install",
                    "-y",
                    "python3-venv",
                    "libseccomp2",
                    "util-linux",
                    "clamav",
                ],
                check=True,
                timeout=600,
            )
        if not shutil.which("clamscan", path=env["PATH"]):
            raise ValueError(
                "ClamAV is required; rerun with --install-deps and supply current official databases"
            )
        # Keep the installation private until public code permissions are verified.
        with (run / "setup.log").open("xb") as log:

            def setup(command):
                subprocess.run(
                    command,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=True,
                    env=env,
                    timeout=600,
                    umask=0o022,
                )

            code = run / "source"
            setup(["git", "init", "-q", str(code)])
            setup(
                [
                    "git",
                    "-C",
                    str(code),
                    "fetch",
                    "--depth=1",
                    "--no-tags",
                    str(ROOT),
                    revision,
                ]
            )
            setup(["git", "-C", str(code), "checkout", "-q", "--detach", "FETCH_HEAD"])
            setup(["/usr/bin/python3", "-m", "venv", "--copies", str(run / "venv")])
            print("Installing MCP in the isolated test environment...", flush=True)
            setup(
                [
                    str(run / "venv/bin/python"),
                    "-m",
                    "pip",
                    "install",
                    str(code) + "[mcp]",
                ]
            )
        prepare_public_runtime(run)
        (run / "private/lease").mkdir(mode=0o700)
        (run / "project").mkdir(mode=0o700)
        (run / "project/check.txt").write_text(
            "Harmless BULL connected-tool qualification input.\n"
        )
        write_json(
            run / "config.json",
            {
                "operator_uid": user.pw_uid,
                "source": str(code),
                "source_commit": revision,
                "collector_url": url,
                "collector_key_file": str(key) if key is not None else None,
                "audit_mode": mode,
            },
        )
        print(
            "Starting separate agent UID and the " + mode + " audit authority...",
            flush=True,
        )
        child = subprocess.run(
            [
                "sudo",
                "-n",
                "/usr/bin/python3",
                "-I",
                "-B",
                str(code / "tools/run_codespace_agent_gateway.py"),
                "--_role",
                "root",
                "--_run",
                str(run),
            ]
        )
        if (run / "report.json").exists():
            report = json.loads((run / "report.json").read_text())
        if child.returncode and "reason" not in report:
            report["reason"] = "sudo provisioning or the live gateway check failed"
    except (Exception, KeyboardInterrupt) as exc:
        report["reason"] = type(exc).__name__ + ": " + str(exc)[:700]
    report["collector_configuration"] = configuration
    write_json(run / "report.json", report)
    print(
        json.dumps(
            {
                "status": report["status"],
                "report": str(run / "report.json"),
                "checks": report.get("checks", {}),
                "reason": report.get("reason"),
                "gate_failures": report.get("gate_failures", []),
                "audit_mode": mode,
                "collector_configuration": configuration,
                "enterprise_qualified": False,
            },
            indent=2,
        )
    )
    print(
        "Keep private/ and deployment keys local; share only the redacted report.json."
    )
    return 0 if report["status"] == expected_status else 1


if __name__ == "__main__":
    raise SystemExit(main())

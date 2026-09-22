#!/usr/bin/env python3
"""Prepare operator-owned BULL deployments without shared keys or machine paths.

Provisioning is not certification. This tool does not change host permissions,
contact collectors, enroll hardware automatically, or overwrite an installation.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shlex
import stat
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from bulldog.approval_crypto import validate_public_key
from bulldog.integrity import build_integrity_manifest, sign_integrity_manifest, verify_integrity_manifest
from bulldog.policy_bundle import sign_policy_bundle, verify_policy_bundle
from bulldog.models import Capability

FORMAT = "bull-deployment-config-v1"
CAPABILITIES = ["fs.read.project", "process.exec"]


def canonical_path(path, *, exists=True):
    path = Path(os.path.abspath(path))
    if path.resolve(strict=exists) != path or path.is_symlink():
        raise ValueError("path must be canonical without symlinks: " + str(path))
    return path


def private_directory(path):
    path = canonical_path(path)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("deployment directory must be owned by this UID and mode 0700")
    return path


def private_read(path, *, maximum=65536):
    path = canonical_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > maximum):
            raise ValueError("deployment file must be a bounded private regular file")
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("deployment file exceeds size limit")
    return value


def secret_text(raw):
    if not 32 <= len(raw) <= 4096 or b"\0" in raw:
        raise ValueError("key must contain 32..4096 UTF-8 bytes without NUL")
    return raw.decode("utf-8")  # No stripping: collector key bytes are exact.


def write_new(path, value):
    raw = value if isinstance(value, bytes) else (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def collector_url(value):
    if value is None:
        return None
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.hostname in {"localhost", "127.0.0.1", "::1"}
            or any(ord(c) <= 32 or ord(c) == 127 for c in value)):
        raise ValueError("collector URL must be non-local HTTPS without credentials, query or fragment")
    return value


def public_key(path):
    path = canonical_path(path)
    if not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("invalid public-key file")
    key = " ".join(path.read_text().split()[:2])
    validate_public_key(key)
    return key


def policy_for(state, project, key, approval=None, capabilities=None):
    config = None
    if approval is not None:
        config = {"state_directory": str(state / "approvals"), "credentials": {"operator": approval},
                  "routine_egress_urls": [], "ttl_seconds": 300}
    return sign_policy_bundle(project_root=str(project), allowed_capabilities=capabilities or CAPABILITIES,
                              key=key, key_id="deployment-policy", human_approval=config)


def initialize(state, project, *, url=None, existing_collector_key=None, approval_public_key=None,
               approval_key=None, assets=None, cgroup_parent=None, capabilities=None):
    state = canonical_path(state, exists=False)
    project = canonical_path(project)
    if not project.is_dir():
        raise ValueError("project root must be an existing directory")
    if state == project or project in state.parents or state == ROOT or ROOT in state.parents:
        raise ValueError("private deployment state must be outside the project and repository")
    url = collector_url(url)
    master = (private_read(existing_collector_key, maximum=4096) if existing_collector_key
              else secrets.token_hex(32).encode())
    secret_text(master)
    enrolled = public_key(approval_public_key) if approval_public_key else None
    capabilities = sorted({Capability(x).value for x in (CAPABILITIES if capabilities is None else capabilities)})
    if not capabilities:
        raise ValueError("at least one explicit capability is required")
    if set(capabilities) & {"credential.read", "network.outbound", "network.post", "security_control.write"} and not enrolled:
        raise ValueError("consequential capabilities require an enrolled approval public key")
    if approval_key and not enrolled:
        raise ValueError("an approval key handle requires an enrolled public key")
    if approval_key:
        private_read(approval_key)
    if assets:
        from tools.deployment_check import checked_assets
        checked_assets(canonical_path(assets))
    # A caller may supply a not-yet-created cgroup; readiness is tested separately.
    cgroup_parent = str(canonical_path(cgroup_parent, exists=False)) if cgroup_parent else None
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.parent.resolve() != state.parent:
        raise ValueError("deployment parent changed")
    state.mkdir(mode=0o700, exist_ok=False)  # Re-runs never rotate or erase authority.
    for name in ("secrets", "snapshots", "audit", "approvals"):
        (state / name).mkdir(mode=0o700)
    ik, pk = secrets.token_hex(32), secrets.token_hex(32)
    for name, value in (("integrity.key", ik.encode()), ("policy.key", pk.encode()), ("collector.key", master)):
        write_new(state / "secrets" / name, value)
    manifest = sign_integrity_manifest(build_integrity_manifest(ROOT / "src/bulldog"), ik)
    write_new(state / "integrity.json", manifest)
    write_new(state / "policy.json", policy_for(state, project, pk, enrolled, capabilities))
    if enrolled:
        write_new(state / "approval.pub", (enrolled + "\n").encode())
    config = {"format": FORMAT, "installation_id": secrets.token_hex(32),
              "audit_session": secrets.token_hex(32), "project_root": str(project), "capabilities": capabilities,
              "collector_url": url, "cgroup_parent": cgroup_parent,
              "assets": str(canonical_path(assets)) if assets else None,
              "approval_key": str(canonical_path(approval_key)) if approval_key else None,
              "approval_enrolled": enrolled is not None,
              "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()}
    write_new(state / "deployment.json", config)
    return state


def read_config(state):
    state = private_directory(state)
    private_directory(state / "secrets")
    config = json.loads(private_read(state / "deployment.json"))
    required = {"format", "installation_id", "audit_session", "project_root", "capabilities", "collector_url", "cgroup_parent",
                "assets", "approval_key", "approval_enrolled", "source_commit"}
    if not isinstance(config, dict) or set(config) != required or config["format"] != FORMAT:
        raise ValueError("unsupported deployment configuration")
    for name in ("installation_id", "audit_session"):
        if not isinstance(config[name], str) or len(config[name]) != 64 or any(c not in "0123456789abcdef" for c in config[name]):
            raise ValueError("invalid deployment identity")
    if type(config["approval_enrolled"]) is not bool:
        raise ValueError("invalid approval enrollment state")
    if (not isinstance(config["capabilities"], list) or not config["capabilities"]
            or config["capabilities"] != sorted({Capability(x).value for x in config["capabilities"]})):
        raise ValueError("invalid deployment capabilities")
    collector_url(config["collector_url"])
    project = canonical_path(config["project_root"])
    if state == project or project in state.parents:
        raise ValueError("private deployment state is inside the admitted project")
    for name in ("snapshots", "audit", "approvals"):
        private_directory(state / name)
    return state, config


def environment(state):
    state, config = read_config(state)
    ik = secret_text(private_read(state / "secrets/integrity.key", maximum=4096))
    pk = secret_text(private_read(state / "secrets/policy.key", maximum=4096))
    master = secret_text(private_read(state / "secrets/collector.key", maximum=4096))
    manifest = json.loads(private_read(state / "integrity.json", maximum=1024*1024))
    verify_integrity_manifest(ROOT / "src/bulldog", manifest, signature_key=ik, require_signature=True)
    policy = json.loads(private_read(state / "policy.json"))
    verified = verify_policy_bundle(policy, pk)
    if verified.project_root != config["project_root"] or {x.value for x in verified.capability_ceiling} != set(config["capabilities"]):
        raise ValueError("signed policy does not match this deployment")
    enrolled = public_key(state / "approval.pub") if config["approval_enrolled"] else None
    expected = policy_for(state, config["project_root"], pk, enrolled, config["capabilities"])
    if policy != expected:
        raise ValueError("signed approval policy does not match this deployment")
    values = {"BULL_SECCOMP_PROFILE": "strict", "BULL_INTEGRITY_MANIFEST": str(state / "integrity.json"),
              "BULL_INTEGRITY_MANIFEST_KEY": ik, "BULL_POLICY_BUNDLE": str(state / "policy.json"),
              "BULL_POLICY_BUNDLE_KEY": pk, "BULL_SNAPSHOT_ROOT": str(state / "snapshots"),
              "BULL_AUDIT_LEDGER": str(state / "audit/ledger.jsonl"), "BULL_AUDIT_TRANSPORT": "https",
              "BULL_REMOTE_AUDIT_ANCHOR_KEY": master, "BULL_AUDIT_SESSION_ID": config["audit_session"],
              "BULL_DEPLOYMENT_ANCHOR_KEY_FILE": str(state / "secrets/collector.key")}
    optional = {"BULL_REMOTE_AUDIT_ANCHOR_URL": config["collector_url"], "BULL_CGROUP_PARENT": config["cgroup_parent"],
                "BULL_DEPLOYMENT_ASSETS": config["assets"], "BULL_APPROVAL_KEY": config["approval_key"],
                "BULL_APPROVAL_PUBLIC_KEY": str(state / "approval.pub") if enrolled else None}
    values.update({k: v for k, v in optional.items() if v is not None})
    return values


def isolated_environment(state, inherited=None):
    # An installation must not silently borrow another operator's BULL authority.
    result = {k: v for k, v in (os.environ if inherited is None else inherited).items() if not k.startswith("BULL_")}
    result.update(environment(state))
    return result


def configure(state, *, url=None, cgroup_parent=None, assets=None):
    state, config = read_config(state)
    environment(state)  # Refuse to re-sign or repair changed runtime/policy bytes.
    if url is not None:
        if (state / "audit/ledger.jsonl").exists() and url != config["collector_url"]:
            raise ValueError("active audit destination changes require a new deployment")
        config["collector_url"] = collector_url(url)
    if cgroup_parent is not None:
        config["cgroup_parent"] = str(canonical_path(cgroup_parent, exists=False))
    if assets is not None:
        from tools.deployment_check import checked_assets
        assets = canonical_path(assets)
        checked_assets(assets)
        config["assets"] = str(assets)
    temporary = state / (".configuration-" + secrets.token_hex(8))
    write_new(temporary, config)
    try:
        os.replace(temporary, state / "deployment.json")
    finally:
        temporary.unlink(missing_ok=True)


def check_cgroup(parent):
    from bulldog.cgroup_scope import CgroupV2Scope
    parent = canonical_path(parent)
    if Path('/sys/fs/cgroup') not in parent.parents:
        raise ValueError("cgroup must be below the real /sys/fs/cgroup mount")
    # Reject ordinary-directory fixtures, including on a different mount.
    if parent.stat().st_dev != Path('/sys/fs/cgroup').stat().st_dev:
        raise ValueError("cgroup parent is not on the cgroup filesystem")
    with CgroupV2Scope(parent, memory_bytes=128*1024*1024, processes=32, cpu_quota_us=25000) as scope:
        limits = {"memory.max": "134217728", "pids.max": "32", "cpu.max": "25000 100000"}
        for name, expected in limits.items():
            if (scope.path / name).read_text().strip() != expected:
                raise ValueError("cgroup limit readback mismatch: " + name)
        probe = ('import os,sys; from pathlib import Path; '
                 'raise SystemExit(0 if str(os.getpid()) in (Path(sys.argv[1])/"cgroup.procs").read_text().split() else 1)')
        subprocess.run([sys.executable, "-I", "-c", probe, str(scope.path)],
                       preexec_fn=scope.attach_current, check=True, timeout=10)
    from tools.cgroup_check import check_limits
    return {"status": "PASS", "scope": "real placement, bounded resource enforcement and descendant cleanup",
            "checks": check_limits(parent)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="create new private authority; refuses an existing destination")
    init.add_argument("--state", type=Path, required=True)
    init.add_argument("--project-root", type=Path, required=True)
    init.add_argument("--collector-url")
    init.add_argument("--existing-collector-key", type=Path)
    init.add_argument("--approval-public-key", type=Path)
    init.add_argument("--approval-key", type=Path)
    init.add_argument("--assets", type=Path)
    init.add_argument("--cgroup-parent", type=Path)
    init.add_argument("--capability", action="append", choices=[c.value for c in Capability],
                      help="repeat to set an explicit capability ceiling; default: project read and process execution")
    update = commands.add_parser("configure", help="set this installation's endpoint, cgroup or verified assets")
    update.add_argument("--state", type=Path, required=True)
    update.add_argument("--collector-url")
    update.add_argument("--cgroup-parent", type=Path)
    update.add_argument("--assets", type=Path)
    show = commands.add_parser("show", help="show public configuration and readiness without keys")
    show.add_argument("--state", type=Path, required=True)
    shell = commands.add_parser("environment", help="write a new private shell environment file (never stdout)")
    shell.add_argument("--state", type=Path, required=True)
    shell.add_argument("--output", type=Path, required=True)
    check = commands.add_parser("cgroup-check", help="run bounded actual placement, resource enforcement and cleanup checks")
    check.add_argument("--state", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.command == "init":
            initialize(args.state, args.project_root, url=args.collector_url,
                       existing_collector_key=args.existing_collector_key, approval_public_key=args.approval_public_key,
                       approval_key=args.approval_key, assets=args.assets, cgroup_parent=args.cgroup_parent,
                       capabilities=args.capability)
        elif args.command == "configure":
            configure(args.state, url=args.collector_url, cgroup_parent=args.cgroup_parent, assets=args.assets)
        elif args.command == "environment":
            output = canonical_path(args.output, exists=False)
            state, _ = read_config(args.state)
            if output.parent != state:
                raise ValueError("environment output must be a new file inside the private deployment directory")
            # Clear inherited authority before loading this deployment's values.
            text = 'for bull_name in ${!BULL_@}; do unset "$bull_name"; done\n'
            text += "".join("export " + k + "=" + shlex.quote(v) + "\n" for k, v in environment(state).items())
            write_new(output, text.encode())
            print("Private environment written:", output)
            return 0
        elif args.command == "cgroup-check":
            values = environment(args.state)
            if not values.get("BULL_CGROUP_PARENT"):
                raise ValueError("cgroup parent is not configured")
            print(json.dumps(check_cgroup(values["BULL_CGROUP_PARENT"]), indent=2))
            return 0
        state, config = read_config(args.state)
        environment(state)
        print(json.dumps({"state": str(state), **config, "status": "PREPARED_NOT_CERTIFIED", "certified": False,
                          "collector_key_file": str(state / "secrets/collector.key")}, indent=2))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        print("Deployment setup failed: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Also permit imports of the repository's tools namespace when invoked directly.
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())

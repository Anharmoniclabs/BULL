#!/usr/bin/env python3
"""Run BULL deployment checks where invoked, including inside a Codespace.

Missing devices, credentials, or assets remain BLOCKED. No emulation fallback,
host security changes, downloaded VM assets, or automatic human certification.
External collector checks send fresh checkpoint metadata only when configured.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from microvm.evidence import ReceiptTransport, anchor_master


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    path.chmod(0o600)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_identity():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()
    files = {name: digest(ROOT / name) for name in git("ls-files").splitlines()
             if (ROOT / name).is_file() and not (ROOT / name).is_symlink()}
    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain")),
            "files": files}


def probe_kvm():
    """Check the actual device/API and create then close an empty VM descriptor."""
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        return {"status": "BLOCKED", "reason": "current live guest runner requires Linux x86-64"}
    fd = vm = None
    try:
        fd = os.open("/dev/kvm", os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        if not stat.S_ISCHR(os.fstat(fd).st_mode):
            raise ValueError("/dev/kvm is not a character device")
        version = fcntl.ioctl(fd, 0xAE00, 0)  # KVM_GET_API_VERSION
        if version != 12:
            raise ValueError("unsupported KVM API version")
        vm = fcntl.ioctl(fd, 0xAE01, 0)  # KVM_CREATE_VM; no guest memory or vCPU
        return {"status": "PASS", "api_version": version, "empty_vm_created": True,
                "scope": "device readiness only; no guest boot"}
    except (OSError, ValueError) as exc:
        return {"status": "BLOCKED", "reason": str(exc), "exception": type(exc).__name__}
    finally:
        if vm is not None:
            os.close(vm)
        if fd is not None:
            os.close(fd)


def checked_assets(manifest):
    if manifest.stat().st_size > 16384:
        raise ValueError("asset manifest exceeds size limit")
    values = json.loads(manifest.read_text())
    if set(values) != {"kernel", "rootfs", "firmware"}:
        raise ValueError("asset manifest must contain kernel, rootfs, and firmware")
    result = {}
    for name, entry in values.items():
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            raise ValueError("each asset requires path and sha256")
        path = Path(entry["path"])
        if (not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path
                or not path.is_file() or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"])):
            raise ValueError("asset path/hash is invalid: " + name)
        if digest(path) != entry["sha256"]:
            raise ValueError("asset SHA-256 mismatch: " + name)
        result[name] = entry
    return result


def check_external(out, endpoint, key_file):
    from bulldog.anchor_service import session_key
    from bulldog.audit import AuditLedger
    from bulldog.audit_transport import AnchorIdentity, HTTPSAnchorTransport
    out.mkdir(mode=0o700)
    session = secrets.token_hex(32)
    identity = AnchorIdentity(session, session_key(anchor_master(key_file), session))
    upstream = HTTPSAnchorTransport(endpoint, identity)
    if not upstream.production_ready:
        raise ValueError("external collector requires non-local HTTPS with system certificate trust")
    transport = ReceiptTransport(upstream, out / "receipt.json")
    ledger = AuditLedger(out / "ledger.jsonl", transport=transport)
    ledger.append_event("deployment_validation", {"scope": "host-only collector check"})
    audit = ledger.verify()
    receipt = transport.completion(session, {"valid": audit.valid, "records": audit.records,
                                             "head_hash": audit.head_hash})
    result = {"status": "PASS", "session": session, "receipt": receipt,
              "scope": "host-to-external authenticated checkpoint; no guest or independent durability proof"}
    save(out / "report.json", result)
    return result


class Checks:
    def __init__(self, out):
        self.out, self.gates = out, {}

    def record(self, name, status, **detail):
        self.gates[name] = {"status": status, **detail}
        print(name + ": " + status, flush=True)

    def command(self, name, argv, timeout=300, interactive=False, clean_authority=False):
        start = time.monotonic()
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        if clean_authority:
            env = {key: value for key, value in env.items() if not key.startswith("BULL_")}
        try:
            with (self.out / (name + ".log")).open("w") as log:
                if interactive:
                    # Preserve the terminal for PIN/touch; the signing CLI also
                    # enforces its own authenticator deadline.
                    code = subprocess.run(argv, cwd=ROOT, env=env, timeout=timeout, check=False).returncode
                else:
                    child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=log,
                                             stderr=subprocess.STDOUT, start_new_session=True)
                    try:
                        code = child.wait(timeout=timeout)
                    except (subprocess.TimeoutExpired, KeyboardInterrupt):
                        try:
                            os.killpg(child.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            child.wait(timeout=45)
                        except subprocess.TimeoutExpired:
                            os.killpg(child.pid, signal.SIGKILL)
                            child.wait(timeout=5)
                        raise
            self.record(name, "PASS" if code == 0 else "FAIL", returncode=code,
                        seconds=round(time.monotonic() - start, 3))
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.record(name, "FAIL", reason=str(exc))
        return self.gates[name]["status"] == "PASS"

    def pytest(self, name, selection):
        junit = self.out / (name + ".xml")
        passed = self.command(name, [sys.executable, "-m", "pytest", "-q", "--junitxml=" + str(junit), *selection], clean_authority=True)
        if not junit.exists():
            self.record(name, "FAIL", reason="missing test evidence")
            return
        suites = ET.parse(junit).getroot()
        counts = {key: sum(int(x.get(key, 0)) for x in suites.iter("testsuite"))
                  for key in ("tests", "failures", "errors", "skipped")}
        self.gates[name]["counts"] = counts
        if not passed or not counts["tests"] or any(counts[k] for k in ("failures", "errors", "skipped")):
            self.gates[name]["status"] = "FAIL"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tla-jar", type=Path)
    parser.add_argument("--deployment", type=Path, help="private state created by deployment_setup.py; ignores inherited BULL authority")
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--anchor-url")
    parser.add_argument("--anchor-key-file", type=Path)
    parser.add_argument("--approval-key", type=Path)
    parser.add_argument("--approval-public-key", type=Path)
    parser.add_argument("--cpu-profile", choices=("host", "amd-native-ssbd"), default="host")
    args = parser.parse_args(argv)
    out = args.output.resolve()
    if out == ROOT or ROOT in out.parents:
        parser.error("evidence must be outside the repository")
    os.umask(0o077)
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    checks = Checks(out)
    before = source_identity()
    save(out / "source.json", before)

    inputs = {"assets": "BULL_DEPLOYMENT_ASSETS", "anchor_url": "BULL_REMOTE_AUDIT_ANCHOR_URL",
              "anchor_key_file": "BULL_DEPLOYMENT_ANCHOR_KEY_FILE", "approval_key": "BULL_APPROVAL_KEY",
              "approval_public_key": "BULL_APPROVAL_PUBLIC_KEY"}
    if args.deployment:
        if any(getattr(args, name) is not None for name in inputs):
            parser.error("--deployment owns collector, approval and asset inputs; use deployment_setup.py configure")
        from tools.deployment_setup import isolated_environment, read_config
        try:
            prepared = isolated_environment(args.deployment)
            _, deployment = read_config(args.deployment)
            os.environ.clear()
            os.environ.update(prepared)
            save(out / "deployment.json", {"installation_id": deployment["installation_id"],
                                           "source_commit": deployment["source_commit"]})
            checks.record("deployment_configuration", "PASS", installation_id=deployment["installation_id"])
        except (OSError, ValueError, TypeError, KeyError, RuntimeError) as exc:
            checks.record("deployment_configuration", "FAIL", reason=str(exc))
            save(out / "report.json", {"format": "bull-deployment-evidence-v1", "certified": False,
                 "automated_checks_passed": False, "gates": checks.gates,
                 "scope": "Invalid deployment authority; no downstream checks executed."})
            return 1
    for name, variable in inputs.items():
        if getattr(args, name) is None and os.environ.get(variable):
            value = os.environ[variable]
            setattr(args, name, value if name == "anchor_url" else Path(value))

    if args.tla_jar:
        checks.command("source", [sys.executable, "tools/release_check.py", "--tla-jar", str(args.tla_jar.resolve()),
                                  "--output", str(out / "source-checks")], timeout=600, clean_authority=True)
    else:
        checks.record("source", "BLOCKED", reason="provide --tla-jar to collect current source evidence")
    checks.command("strict_host", [sys.executable, "-c",
        "import json; from bulldog.host_certify import certify_host; "
        "r=certify_host(dynamic=True, seccomp_profile='strict'); print(json.dumps(r)); "
        "raise SystemExit(0 if r['dynamic_certified'] is True else 1)"], clean_authority=True)
    checks.pytest("approval_protocol", ["tests/test_human_approval.py"])
    checks.gates["approval_protocol"]["scope"] = "synthetic SK credentials; physical device presence is not established"
    checks.pytest("live_local_tls", ["tests/test_anchor_service.py::test_real_local_tls_acceptance_and_unavailable_service"])
    checks.gates["live_local_tls"]["scope"] = "real loopback TLS with disposable certificate; not an external collector"

    required = ("BULL_SECCOMP_PROFILE", "BULL_INTEGRITY_MANIFEST", "BULL_INTEGRITY_MANIFEST_KEY",
                "BULL_POLICY_BUNDLE", "BULL_POLICY_BUNDLE_KEY", "BULL_AUDIT_LEDGER",
                "BULL_SNAPSHOT_ROOT", "BULL_CGROUP_PARENT")
    if args.deployment:
        required += ("BULL_REMOTE_AUDIT_ANCHOR_URL", "BULL_REMOTE_AUDIT_ANCHOR_KEY", "BULL_AUDIT_SESSION_ID")
        if os.environ.get("BULL_CGROUP_PARENT"):
            checks.command("cgroup_delegation", [sys.executable, "tools/deployment_setup.py", "cgroup-check",
                                                "--state", str(args.deployment.resolve())])
        else:
            checks.record("cgroup_delegation", "BLOCKED", reason="configure an administrator-delegated cgroup parent")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        checks.record("production_configuration", "BLOCKED", missing_environment=missing,
                      reason="production signed policy, integrity, audit and resource delegation must be provisioned")
    else:
        checks.command("production_configuration", [sys.executable, "-c",
            "from pathlib import Path; import bulldog; "
            "from bulldog.production_gate import verify_production_environment; "
            "verify_production_environment(package_root=Path(bulldog.__file__).parent); print('production gates: PASS')"])

    external_configured = bool(args.anchor_url and (args.anchor_key_file or os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY")))
    if external_configured:
        try:
            result = check_external(out / "external-host", args.anchor_url, args.anchor_key_file)
            checks.record("external_collector_host", **result)
        except Exception as exc:
            checks.record("external_collector_host", "FAIL", reason=str(exc))
    else:
        checks.record("external_collector_host", "BLOCKED", reason="provide collector URL and its existing key via file or Codespaces secret")

    checks.record("kvm_device", **probe_kvm())
    assets = None
    if args.assets:
        try:
            assets = checked_assets(args.assets)
            checks.record("guest_assets", "PASS", assets=assets)
        except (OSError, ValueError, TypeError) as exc:
            checks.record("guest_assets", "FAIL", reason=str(exc))
    else:
        checks.record("guest_assets", "BLOCKED", reason="provide BULL_DEPLOYMENT_ASSETS or --assets with pinned kernel/rootfs/firmware")
    if assets and checks.gates["kvm_device"]["status"] == "PASS":
        missing = [name for name in ("qemu-system-x86_64", "openssl", "mkfs.ext4", "debugfs") if not shutil.which(name)]
        if missing:
            checks.record("current_candidate_kvm", "BLOCKED", reason="missing executables", executables=missing)
        else:
            command = [sys.executable, "microvm/integration.py", "--case", "all", "--output", str(out / "kvm"),
                       "--cpu-profile", args.cpu_profile]
            for name, entry in assets.items():
                command.extend(["--" + name, entry["path"]])
            if external_configured:
                command.extend(["--external-url", args.anchor_url])
                if args.anchor_key_file:
                    command.extend(["--external-key-file", str(args.anchor_key_file.resolve())])
            checks.command("current_candidate_kvm", command, timeout=1200)
            if checks.gates["current_candidate_kvm"]["status"] == "PASS":
                try:
                    summary = json.loads((out / "kvm/summary.json").read_text())
                    expected = {"allowed", "denied", "timeout", "cancel", "missing-protection"}
                    if summary.get("status") != "PASS" or set(summary.get("cases", {})) != expected or any(v != "PASS" for v in summary["cases"].values()):
                        raise ValueError("incomplete KVM case evidence")
                    for name in expected:
                        evidence = json.loads((out / "kvm" / name / "report.json").read_text())
                        if evidence.get("revision") != before["commit"] or evidence.get("assets") != {k: v["sha256"] for k, v in assets.items()}:
                            raise ValueError("KVM source or assets differ from selected candidate")
                except (OSError, ValueError) as exc:
                    checks.record("current_candidate_kvm", "FAIL", reason=str(exc))
    else:
        checks.record("current_candidate_kvm", "BLOCKED", reason="requires usable KVM device and verified guest assets")
    if external_configured and checks.gates["current_candidate_kvm"]["status"] == "PASS":
        allowed = json.loads((out / "kvm/allowed/report.json").read_text())
        receipt = allowed.get("completion_receipt", {})
        audit = allowed.get("result", {}).get("audit", {})
        matched = (allowed.get("external_collector") is True and receipt.get("accepted") is True
                   and receipt.get("session") == allowed.get("session") and receipt.get("sequence") == audit.get("records")
                   and receipt.get("head_hash") == audit.get("head_hash") and bool(receipt.get("mac")))
        checks.record("external_collector_with_guest", "PASS" if matched else "FAIL", reason="guest completion correlated with authenticated upstream receipt")
    else:
        checks.record("external_collector_with_guest", "BLOCKED", reason="requires completed current KVM cases with configured external collector")

    if args.approval_key and args.approval_public_key:
        checks.command("hardware_approval_protocol", [sys.executable, "tools/hardware_approval_check.py",
                       "--key", str(args.approval_key.resolve()), "--public-key", str(args.approval_public_key.resolve()),
                       "--output", str(out / "hardware")], interactive=True)
        if checks.gates["hardware_approval_protocol"]["status"] == "PASS":
            try:
                ceremony = json.loads((out / "hardware/report.json").read_text())
                required_evidence = ("credential_protocol_verified", "signed_presence_and_verification", "replay_rejected", "audit_valid")
                if any(ceremony.get(name) is not True for name in required_evidence):
                    raise ValueError("incomplete approval ceremony evidence")
                checks.gates["hardware_approval_protocol"]["scope"] = "harmless credential ceremony; physical enrollment and informed consent require human evidence"
            except (OSError, ValueError) as exc:
                checks.record("hardware_approval_protocol", "FAIL", reason=str(exc))
    else:
        checks.record("hardware_approval_protocol", "BLOCKED", reason="provide enrolled approval key/public key and an accessible authenticator; physical interaction is required")
    after = source_identity()
    checks.record("unchanged_clean_source", "PASS" if before == after and not before["dirty"] else "FAIL")
    automated_pass = all(gate["status"] == "PASS" for gate in checks.gates.values())
    report = {"format": "bull-deployment-evidence-v1", "commit": before["commit"], "dirty": before["dirty"],
              "python": platform.python_version(), "platform": platform.platform(), "codespaces": os.environ.get("CODESPACES") == "true",
              "gates": checks.gates, "automated_checks_passed": automated_pass, "certified": False,
              "manual_gates": {"hardware_enrollment_and_informed_consent": "REQUIRES_HUMAN_EVIDENCE", "independent_review": "REQUIRES_INDEPENDENT_REVIEW"},
              "scope": "Observed checks in this environment; no universal security, independent review, or hardware attestation certification."}
    save(out / "report.json", report)
    save(out / "review-packet.json", {"commit": before["commit"], "source_manifest": "source.json", "report": "report.json",
         "review_required": ["adapter mediation coverage", "operator channel authentication", "real authenticator enrollment", "guest and host trust boundaries", "asset provenance", "collector durability"],
         "sharing": "Review reports locally before sharing. Do not share runtime/deployment directories, keys, or raw credential state."})
    print("Report: " + str(out / "report.json"))
    return 0 if automated_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())

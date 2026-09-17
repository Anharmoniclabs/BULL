from __future__ import annotations

import json
from pathlib import Path

import pytest

import bulldog.audit as audit_module
import bulldog.integrity as integrity_module
import bulldog.namespace_sandbox as namespace_module
import bulldog.production_gate as production_gate
from bulldog.audit import AuditIntegrityError, AuditLedger
from bulldog.integrity import (
    IntegrityViolation,
    build_integrity_manifest,
    sign_integrity_manifest,
    verify_integrity_manifest,
)
from bulldog.models import (
    ActionRequest,
    Capability,
    Decision,
    Evaluation,
    Provenance,
)
from bulldog.namespace_sandbox import (
    NamespaceSandbox,
    SandboxAttestationError,
)
from bulldog.production_gate import (
    ProductionGateFailure,
    verify_production_environment,
)
from bulldog.seccomp_policy import (
    DENIED_SYSCALLS,
    STRICT_ALLOWED_SYSCALLS,
)


def _attestation(nonce="NONCE", profile="strict") -> bytes:
    return (
        json.dumps(
            {
                "format": "bull-sandbox-attestation-v1",
                "nonce": nonce,
                "pid": 1,
                "no_new_privs": True,
                "seccomp": True,
                "seccomp_profile": profile,
                "seccomp_rules": 100,
                "network_interfaces": ["lo"],
                "network_isolated": True,
                "python": "/usr/bin/python3",
                "runtime_root": "/bull_runtime",
            }
        )
        + "\n"
    ).encode("utf-8")


def test_security_bootstrap_never_imports_from_agent_workspace():
    launcher = Path(namespace_module.__file__).with_name("_namespace_launcher.sh")
    text = launcher.read_text(encoding="utf-8")
    assert "/workspace/.bull_runtime" not in text
    assert 'sys.path[:] = ["/bull_runtime"]' in text
    assert 'mount --bind "$RUNTIME_ROOT" "$ROOTFS/bull_runtime"' in text


def test_backend_attestation_is_nonce_bound_and_strict():
    att = NamespaceSandbox._parse_attestation(
        _attestation(),
        expected_nonce="NONCE",
        expected_profile="strict",
    )
    assert att.pid == 1
    assert att.no_new_privs is True
    assert att.seccomp is True
    assert att.network_isolated is True
    assert att.runtime_root == "/bull_runtime"

    with pytest.raises(SandboxAttestationError):
        NamespaceSandbox._parse_attestation(
            _attestation(nonce="FORGED"),
            expected_nonce="NONCE",
            expected_profile="strict",
        )

    bad = json.loads(_attestation().decode("utf-8"))
    bad["network_interfaces"] = ["lo", "eth0"]
    with pytest.raises(SandboxAttestationError):
        NamespaceSandbox._parse_attestation(
            (json.dumps(bad) + "\n").encode(),
            expected_nonce="NONCE",
            expected_profile="strict",
        )


def test_strict_seccomp_is_default_deny_surface_not_blacklist():
    assert "execve" in STRICT_ALLOWED_SYSCALLS
    assert "openat" in STRICT_ALLOWED_SYSCALLS
    assert "socket" in STRICT_ALLOWED_SYSCALLS
    for syscall in (
        "mount",
        "ptrace",
        "bpf",
        "setns",
        "unshare",
        "io_uring_setup",
        "userfaultfd",
        "process_vm_writev",
    ):
        assert syscall in DENIED_SYSCALLS
        assert syscall not in STRICT_ALLOWED_SYSCALLS


def test_signed_integrity_manifest_rejects_manifest_replacement(tmp_path, monkeypatch):
    monkeypatch.setattr(
        integrity_module,
        "CRITICAL_FILES",
        ("a.py", "_namespace_launcher.sh"),
    )
    (tmp_path / "a.py").write_text("SAFE", encoding="utf-8")
    (tmp_path / "_namespace_launcher.sh").write_text("SAFE", encoding="utf-8")

    manifest = build_integrity_manifest(tmp_path)
    signed = sign_integrity_manifest(manifest, "deployment-secret")
    verify_integrity_manifest(
        tmp_path,
        signed,
        signature_key="deployment-secret",
        require_signature=True,
    )

    forged = json.loads(json.dumps(signed))
    forged["files"]["a.py"] = "0" * 64
    with pytest.raises(IntegrityViolation, match="signature mismatch"):
        verify_integrity_manifest(
            tmp_path,
            forged,
            signature_key="deployment-secret",
            require_signature=True,
        )


def _action():
    return ActionRequest(
        actor="host",
        task="test",
        operation="execute",
        resource="/usr/bin/true",
        capability=Capability.PROCESS_EXEC,
        granted_capabilities=frozenset({Capability.PROCESS_EXEC}),
        provenance=(Provenance.HUMAN,),
    )


def _evaluation():
    return Evaluation(Decision.ALLOW, 0.0, ("ok",))


class _FakeHTTPResponse:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def getcode(self):
        return self.status

    def read(self, _limit):
        return b""


def test_remote_audit_anchor_is_monotonic_and_fail_closed(tmp_path, monkeypatch):
    seen = []

    def good_urlopen(request, timeout):
        seen.append((request.full_url, request.data, timeout))
        return _FakeHTTPResponse()

    monkeypatch.setattr(audit_module, "urlopen", good_urlopen)
    ledger = AuditLedger(
        tmp_path / "audit.jsonl",
        remote_anchor_url="https://audit.example.invalid/anchor",
        remote_anchor_key="remote-secret",
    )
    ledger.append(_action(), _evaluation())
    assert ledger.verify().valid is True
    assert len(seen) == 1

    def broken_urlopen(request, timeout):
        raise OSError("anchor unavailable")

    monkeypatch.setattr(audit_module, "urlopen", broken_urlopen)
    with pytest.raises(AuditIntegrityError, match="delivery failed"):
        ledger.append(_action(), _evaluation())

    verification = ledger.verify()
    assert verification.valid is False
    assert "remote audit checkpoint" in str(verification.error)


def test_production_gate_requires_strict_profile_https_anchor_and_signature(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        production_gate,
        "certify_host",
        lambda **kwargs: {"certified": True, "dynamic_error": None},
    )
    monkeypatch.setattr(
        integrity_module,
        "CRITICAL_FILES",
        ("a.py",),
    )
    (tmp_path / "a.py").write_text("SAFE", encoding="utf-8")
    manifest = sign_integrity_manifest(
        build_integrity_manifest(tmp_path),
        "integrity-secret",
    )
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setenv("BULL_INTEGRITY_MANIFEST", str(manifest_path))
    monkeypatch.setenv("BULL_INTEGRITY_MANIFEST_KEY", "integrity-secret")
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_URL", "https://audit.example/anchor")
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_KEY", "audit-secret")
    monkeypatch.setenv("BULL_SECCOMP_PROFILE", "strict")

    verify_production_environment(package_root=tmp_path)

    monkeypatch.setenv("BULL_SECCOMP_PROFILE", "compat")
    with pytest.raises(ProductionGateFailure, match="strict"):
        verify_production_environment(package_root=tmp_path)

    monkeypatch.setenv("BULL_SECCOMP_PROFILE", "strict")
    monkeypatch.setenv("BULL_REMOTE_AUDIT_ANCHOR_URL", "http://audit.example/anchor")
    with pytest.raises(ProductionGateFailure, match="HTTPS"):
        verify_production_environment(package_root=tmp_path)

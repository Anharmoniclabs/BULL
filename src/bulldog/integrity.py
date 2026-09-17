from __future__ import annotations

from pathlib import Path
import hashlib
import hmac
import json
import platform


class IntegrityViolation(RuntimeError):
    pass


CRITICAL_FILES = (
    "audit.py",
    "canonicalizer.py",
    "cgroup_scope.py",
    "dispatcher.py",
    "egress_proxy.py",
    "engine.py",
    "filesystem_manifest.py",
    "host_certify.py",
    "integrity.py",
    "landlock_policy.py",
    "malware_scanner.py",
    "namespace_sandbox.py",
    "policy.py",
    "policy_bundle.py",
    "production_gate.py",
    "profiles.py",
    "resource_limits.py",
    "runtime.py",
    "seccomp_policy.py",
    "secret_broker.py",
    "secure_fs.py",
    "security_domain.py",
    "session_guard.py",
    "snapshot.py",
    "snapshot_worker.py",
    "trace_model.py",
    "trace_runtime.py",
    "workspace_limits.py",
    "_namespace_launcher.sh",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _canonical_manifest_bytes(manifest: dict) -> bytes:
    payload = {
        key: value
        for key, value in manifest.items()
        if key != "signature"
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_integrity_manifest(package_root: str | Path) -> dict:
    package_root = Path(package_root)
    files = {}
    for name in CRITICAL_FILES:
        path = package_root / name
        if not path.exists():
            raise IntegrityViolation(f"critical file missing: {name}")
        files[name] = sha256_file(path)
    return {
        "format": "bull-integrity-v2",
        "platform": platform.platform(),
        "algorithm": "sha256",
        "files": files,
    }


def sign_integrity_manifest(
    manifest: dict,
    key: bytes | str,
    *,
    key_id: str = "deployment",
) -> dict:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise IntegrityViolation("integrity signing key cannot be empty")

    signed = dict(manifest)
    signed["signature"] = {
        "type": "hmac-sha256",
        "key_id": str(key_id),
        "value": hmac.new(
            key,
            _canonical_manifest_bytes(signed),
            hashlib.sha256,
        ).hexdigest(),
    }
    return signed


def verify_manifest_signature(manifest: dict, key: bytes | str) -> None:
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise IntegrityViolation("integrity verification key cannot be empty")

    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        raise IntegrityViolation("integrity manifest is unsigned")
    if signature.get("type") != "hmac-sha256":
        raise IntegrityViolation("unsupported integrity signature type")

    supplied = str(signature.get("value", ""))
    expected = hmac.new(
        key,
        _canonical_manifest_bytes(manifest),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise IntegrityViolation("integrity manifest signature mismatch")


def verify_integrity_manifest(
    package_root: str | Path,
    manifest: dict,
    *,
    signature_key: bytes | str | None = None,
    require_signature: bool = False,
) -> None:
    if manifest.get("format") not in {"bull-integrity-v1", "bull-integrity-v2"}:
        raise IntegrityViolation("unsupported integrity manifest format")

    if require_signature:
        if signature_key is None:
            raise IntegrityViolation("signed integrity manifest requires a key")
        verify_manifest_signature(manifest, signature_key)
    elif signature_key is not None and "signature" in manifest:
        verify_manifest_signature(manifest, signature_key)

    actual = build_integrity_manifest(package_root)
    expected_files = manifest.get("files", {})
    if actual["files"] != expected_files:
        raise IntegrityViolation("trusted computing base hash mismatch")

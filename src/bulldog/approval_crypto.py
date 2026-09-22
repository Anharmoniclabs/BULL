"""OpenSSH security-key signature verification; no software-key fallback.

Enrollment of a real authenticator is an operator trust requirement. Signature
flags attest presence/verification under that enrolled key, not informed consent
or hardware manufacturer identity. No authenticator is attached in ordinary CI.
"""
from __future__ import annotations

import base64
import struct
import subprocess
import tempfile
from pathlib import Path

NAMESPACE = "bull-consequential-action-v1"
KEY_TYPES = {b"sk-ssh-ed25519@openssh.com", b"sk-ecdsa-sha2-nistp256@openssh.com"}
APPLICATION = b"ssh:bull-approval"
SSH_KEYGEN = "/usr/bin/ssh-keygen"


class ApprovalError(RuntimeError):
    pass


class _Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or count > len(self.data) - self.offset:
            raise ApprovalError("truncated signature encoding")
        value = self.data[self.offset:self.offset + count]
        self.offset += count
        return value

    def uint(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def string(self) -> bytes:
        return self.take(self.uint())

    def done(self) -> None:
        if self.offset != len(self.data):
            raise ApprovalError("trailing signature data")


def validate_public_key(public_key: str) -> bytes:
    try:
        fields = public_key.split()
        if len(fields) != 2 or len(public_key) > 4096:
            raise ApprovalError("expected one security-key public key without comment")
        algorithm = fields[0].encode("ascii")
        if algorithm not in KEY_TYPES:
            raise ApprovalError("only enrolled OpenSSH security keys are accepted")
        blob = base64.b64decode(fields[1], validate=True)
        reader = _Reader(blob)
        if reader.string() != algorithm:
            raise ApprovalError("public key algorithm mismatch")
        if algorithm == b"sk-ssh-ed25519@openssh.com":
            if len(reader.string()) != 32:
                raise ApprovalError("invalid Ed25519 security key")
        else:
            if reader.string() != b"nistp256" or len(reader.string()) != 65:
                raise ApprovalError("invalid P256 security key")
        if reader.string() != APPLICATION:
            raise ApprovalError("security key application must be ssh:bull-approval")
        reader.done()
        return blob
    except (ValueError, UnicodeError) as exc:
        raise ApprovalError("invalid public key encoding") from exc


def _inspect_signature(signature: bytes, public_blob: bytes) -> None:
    if not isinstance(signature, bytes) or len(signature) > 16384:
        raise ApprovalError("invalid signature size")
    try:
        lines = signature.strip().splitlines()
        if not lines or lines[0] != b"-----BEGIN SSH SIGNATURE-----" or lines[-1] != b"-----END SSH SIGNATURE-----":
            raise ApprovalError("expected an SSH signature, not approval text")
        reader = _Reader(base64.b64decode(b"".join(lines[1:-1]), validate=True))
        if reader.take(6) != b"SSHSIG" or reader.uint() != 1:
            raise ApprovalError("unsupported SSH signature")
        if reader.string() != public_blob:
            raise ApprovalError("signature does not match enrolled credential")
        if reader.string() != NAMESPACE.encode() or reader.string() != b"":
            raise ApprovalError("invalid approval signature namespace")
        if reader.string() not in {b"sha256", b"sha512"}:
            raise ApprovalError("unsupported signature hash")
        inner = _Reader(reader.string())
        reader.done()
        if inner.string() not in KEY_TYPES:
            raise ApprovalError("signature is not a security-key signature")
        inner.string()  # OpenSSH verifies the cryptographic signature below.
        flags = inner.take(1)[0]
        inner.uint()  # Authenticator counter; nonce + durable state prevents reuse.
        inner.done()
        if flags & 0x05 != 0x05:
            raise ApprovalError("both user presence and user verification are required")
    except (ValueError, struct.error) as exc:
        raise ApprovalError("invalid SSH signature encoding") from exc


def verify_hardware_signature(message: bytes, signature: bytes, public_key: str) -> None:
    blob = validate_public_key(public_key)
    _inspect_signature(signature, blob)
    # OpenSSH checks that flags, application, key and message are cryptographically
    # bound. Inspecting flags without verifying the signature would be insufficient.
    with tempfile.TemporaryDirectory(prefix="bull-approval-verify-") as directory:
        root = Path(directory)
        (root / "signers").write_text(f'approver namespaces="{NAMESPACE}" {public_key}\n')
        (root / "proof").write_bytes(signature)
        try:
            result = subprocess.run(
                [SSH_KEYGEN, "-Y", "verify", "-f", str(root / "signers"),
                 "-I", "approver", "-n", NAMESPACE, "-s", str(root / "proof")],
                input=message, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ApprovalError("signature verifier unavailable") from exc
        if result.returncode != 0:
            raise ApprovalError("approval signature verification failed")

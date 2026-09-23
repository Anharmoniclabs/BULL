"""Custom secure-element assertions for the existing durable ApprovalGate.

Enrollment is an operator assertion about inspected hardware, not remote
attestation. No diagnostic firmware or unsigned button event is a proof.
"""
import hashlib
import json
import re

from ..approval_crypto import ApprovalError
from .protocol import Request

KIND = "bull-hardware-p256-v1"


def validate_credential(value):
    fields = {"type", "protocol", "device_id", "public_key", "enabled", "provisioning"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ApprovalError("invalid hardware enrollment fields")
    if value["type"] != KIND or value["protocol"] != "BULL-AUTH-1" or type(value["enabled"]) is not bool:
        raise ApprovalError("unsupported hardware enrollment")
    for name, length in (("device_id", 64), ("public_key", 130)):
        if not isinstance(value[name], str) or not re.fullmatch(r"[0-9a-f]{" + str(length) + "}", value[name]):
            raise ApprovalError("invalid hardware " + name)
    provisioning = value["provisioning"]
    if not isinstance(provisioning, dict) or set(provisioning) != {
            "part", "serial", "config_sha256", "firmware_sha256", "key_origin"}:
        raise ApprovalError("hardware provisioning evidence required")
    if provisioning["key_origin"] != "secure-element-generated":
        raise ApprovalError("hardware key must be generated inside the secure element")
    for name in ("part", "serial"):
        if not isinstance(provisioning[name], str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", provisioning[name]):
            raise ApprovalError("invalid secure-element " + name)
    for name in ("config_sha256", "firmware_sha256"):
        if not isinstance(provisioning[name], str) or not re.fullmatch(r"[0-9a-f]{64}", provisioning[name]):
            raise ApprovalError("invalid provisioning fingerprint")
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), bytes.fromhex(value["public_key"]))
    except (ImportError, ValueError) as exc:
        raise ApprovalError("P-256 verifier unavailable or enrolled public key invalid") from exc
    return value


def counter_identity(credential):
    # Aliases and enrollment labels cannot reset a key's replay counter.
    return hashlib.sha256(bytes.fromhex(credential["public_key"])).hexdigest()


def request_for(message: bytes, credential_id: str) -> Request:
    from ..approval import canonical_bytes
    value = json.loads(message)
    action = value["action"]
    def digest(obj):
        return hashlib.sha256(canonical_bytes({"value": obj})).digest()
    try:
        request_id = bytes.fromhex(value["request_id"])
        request = Request(request_id, digest(action["session_id"]), digest(action),
                          digest(action["operation"]), digest(action["target"]),
                          digest(action["parameters"]), digest(action["policy_digest"]),
                          hashlib.sha256(b"bull-hardware-nonce-v1\0" + credential_id.encode() + b"\0" + message).digest(),
                          value["issued_at"], value["expires_at"])
        request.encode()
        return request
    except (KeyError, TypeError, ValueError) as exc:
        raise ApprovalError("pending request cannot be encoded for hardware") from exc

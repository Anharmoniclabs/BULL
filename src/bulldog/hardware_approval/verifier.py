"""Stateless assertion verification. Durable consumption belongs in ApprovalGate.

This function alone grants no execution authority and does not update counters.
"""
from .protocol import Assertion, Request, fixed
from ..approval_crypto import ApprovalError


def verify(assertion: Assertion, request: Request, *, public_key: bytes,
           device_id: bytes, enabled: bool, last_counter: int, now: int) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    request.encode()
    assertion.encode()
    if enabled is not True or assertion.device_id != fixed(device_id):
        raise ApprovalError("hardware device unknown or disabled")
    if not request.created <= now < request.expires:
        raise ApprovalError("hardware request expired or clock invalid")
    if (assertion.request_id != request.request_id or assertion.request_digest != request.digest
            or assertion.session_digest != request.session_digest or assertion.nonce != request.nonce):
        raise ApprovalError("hardware request binding mismatch")
    if type(last_counter) is not int or not 0 <= last_counter < assertion.counter:
        raise ApprovalError("hardware counter replay")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), fixed(public_key, 65))
        r = int.from_bytes(assertion.signature[:32], "big")
        s = int.from_bytes(assertion.signature[32:], "big")
        key.verify(encode_dss_signature(r, s), assertion.signed_bytes(), ec.ECDSA(hashes.SHA256()))
    except (ValueError, InvalidSignature) as exc:
        raise ApprovalError("invalid hardware signature") from exc

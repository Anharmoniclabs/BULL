"""Bounded, fixed-width network-byte-order BULL-AUTH-1 encoding.

Wire digests include domain separators. The request digest commits to the
session, nonce, complete action binding, and expiry. No arbitrary JSON is signed.
"""
from dataclasses import dataclass
from enum import IntEnum
import hashlib
import struct

from ..approval_crypto import ApprovalError

PROTOCOL = b"BULL-AUTH-1"
MAX_PACKET = 512
REQUEST = struct.Struct(">11sB32s32s32s32s32s32s32s32sQQ")
ASSERTION = struct.Struct(">11sB32s32s32s32s32sI")


class Decision(IntEnum):
    DENY = 0
    APPROVE = 1


def fixed(value: bytes, length: int = 32) -> bytes:
    if type(value) is not bytes or len(value) != length:
        raise ApprovalError("invalid fixed-width hardware field")
    return value


@dataclass(frozen=True)
class Request:
    request_id: bytes
    session_digest: bytes
    action_digest: bytes
    operation_digest: bytes
    resource_digest: bytes
    parameter_digest: bytes
    policy_digest: bytes
    nonce: bytes
    created: int
    expires: int

    def encode(self) -> bytes:
        if (type(self.created) is not int or type(self.expires) is not int
                or not 0 <= self.created < self.expires < 2**64
                or self.expires - self.created > 30):
            raise ApprovalError("invalid hardware request lifetime")
        return REQUEST.pack(PROTOCOL, 1, *(fixed(getattr(self, name)) for name in (
            "request_id", "session_digest", "action_digest", "operation_digest",
            "resource_digest", "parameter_digest", "policy_digest", "nonce")),
            self.created, self.expires)

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.encode()).digest()

    @classmethod
    def decode(cls, packet: bytes):
        fixed(packet, REQUEST.size)
        magic, kind, *fields = REQUEST.unpack(packet)
        if magic != PROTOCOL or kind != 1:
            raise ApprovalError("unsupported hardware request")
        value = cls(*fields)
        value.encode()
        return value


@dataclass(frozen=True)
class Assertion:
    decision: Decision
    device_id: bytes
    request_id: bytes
    request_digest: bytes
    session_digest: bytes
    nonce: bytes
    counter: int
    signature: bytes

    def signed_bytes(self) -> bytes:
        if type(self.decision) is not Decision:
            raise ApprovalError("invalid hardware decision")
        if type(self.counter) is not int or not 0 < self.counter < 2**32:
            raise ApprovalError("invalid hardware counter")
        return ASSERTION.pack(PROTOCOL, self.decision, *(fixed(getattr(self, name)) for name in (
            "device_id", "request_id", "request_digest", "session_digest", "nonce")), self.counter)

    def encode(self) -> bytes:
        return self.signed_bytes() + fixed(self.signature, 64)

    @classmethod
    def decode(cls, packet: bytes):
        fixed(packet, ASSERTION.size + 64)
        magic, decision, *fields = ASSERTION.unpack(packet[:ASSERTION.size])
        if magic != PROTOCOL:
            raise ApprovalError("unsupported hardware assertion")
        try:
            value = cls(Decision(decision), *fields, packet[ASSERTION.size:])
        except ValueError as exc:
            raise ApprovalError("invalid hardware decision") from exc
        value.encode()
        return value

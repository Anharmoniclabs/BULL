"""Software-generated keys are confined to tests; these do not attest hardware."""
from dataclasses import replace
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from bulldog.approval_crypto import ApprovalError
from bulldog.hardware_approval.protocol import Request, Assertion, Decision
from bulldog.hardware_approval.verifier import verify


@pytest.fixture
def ceremony():
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    request = Request(*(bytes([i])*32 for i in range(1, 9)), 100, 130)
    assertion = Assertion(Decision.APPROVE, b'd'*32, request.request_id,
                          request.digest, request.session_digest, request.nonce, 2, b'\0'*64)
    def sign(value):
        r, s = decode_dss_signature(key.sign(value.signed_bytes(), ec.ECDSA(hashes.SHA256())))
        return replace(value, signature=r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    kwargs = dict(public_key=pub, device_id=b'd'*32, enabled=True, last_counter=1, now=110)
    return request, sign(assertion), kwargs, sign


@pytest.mark.parametrize('decision', list(Decision))
def test_valid(ceremony, decision):
    req, assertion, kwargs, sign = ceremony
    assertion = sign(replace(assertion, decision=decision))
    verify(Assertion.decode(assertion.encode()), Request.decode(req.encode()), **kwargs)


@pytest.mark.parametrize('field', ['request_id', 'request_digest', 'session_digest', 'nonce', 'device_id'])
def test_binding(ceremony, field):
    req, assertion, kwargs, sign = ceremony
    with pytest.raises(ApprovalError):
        verify(sign(replace(assertion, **{field: b'x'*32})), req, **kwargs)


@pytest.mark.parametrize('change', [{'now': 130}, {'now': 99}, {'enabled': False},
                                  {'last_counter': 2}, {'last_counter': 3}, {'device_id': b'x'*32}])
def test_rejections(ceremony, change):
    req, assertion, kwargs, _ = ceremony
    with pytest.raises(ApprovalError):
        verify(assertion, req, **(kwargs | change))


def test_bad_signature(ceremony):
    req, assertion, kwargs, _ = ceremony
    with pytest.raises(ApprovalError):
        verify(replace(assertion, signature=b'\0'*64), req, **kwargs)


def test_skipped_counter(ceremony):
    req, assertion, kwargs, sign = ceremony
    verify(sign(replace(assertion, counter=9)), req, **kwargs)


@pytest.mark.parametrize('field', ['action_digest', 'policy_digest', 'parameter_digest', 'resource_digest'])
def test_changed_action(ceremony, field):
    req, assertion, kwargs, _ = ceremony
    with pytest.raises(ApprovalError):
        verify(assertion, replace(req, **{field: b'x'*32}), **kwargs)


@pytest.mark.parametrize('packet', [b'', b'YES', bytes(513), bytes(284), bytes(240)])
def test_malformed(packet):
    for codec in (Request, Assertion):
        with pytest.raises(ApprovalError):
            codec.decode(packet)

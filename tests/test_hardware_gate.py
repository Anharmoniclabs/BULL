"""Real P-256 signatures and durable gate/dispatcher checks; synthetic test keys only."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from types import SimpleNamespace
import json
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from bulldog.policy_bundle import PolicyBundleError
from bulldog.approval import ApprovalGate, ApprovalProof, ApprovalRequired, ApprovalError, validate_config
from bulldog.hardware_approval.protocol import Request, Assertion, Decision
from bulldog.hardware_approval.provider import KIND, request_for
from test_human_approval import setup as legacy_setup, dispatcher_fixture


@pytest.fixture
def custom(legacy_setup):
    s = legacy_setup
    key = ec.generate_private_key(ec.SECP256R1())
    pub = key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    s.config.update(ttl_seconds=30, credentials={'board': {
        'type': KIND, 'protocol': 'BULL-AUTH-1', 'device_id': 'ab'*32,
        'public_key': pub.hex(), 'enabled': True,
        'provisioning': {'part': 'SYNTHETIC-TEST-NOT-HARDWARE', 'serial': 'TEST',
                         'config_sha256': '12'*32, 'firmware_sha256': '34'*32,
                         'key_origin': 'secure-element-generated'}}})
    s.gate = ApprovalGate(s.config, audit=s.ledger.append_event, policy_digest=s.gate.policy_digest)
    def sign(gate, request_id, counter=1, decision=Decision.APPROVE, change=None):
        req = Request.decode(gate.hardware_request(request_id, 'board'))
        assertion = Assertion(decision, bytes.fromhex('ab'*32), req.request_id, req.digest,
                              req.session_digest, req.nonce, counter, bytes(64))
        if change: assertion = replace(assertion, **change)
        r, t = decode_dss_signature(key.sign(assertion.signed_bytes(), ec.ECDSA(hashes.SHA256())))
        assertion = replace(assertion, signature=r.to_bytes(32,'big')+t.to_bytes(32,'big'))
        return ApprovalProof(request_id, 'board', assertion.encode())
    s.sign = sign
    return s


def test_exact_protected_effect_uses_existing_dispatcher(custom):
    s=custom; dispatcher, request, calls, gate=dispatcher_fixture(s)
    url='https://example.com/result'
    with pytest.raises(ApprovalRequired) as pending:
        dispatcher.fetch_egress(url=url, request=request(url))
    assert calls == []
    proof=s.sign(gate,pending.value.request['request_id'])
    assert dispatcher.fetch_egress(url=url,request=request(url),approval=proof)=='fixture response'
    assert gate.inspect(proof.request_id)['outcome']=='completed'
    with pytest.raises(ApprovalError):dispatcher.fetch_egress(url=url,request=request(url),approval=proof)
    assert len(calls)==1


def test_signed_denial_is_terminal_audited_and_never_executes(custom):
    s=custom;dispatcher,request,calls,gate=dispatcher_fixture(s);url='https://example.com/result'
    with pytest.raises(ApprovalRequired) as pending:dispatcher.fetch_egress(url=url,request=request(url))
    proof=s.sign(gate,pending.value.request['request_id'],decision=Decision.DENY)
    with pytest.raises(ApprovalError,match='human denial'):dispatcher.fetch_egress(url=url,request=request(url),approval=proof)
    assert not calls and gate.inspect(proof.request_id)['state']=='denied'
    with pytest.raises(ApprovalError):dispatcher.fetch_egress(url=url,request=request(url),approval=proof)
    assert 'approval.human_denied' in (s.root/'audit.jsonl').read_text()


@pytest.mark.parametrize('field', ['request_id','request_digest','nonce','session_digest','device_id'])
def test_signed_binding_mismatch_rejected(custom,field):
    s=custom;r=s.gate.request(s.binding);proof=s.sign(s.gate,r['request_id'],change={field:b'x'*32})
    with pytest.raises(ApprovalError):s.gate.consume(s.binding,proof)
    assert s.gate.inspect(r['request_id'])['state']=='pending'


def test_counter_survives_restart_denial_and_allows_skips(custom):
    s=custom;r=s.gate.request(s.binding)
    with pytest.raises(ApprovalError,match='human denial'):
        s.gate.consume(s.binding,s.sign(s.gate,r['request_id'],counter=5,decision=Decision.DENY))
    gate=ApprovalGate(s.config,audit=s.ledger.append_event,policy_digest=s.gate.policy_digest)
    r=gate.request(s.binding)
    with pytest.raises(ApprovalError,match='counter replay'):gate.consume(s.binding,s.sign(gate,r['request_id'],counter=5))
    assert gate.consume(s.binding,s.sign(gate,r['request_id'],counter=9))==r['request_id']


def test_parallel_consumption_has_one_winner(custom):
    s=custom;r=s.gate.request(s.binding);proof=s.sign(s.gate,r['request_id'])
    def attempt(_):
        gate=ApprovalGate(s.config,audit=lambda *a:'receipt',policy_digest=s.gate.policy_digest)
        try:gate.consume(s.binding,proof);return True
        except ApprovalError:return False
    with ThreadPoolExecutor(max_workers=4) as pool:assert sum(pool.map(attempt,range(4)))==1


@pytest.mark.parametrize('failure',['disabled','unknown','expired','cancelled','bad-signature','diagnostic','oversized','policy','action','argv','executable'])
def test_failure_never_releases_authority(custom,monkeypatch,failure):
    s=custom;r=s.gate.request(s.binding);proof=s.sign(s.gate,r['request_id']);binding=s.binding
    if failure=='disabled':s.gate.config['credentials']['board']['enabled']=False
    elif failure=='unknown':proof=replace(proof,credential_id='unknown')
    elif failure=='expired':monkeypatch.setattr('bulldog.approval.time.time',lambda:r['expires_at'])
    elif failure=='cancelled':s.gate.cancel(r['request_id'])
    elif failure=='bad-signature':proof=replace(proof,signature=proof.signature[:-64]+bytes(64))
    elif failure=='diagnostic':proof=replace(proof,signature=b'BULL-DIAG-3'+bytes(53))
    elif failure=='oversized':proof=replace(proof,signature=bytes(513))
    elif failure=='policy':binding=dict(binding,policy_digest='different')
    elif failure=='action':binding=dict(binding,target='https://example.com/changed')
    else:binding=dict(binding,parameters=dict(binding['parameters'],**{failure:'changed'}))
    with pytest.raises(ApprovalError):s.gate.consume(binding,proof)
    assert s.gate.inspect(r['request_id'])['state']!='consumed'


def test_audit_outage_consumes_request_and_counter_before_effect(custom):
    s=custom;dispatcher,request,calls,gate=dispatcher_fixture(s);url='https://example.com/result'
    with pytest.raises(ApprovalRequired) as pending:dispatcher.fetch_egress(url=url,request=request(url))
    proof=s.sign(gate,pending.value.request['request_id'])
    def outage(*args):raise OSError('collector unavailable')
    gate.audit=outage
    with pytest.raises(OSError):dispatcher.fetch_egress(url=url,request=request(url),approval=proof)
    assert not calls and gate.inspect(proof.request_id)['state']=='consumed'
    restarted=ApprovalGate(s.config,audit=s.ledger.append_event,policy_digest=gate.policy_digest)
    with pytest.raises(ApprovalError):restarted.consume(pending.value.request['action'],proof)


def test_policy_drift_after_consume_blocks_effect(custom):
    s=custom;dispatcher,request,calls,gate=dispatcher_fixture(s);url='https://example.com/result'
    with pytest.raises(ApprovalRequired) as pending:dispatcher.fetch_egress(url=url,request=request(url))
    proof=s.sign(gate,pending.value.request['request_id'])
    original=gate.consume
    def consume(*args):
        result=original(*args)
        dispatcher.runtime._policy_bundle_path.write_text('{}')
        return result
    gate.consume=consume
    with pytest.raises(PolicyBundleError):dispatcher.fetch_egress(url=url,request=request(url),approval=proof)
    assert not calls and gate.inspect(proof.request_id)['state']=='consumed'


def test_disabled_enrollment_cannot_export_and_missing_evidence_rejected(custom):
    s=custom;r=s.gate.request(s.binding)
    s.gate.config['credentials']['board']['enabled']=False
    with pytest.raises(ApprovalError):s.gate.hardware_request(r['request_id'],'board')
    broken=json.loads(json.dumps(s.config));del broken['credentials']['board']['provisioning']
    with pytest.raises(ApprovalError):validate_config(broken)

"""Deterministic approval conformance tests with real OpenSSH verification.

The software-generated SK fixtures below test the wire protocol and verifier.
They do NOT establish hardware presence. Real enrollment/ceremony is a separate
release gate. No external endpoints, real credentials or unsafe workloads used.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

from bulldog.approval import (ApprovalGate, ApprovalProof, ApprovalRequired, binding_for,
                             canonical_bytes, digest, validate_config)
from bulldog.approval_crypto import (ApprovalError, APPLICATION, NAMESPACE,
                                    validate_public_key, verify_hardware_signature)
from bulldog.audit import AuditLedger
from bulldog.canonicalizer import TrustedExecutionContext
from bulldog.dispatcher import DispatchDenied, DispatchRequest
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Provenance
from bulldog.policy_bundle import sign_policy_bundle, load_policy_bundle
from bulldog.policy import DeterministicPolicy
from bulldog.profiles import ProductionDispatcher


def string(value):
    return struct.pack(">I", len(value)) + value


class SyntheticSK:
    def __init__(self, algorithm="ed25519"):
        self.algorithm = algorithm
        if algorithm == "ed25519":
            self.key = ed25519.Ed25519PrivateKey.generate()
            self.name = b"sk-ssh-ed25519@openssh.com"
            self.blob = string(self.name) + string(self.key.public_key().public_bytes_raw()) + string(APPLICATION)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
            self.name = b"sk-ecdsa-sha2-nistp256@openssh.com"
            point = self.key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            self.blob = string(self.name) + string(b"nistp256") + string(point) + string(APPLICATION)
        self.public = self.name.decode() + " " + base64.b64encode(self.blob).decode()

    def sign(self, message, *, flags=5, namespace=NAMESPACE):
        signed = b"SSHSIG" + string(namespace.encode()) + string(b"") + string(b"sha512") + string(hashlib.sha512(message).digest())
        auth = hashlib.sha256(APPLICATION).digest() + bytes([flags]) + struct.pack(">I", 1) + hashlib.sha256(signed).digest()
        if self.algorithm == "ed25519":
            signature = self.key.sign(auth)
        else:
            r, s = decode_dss_signature(self.key.sign(auth, ec.ECDSA(hashes.SHA256())))
            def mpint(x):
                return string(x.to_bytes((x.bit_length() + 8) // 8, "big"))
            signature = mpint(r) + mpint(s)
        inner = string(self.name) + string(signature) + bytes([flags]) + struct.pack(">I", 1)
        blob = b"SSHSIG" + struct.pack(">I", 1) + string(self.blob) + string(namespace.encode()) + string(b"") + string(b"sha512") + string(inner)
        return b"-----BEGIN SSH SIGNATURE-----\n" + base64.b64encode(blob) + b"\n-----END SSH SIGNATURE-----\n"


@pytest.fixture
def setup(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    key = SyntheticSK()
    config = {"state_directory": str(state), "credentials": {"operator": key.public},
              "routine_egress_urls": ["https://example.com/manual"], "ttl_seconds": 300}
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    gate = ApprovalGate(config, audit=ledger.append_event, policy_digest="fixture-policy")
    action = ActionRequest(actor="agent", task="fixture", operation="fetch", resource="https://example.com/result",
                           capability=Capability.NETWORK_OUTBOUND,
                           granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}),
                           provenance=(Provenance.HUMAN,), metadata={"domain_id": "domain-1", "security_context_id": "ctx"})
    binding = binding_for(action, operation="network.request", parameters={"method": "GET"},
                          policy_digest=gate.policy_digest, session_id="session-1")
    return SimpleNamespace(root=tmp_path, key=key, config=config, ledger=ledger, gate=gate, action=action, binding=binding)


def proof_for(s, request):
    return ApprovalProof(request["request_id"], "operator", s.key.sign(canonical_bytes(request)))


@pytest.mark.parametrize("algorithm", ["ed25519", "p256"])
def test_real_openssh_accepts_valid_synthetic_sk_signature(algorithm):
    key = SyntheticSK(algorithm)
    signature = key.sign(b"fixture message")
    verify_hardware_signature(b"fixture message", signature, key.public)
    with pytest.raises(ApprovalError):
        verify_hardware_signature(b"different message", signature, key.public)


@pytest.mark.parametrize("flags", [0, 1, 4])
def test_presence_and_user_verification_are_both_required(flags):
    key = SyntheticSK()
    with pytest.raises(ApprovalError, match="presence"):
        verify_hardware_signature(b"fixture", key.sign(b"fixture", flags=flags), key.public)


def test_text_and_cross_namespace_proofs_rejected():
    key = SyntheticSK()
    for value in (b"APPROVE", b"\n", key.sign(b"fixture", namespace="file")):
        with pytest.raises(ApprovalError):
            verify_hardware_signature(b"fixture", value, key.public)


def test_software_key_type_rejected():
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    text = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    with pytest.raises(ApprovalError, match="security keys"):
        validate_public_key(text)


def test_pending_has_no_authority_and_exact_approval_consumed_once(setup):
    s = setup
    with pytest.raises(ApprovalRequired) as pending:
        s.gate.consume(s.binding, None)
    request = pending.value.request
    assert s.gate.inspect(request["request_id"])["state"] == "pending"
    proof = proof_for(s, request)
    assert s.gate.consume(s.binding, proof) == request["request_id"]
    assert s.gate.inspect(request["request_id"])["outcome"] == "uncertain"
    with pytest.raises(ApprovalError):
        s.gate.consume(s.binding, proof)
    s.gate.finish(request["request_id"], "completed")
    assert s.gate.inspect(request["request_id"])["outcome"] == "completed"
    assert s.ledger.verify().valid


@pytest.mark.parametrize("field,value", [
    ("target", "https://example.com/different"), ("actor", "other"),
    ("domain_id", "child"), ("root_domain_id", "other-root"),
    ("security_context_id", "other-ctx"), ("session_id", "next-session"),
    ("policy_digest", "new-policy"), ("parameters", {"method": "POST"}),
    ("granted_capabilities", ["network.post"]), ("operation", "send"),
])
def test_changed_binding_rejected_without_consuming_original(setup, field, value):
    s = setup
    request = s.gate.request(s.binding)
    with pytest.raises(ApprovalError):
        s.gate.consume(dict(s.binding, **{field: value}), proof_for(s, request))
    assert s.gate.inspect(request["request_id"])["state"] == "pending"


def test_expiry_cancellation_and_revocation(setup, monkeypatch):
    s = setup
    request = s.gate.request(s.binding)
    proof = proof_for(s, request)
    with monkeypatch.context() as patch:
        patch.setattr("bulldog.approval.time.time", lambda: request["expires_at"])
        with pytest.raises(ApprovalError, match="expired"):
            s.gate.consume(s.binding, proof)
    s.gate.cancel(request["request_id"])
    with pytest.raises(ApprovalError):
        s.gate.consume(s.binding, proof)
    other = SyntheticSK()
    revoked = ApprovalGate(dict(s.config, credentials={"replacement": other.public}),
                           audit=s.ledger.append_event, policy_digest="new-policy")
    with pytest.raises(ApprovalError, match="revoked"):
        revoked.consume(s.binding, proof)


def test_wrong_key_cannot_sign_for_enrolled_identity(setup):
    s = setup
    request = s.gate.request(s.binding)
    proof = ApprovalProof(request["request_id"], "operator", SyntheticSK().sign(canonical_bytes(request)))
    with pytest.raises(ApprovalError, match="enrolled"):
        s.gate.consume(s.binding, proof)


def test_parallel_consumption_and_restart_allow_at_most_one(setup):
    s = setup
    request = s.gate.request(s.binding)
    proof = proof_for(s, request)
    def attempt(_):
        gate = ApprovalGate(s.config, audit=s.ledger.append_event, policy_digest=s.gate.policy_digest)
        try:
            gate.consume(s.binding, proof)
            return True
        except ApprovalError:
            return False
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(attempt, range(8))) == 1
    restarted = ApprovalGate(s.config, audit=s.ledger.append_event, policy_digest=s.gate.policy_digest)
    with pytest.raises(ApprovalError):
        restarted.consume(s.binding, proof)


def test_audit_failure_leaves_consumed_request_nonreplayable(setup):
    s = setup
    request = s.gate.request(s.binding)
    proof = proof_for(s, request)
    def unavailable(*args):
        raise RuntimeError("collector unavailable")
    gate = ApprovalGate(s.config, audit=unavailable, policy_digest=s.gate.policy_digest)
    with pytest.raises(RuntimeError, match="collector"):
        gate.consume(s.binding, proof)
    assert gate.inspect(request["request_id"])["state"] == "consumed"
    with pytest.raises(ApprovalError):
        s.gate.consume(s.binding, proof)


def test_missing_audit_prevents_pending_request(setup):
    s = setup
    def unavailable(*args):
        raise RuntimeError("audit unavailable")
    gate = ApprovalGate(s.config, audit=unavailable, policy_digest=s.gate.policy_digest)
    with pytest.raises(RuntimeError):
        gate.request(s.binding)
    with gate._connect() as db:
        assert db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0


def test_clock_rollback_stops_approval(setup, monkeypatch):
    s = setup
    request = s.gate.request(s.binding)
    monkeypatch.setattr("bulldog.approval.time.time", lambda: request["issued_at"] - 1)
    with pytest.raises(ApprovalError, match="clock"):
        s.gate.consume(s.binding, proof_for(s, request))


def test_private_state_permissions_required(setup):
    s = setup
    Path(s.config["state_directory"]).chmod(0o755)
    with pytest.raises(ApprovalError, match="0700"):
        ApprovalGate(s.config, audit=s.ledger.append_event, policy_digest="fixture")


def dispatcher_fixture(s):
    # Controlled host fixture: production dispatcher methods + real policy engine,
    # real approval DB and real verifier. No claim of live namespace certification.
    signed = sign_policy_bundle(allowed_capabilities=[Capability.NETWORK_OUTBOUND, Capability.CREDENTIAL_READ],
                                key="fixture-key", human_approval=s.config)
    policy_path = s.root / "policy.json"
    policy_path.write_text(json.dumps(signed))
    gate = ApprovalGate(s.config, audit=s.ledger.append_event, policy_digest=digest(canonical_bytes(signed)))
    calls = []
    dispatcher = object.__new__(ProductionDispatcher)
    dispatcher.production_mode = True
    dispatcher.domain_registry = None
    dispatcher.broker_engine = BulldogEngine(ledger=s.ledger, policy=DeterministicPolicy(
        global_capability_ceiling=frozenset({Capability.NETWORK_OUTBOUND, Capability.CREDENTIAL_READ})))
    dispatcher.runtime = SimpleNamespace(verify_trusted_state=lambda: None,
        approval_gate=lambda: (gate, signed), _approval_session_id="session-1",
        _policy_bundle_path=policy_path, _policy_key="fixture-key")
    dispatcher.egress_broker = SimpleNamespace(fetch=lambda **kw: calls.append(kw) or "fixture response")
    def request(url):
        return DispatchRequest(proposal={"operation": "fetch", "resource": url},
            trusted=TrustedExecutionContext("agent", (Provenance.HUMAN,), "ctx"),
            granted_capabilities=frozenset({Capability.NETWORK_OUTBOUND}))
    return dispatcher, request, calls, gate


def test_dispatcher_protected_effect_waits_then_executes_once(setup):
    s = setup
    dispatcher, request, calls, gate = dispatcher_fixture(s)
    url = "https://example.com/result"
    with pytest.raises(ApprovalRequired) as pending:
        dispatcher.fetch_egress(url=url, request=request(url))
    assert calls == []
    proof = proof_for(s, pending.value.request)
    assert dispatcher.fetch_egress(url=url, request=request(url), approval=proof) == "fixture response"
    assert calls == [{"method": "GET", "url": url}]
    with pytest.raises(ApprovalError):
        dispatcher.fetch_egress(url=url, request=request(url), approval=proof)
    assert len(calls) == 1
    assert gate.inspect(proof.request_id)["outcome"] == "completed"


def test_dispatcher_hard_deny_precedes_approval(setup):
    dispatcher, request, calls, gate = dispatcher_fixture(setup)
    url = "https://example.com/result"
    denied = replace(request(url), granted_capabilities=frozenset())
    with pytest.raises(DispatchDenied):
        dispatcher.fetch_egress(url=url, request=denied)
    assert calls == []
    with gate._connect() as db:
        assert db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0


def test_exact_routine_url_continues_without_approval(setup):
    dispatcher, request, calls, gate = dispatcher_fixture(setup)
    url = "https://example.com/manual"
    assert dispatcher.fetch_egress(url=url, request=request(url)) == "fixture response"
    assert len(calls) == 1
    with gate._connect() as db:
        assert db.execute("SELECT count(*) FROM requests").fetchone()[0] == 0


def test_effect_error_cannot_be_retried_with_same_approval(setup):
    s = setup
    dispatcher, request, calls, gate = dispatcher_fixture(s)
    url = "https://example.com/result"
    with pytest.raises(ApprovalRequired) as pending:
        dispatcher.fetch_egress(url=url, request=request(url))
    proof = proof_for(s, pending.value.request)
    def failed(**kwargs):
        calls.append(kwargs)
        raise RuntimeError("outcome unknown")
    dispatcher.egress_broker.fetch = failed
    with pytest.raises(RuntimeError):
        dispatcher.fetch_egress(url=url, request=request(url), approval=proof)
    with pytest.raises(ApprovalError):
        dispatcher.fetch_egress(url=url, request=request(url), approval=proof)
    assert len(calls) == 1
    assert gate.inspect(proof.request_id)["outcome"] == "uncertain"


def test_policy_signature_covers_approval_config(setup):
    s = setup
    path = s.root / "policy.json"
    policy = sign_policy_bundle(allowed_capabilities=[Capability.PROCESS_EXEC], key="fixture", human_approval=s.config)
    policy["human_approval"]["ttl_seconds"] = 600
    path.write_text(json.dumps(policy))
    with pytest.raises(Exception, match="signature mismatch"):
        load_policy_bundle(path, "fixture")


def test_secret_callback_waits_for_matching_credential(setup, monkeypatch):
    s = setup
    dispatcher, _, calls, gate = dispatcher_fixture(s)
    dispatcher.secret_broker = SimpleNamespace(socket_path=s.root / "unused-secret.sock")
    request = DispatchRequest(proposal={"operation": "secret.get", "resource": "fixture-token"},
        trusted=TrustedExecutionContext("agent", (Provenance.HUMAN,), "ctx"),
        granted_capabilities=frozenset({Capability.CREDENTIAL_READ}))
    monkeypatch.setattr("bulldog.dispatcher.request_secret", lambda **kw: calls.append(kw["name"]) or "DUMMY")
    with pytest.raises(ApprovalRequired) as pending:
        dispatcher.get_secret(token="synthetic-grant", name="fixture-token", request=request)
    assert calls == []
    proof = proof_for(s, pending.value.request)
    value = dispatcher.get_secret(token="synthetic-grant", name="fixture-token", request=request, approval=proof)
    assert value == "DUMMY" and calls == ["fixture-token"]
    assert "DUMMY" not in s.ledger.path.read_text()


def test_policy_change_after_consumption_blocks_effect(setup, monkeypatch):
    s = setup
    dispatcher, request, calls, gate = dispatcher_fixture(s)
    url = "https://example.com/result"
    with pytest.raises(ApprovalRequired) as pending:
        dispatcher.fetch_egress(url=url, request=request(url))
    proof = proof_for(s, pending.value.request)
    original = gate.consume
    def changed(binding, supplied):
        result = original(binding, supplied)
        bundle = sign_policy_bundle(allowed_capabilities=[Capability.PROCESS_EXEC], key="fixture-key", human_approval=s.config)
        dispatcher.runtime._policy_bundle_path.write_text(json.dumps(bundle))
        return result
    monkeypatch.setattr(gate, "consume", changed)
    with pytest.raises(DispatchDenied, match="policy changed"):
        dispatcher.fetch_egress(url=url, request=request(url), approval=proof)
    assert calls == []
    assert gate.inspect(proof.request_id)["state"] == "consumed"


def test_ordinary_keystroke_cannot_be_a_proof(setup):
    with pytest.raises(ApprovalError, match="text"):
        setup.gate.consume(setup.binding, "APPROVE")


def test_production_missing_approval_config_blocks(setup):
    from bulldog.profiles import ProductionRuntime
    s = setup
    path = s.root / "policy-without-approval.json"
    path.write_text(json.dumps(sign_policy_bundle(allowed_capabilities=[Capability.PROCESS_EXEC], key="fixture")))
    runtime = object.__new__(ProductionRuntime)
    runtime.verify_trusted_state = lambda: None
    runtime._policy_bundle_path = path
    runtime._policy_key = "fixture"
    with pytest.raises(ApprovalError, match="configuration missing"):
        runtime.approval_gate()

"""Operational boundary tests. Native NVIDIA gateway coverage is a separate run."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import threading
import time

import grpc
import pytest

from bulldog.audit import AuditIntegrityError, AuditLedger
from bulldog.models import Capability
from bulldog.openshell.authority import OpenShellAuthority
from bulldog.openshell.boundary import BoundaryDenied, DecisionGate
from bulldog.openshell.grants import GrantError, validate_grants
from bulldog.openshell.ocsf import correlate_exact
from bulldog.openshell.services import BullMiddleware, BullInterceptor
from bulldog.openshell._proto import supervisor_middleware_pb2 as mw
from bulldog.openshell._proto import gateway_interceptor_pb2 as gi

GRANTS = {"format": "bull-openshell-grants-v1", "host_ceiling": ["api.internal"],
          "sandboxes": {"parent": {"capabilities": ["network.post", "network.outbound"],
                                   "trusted_sources": ["api.internal"]},
                        "child": {"parent": "parent", "capabilities": ["network.post"],
                                  "trusted_sources": []},
                        "grandchild": {"parent": "child", "capabilities": ["network.post"],
                                       "trusted_sources": []}}}
CEILING = frozenset({Capability.NETWORK_POST, Capability.NETWORK_OUTBOUND})


def request(rid="1", sandbox="parent", body=b"identical"):
    return mw.HttpRequestEvaluation(
        context=mw.RequestContext(sandbox=sandbox, sandbox_id="sb-"+sandbox, request_id=rid),
        target=mw.HttpRequestTarget(method="POST", scheme="http", host="api.internal",
                                    port=80, path="/records"), body=body,
        headers=[mw.HttpHeader(name="x-bull-request-id", value="forged")])


@pytest.fixture
def authority(tmp_path):
    return OpenShellAuthority(GRANTS, CEILING, ledger=AuditLedger(tmp_path / "audit"),
                              state_path=tmp_path / "state")


@pytest.mark.parametrize("delay", [10, 50, 100, 250, 1000, 5000])
def test_delay_has_bounded_fail_closed_result(authority, monkeypatch, delay):
    original = authority.policy.evaluate
    def slow(action):
        time.sleep(delay / 1000)
        return original(action)
    monkeypatch.setattr(authority.policy, "evaluate", slow)
    service = BullMiddleware(authority, timeout=0.2, capacity=1)
    started = time.monotonic()
    result = service.EvaluateHttpRequest(request(), None)
    elapsed = time.monotonic() - started
    if delay < 200:
        assert result.decision == mw.DECISION_ALLOW
    else:
        assert result.decision == mw.DECISION_DENY
        assert result.reason_code == "bull_timeout"
    assert elapsed < 0.6
    service.gate.close()


def test_late_allow_never_resurrects_and_hung_worker_backpressures():
    gate = DecisionGate(timeout=.04, capacity=1)
    release = threading.Event()
    def late(budget):
        release.wait(1)
        return "ALLOW"  # deliberately ignores cancellation
    try:
        with pytest.raises(BoundaryDenied, match="bull_timeout"):
            gate.call(late)
        with pytest.raises(BoundaryDenied, match="bull_backpressure"):
            gate.call(late)
    finally:
        release.set()
        gate.close()


def test_duplicate_rejected_even_after_restart(authority):
    service = BullMiddleware(authority)
    assert service.EvaluateHttpRequest(request(), None).decision == mw.DECISION_ALLOW
    assert service.EvaluateHttpRequest(request(), None).reason_code == "bull_replayed_request"
    restarted = OpenShellAuthority(GRANTS, CEILING, ledger=authority.ledger,
                                   state_path=authority.state_path)
    other = BullMiddleware(restarted)
    assert other.EvaluateHttpRequest(request(), None).reason_code == "bull_replayed_request"
    service.gate.close(); other.gate.close()


def test_identity_is_generated_and_bound_to_body(authority):
    service = BullMiddleware(authority)
    one = service.EvaluateHttpRequest(request("1"), None)
    two = service.EvaluateHttpRequest(request("2", body=b"changed"), None)
    assert one.metadata["bull_request_id"] != "forged"
    assert one.metadata["bull_action_digest"] != two.metadata["bull_action_digest"]
    assert len(one.metadata["bull_request_id"]) == 32
    writes = {m.write.name: m.write.value for m in one.header_mutations if m.HasField("write")}
    assert writes["X-BULL-Request-ID"] == one.metadata["bull_request_id"]
    assert sum(m.HasField("remove") for m in one.header_mutations) == 3
    service.gate.close()


def test_missing_identity_and_service_exception_fail_closed(authority, monkeypatch):
    service = BullMiddleware(authority)
    assert service.EvaluateHttpRequest(request(""), None).reason_code == "bull_identity_missing"
    monkeypatch.setattr(authority, "evaluate_request", lambda **kw: (_ for _ in ()).throw(OSError()))
    assert service.EvaluateHttpRequest(request("2"), None).reason_code == "bull_unavailable"
    service.gate.close()


def test_client_cancellation_and_shorter_deadline():
    class Context:
        def is_active(self): return False
        def time_remaining(self): return 1
    gate = DecisionGate()
    with pytest.raises(BoundaryDenied, match="bull_cancelled"):
        gate.call(lambda budget: "ALLOW", Context())
    gate.close()


def test_control_plane_timeout_refuses_admission(authority, monkeypatch):
    def slow(operation):
        time.sleep(.1)
        return None
    monkeypatch.setattr(authority, "validate_create", slow)
    service = BullInterceptor(authority, timeout=.02)
    out = service.Evaluate(gi.InterceptorEvaluation(method="CreateSandbox",
                                                    validate=gi.ValidateEvaluation()), None)
    assert not out.allowed and out.log_annotations["bull_code"] == "bull_timeout"
    service.gate.close()


def test_parent_revoke_blocks_child_grandchild_and_survives_restart(authority):
    service = BullMiddleware(authority)
    for name in ("parent", "child", "grandchild"):
        assert service.EvaluateHttpRequest(request("before", name), None).decision == mw.DECISION_ALLOW
    assert set(authority.revoke("parent", ["network.post"])) == {"parent", "child", "grandchild"}
    for name in ("parent", "child", "grandchild"):
        assert service.EvaluateHttpRequest(request("after", name), None).decision == mw.DECISION_DENY
    restarted = OpenShellAuthority(GRANTS, CEILING, state_path=authority.state_path)
    other = BullMiddleware(restarted)
    assert other.EvaluateHttpRequest(request("restart", "grandchild"), None).decision == mw.DECISION_DENY
    assert restarted._grant("parent")["capabilities"] == ["network.outbound"]
    service.gate.close(); other.gate.close()


def test_revocation_during_evaluation_prevents_late_allow(authority, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = authority.policy.evaluate
    def paused(action):
        entered.set(); release.wait(1)
        return original(action)
    monkeypatch.setattr(authority.policy, "evaluate", paused)
    service = BullMiddleware(authority, timeout=2)
    with ThreadPoolExecutor(1) as pool:
        pending = pool.submit(service.EvaluateHttpRequest, request(), None)
        assert entered.wait(1)
        authority.revoke("parent", ["network.post"])
        release.set()
        assert pending.result().reason_code == "bull_authority_revoked"
    service.gate.close()


def test_emergency_revoke_requires_real_hook_and_invokes_every_descendant(authority):
    with pytest.raises(ValueError, match="trusted host"):
        authority.revoke("parent", ["network.post"], mode="REVOKE_TERMINATE")
    called = []
    authority.revoke("parent", ["network.post"], mode="REVOKE_TERMINATE", terminate=called.append)
    assert set(called) == {"parent", "child", "grandchild"}
    assert authority._grant("parent")["capabilities"] == []


def test_delegation_cycles_and_widening_refused():
    bad = json.loads(json.dumps(GRANTS)); bad["sandboxes"]["parent"]["parent"] = "grandchild"
    with pytest.raises(GrantError): validate_grants(bad)
    bad = json.loads(json.dumps(GRANTS)); bad["sandboxes"]["grandchild"]["capabilities"].append("credential.read")
    with pytest.raises(GrantError): validate_grants(bad)


def test_steady_append_only_verifies_once_and_restart_verifies_history(tmp_path):
    ledger = AuditLedger(tmp_path / "audit", anchor_path=tmp_path / "anchor", anchor_key=b"k"*32)
    for i in range(200): ledger.append_event("test", {"i": i})
    assert ledger.full_verifications == 1
    reopened = AuditLedger(ledger.path, anchor_path=ledger.anchor_path, anchor_key=b"k"*32)
    reopened.append_event("restart", {})
    assert reopened.full_verifications == 1 and reopened.verify().records == 201


@pytest.mark.parametrize("fault", ["modify", "delete", "reorder", "forge", "truncate", "same_size_mtime"])
def test_fast_append_detects_external_history_mutation(tmp_path, fault):
    ledger = AuditLedger(tmp_path / "audit")
    for i in range(4): ledger.append_event("test", {"i": i})
    st = ledger.path.stat(); lines = ledger.path.read_text().splitlines()
    if fault in {"modify", "same_size_mtime"}: lines[1] = lines[1].replace('"i": 1', '"i": 9')
    if fault == "delete": del lines[1]
    if fault == "reorder": lines[1], lines[2] = lines[2], lines[1]
    if fault == "forge": lines[1] = lines[1].replace('"previous_hash": "', '"previous_hash": "f')
    if fault == "truncate": lines.pop()
    ledger.path.write_text("\n".join(lines)+"\n")
    if fault == "same_size_mtime": os.utime(ledger.path, ns=(st.st_atime_ns, st.st_mtime_ns))
    with pytest.raises(AuditIntegrityError): ledger.append_event("must_deny", {})


def test_rollback_of_ledger_and_head_detected_by_retained_anchor(tmp_path):
    ledger = AuditLedger(tmp_path / "audit", anchor_path=tmp_path / "retained-anchor", anchor_key=b"k"*32)
    ledger.append_event("one", {})
    old_ledger, old_head = ledger.path.read_bytes(), ledger.head_path.read_bytes()
    ledger.append_event("two", {})
    ledger.path.write_bytes(old_ledger); ledger.head_path.write_bytes(old_head)
    with pytest.raises(AuditIntegrityError, match="anchor"):
        ledger.append_event("rollback", {})


def test_two_writer_instances_and_threads_preserve_sequence(tmp_path):
    one, two = AuditLedger(tmp_path / "audit"), AuditLedger(tmp_path / "audit")
    with ThreadPoolExecutor(8) as pool:
        list(pool.map(lambda i: (one if i % 2 else two).append_event("test", {"i": i}), range(200)))
    assert one.verify().valid and one.verify().records == 200


def exact_fixture():
    identity = {"request_id": "r", "decision_id": "d", "action_digest": "hash", "sandbox_id": "s"}
    ledger = [{"event_type": "openshell_egress", "data": dict(identity, allowed=True)}]
    events = [dict(identity, engine=layer, action="ALLOWED") for layer in ("l7", "middleware")]
    return ledger, events, [identity.copy()]


def test_exact_join_never_falls_back_to_time_or_accepts_duplicates():
    ledger, events, receipts = exact_fixture()
    assert correlate_exact(ledger, events, receipts)["summary"]["exact"]
    receipts[0]["action_digest"] = "swapped"
    assert not correlate_exact(ledger, events, receipts)["summary"]["exact"]
    ledger, events, receipts = exact_fixture(); events.append(events[0].copy())
    assert correlate_exact(ledger, events, receipts)["summary"]["duplicate_identities"] == 1
    ledger, events, receipts = exact_fixture(); receipts[0].pop("request_id")
    assert correlate_exact(ledger, events, receipts)["summary"]["missing_identity"] == 1


@pytest.mark.parametrize("fault", ["truncate", "same_size", "replace"])
def test_concurrent_change_during_checkpoint_never_becomes_trusted_cache(tmp_path, monkeypatch, fault):
    ledger = AuditLedger(tmp_path / "audit")
    ledger.append_event("one", {})
    original = ledger._write_atomic_head
    def changed(record_hash):
        original(record_hash)
        if fault == "truncate":
            lines = ledger.path.read_text().splitlines()
            ledger.path.write_text(lines[-1] + "\n")
        elif fault == "same_size":
            ledger.path.write_text(ledger.path.read_text().replace('"one"', '"bad"'))
        else:
            replacement = tmp_path / "replacement"
            replacement.write_bytes(ledger.path.read_bytes())
            replacement.replace(ledger.path)
    monkeypatch.setattr(ledger, "_write_atomic_head", changed)
    with pytest.raises(AuditIntegrityError, match="changed while committing"):
        ledger.append_event("two", {})
    assert ledger._validated_head is None
    if fault != "replace":
        with pytest.raises(AuditIntegrityError): ledger.append_event("three", {})

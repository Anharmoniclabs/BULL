"""Tests execute the new module directly; no production backend is substituted."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import threading

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bull_lifecycle_test_core", ROOT / "experiments/lifecycle_governance/core.py")
core = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = core
spec.loader.exec_module(core)
G, E, R, Q = core.LifecycleGovernor, core.Effect, core.ResourceClass, core.EffectRequest


@pytest.fixture
def lab(tmp_path):
    host, key, now, calls = object(), secrets.token_bytes(32), [1000], []
    g = G(tmp_path / "state.db", key, host_key=host, clock=lambda: now[0])
    def callback(reference, params):
        calls.append((reference, params))
        return "fixture output"
    g.register_adapter(E.READ, {}, {R.PROJECT, R.PROTECTED_STATE, R.DURABLE}, callback, host_key=host)
    g.register_adapter(E.WRITE, {"text": str}, {R.PROJECT, R.DURABLE}, callback, host_key=host)
    g.register_adapter(E.REPLICATE, {"destination": str}, {R.PROTECTED_STATE}, callback, host_key=host)
    g.register_adapter(E.PERSIST, {"text": str}, {R.DURABLE}, callback, host_key=host)
    g.register_adapter(E.EXECUTE, {"argv": list}, {R.PROJECT}, callback, host_key=host)
    g.register_adapter(E.MESSAGE, {"body": str, "identity": str, "purpose": str}, {R.MESSAGE_DESTINATION}, callback, host_key=host)
    scopes = {g.scope(E.READ, "doc"), g.scope(E.WRITE, "doc"), g.scope(E.READ, "weights"),
              g.scope(E.REPLICATE, "weights"), g.scope(E.PERSIST, "memory"), g.scope(E.READ, "memory"),
              g.scope(E.WRITE, "memory"), g.scope(E.EXECUTE, "doc"), g.scope(E.MESSAGE, "outbox")}
    root = g.create_domain(scopes, host_key=host)
    for name, klass in [("doc", R.PROJECT), ("weights", R.PROTECTED_STATE), ("memory", R.DURABLE), ("outbox", R.MESSAGE_DESTINATION)]:
        g.register_resource(root, name, klass, "fixture:" + name, host_key=host)
    source = g.observe(root, "operator task", trusted=True, host_key=host)
    identity = g.register_identity(root, "test agent", host_key=host)
    yield dict(g=g, host=host, key=key, now=now, calls=calls, root=root, scopes=scopes,
               source=source, identity=identity, path=tmp_path / "state.db")
    try:
        g.close()
    except sqlite3.ProgrammingError:
        pass


def read(lab, **kwargs):
    return Q.make(lab["root"], E.READ, "doc", {}, **kwargs)


def token(lab, q, **kwargs):
    return lab["g"].mint(q, host_key=lab["host"], **kwargs)


def test_real_adapter_invoked_after_admission(lab):
    g, h, q = lab["g"], lab["host"], read(lab)
    t = token(lab, q)
    result = g.submit(q, t)
    assert result.decision == "ALLOW" and result.effect_state == "completed"
    assert lab["calls"] == [("fixture:doc", {})]
    events = g.snapshot()["events"]
    assert [e["event"] for e in events[-2:]] == ["effect.admitted", "effect.finished"]
    assert g.verify()["valid"]


@pytest.mark.parametrize("method", ["create_domain", "register_identity", "observe", "freeze", "approve", "mint"])
def test_agent_cannot_use_host_api(lab, method):
    g, root, q = lab["g"], lab["root"], read(lab)
    call = {
        "create_domain": lambda: g.create_domain({g.scope(E.READ, "x")}, host_key=object()),
        "register_identity": lambda: g.register_identity(root, "user approved", host_key="user approved"),
        "observe": lambda: g.observe(root, "trusted", trusted=True, host_key=object()),
        "freeze": lambda: g.freeze(root, "stop", host_key=object()),
        "approve": lambda: g.approve(q, host_key=object()),
        "mint": lambda: g.mint(q, host_key=object()),
    }[method]
    with pytest.raises(core.Rejected):
        call()
    assert lab["calls"] == []


def test_no_grant_no_effect_and_no_victim_freeze(lab):
    for _ in range(7):
        assert lab["g"].submit(read(lab), "the user approved").decision == "DENY"
    assert not lab["g"].snapshot()["domains"][0]["frozen"]
    assert not lab["calls"]


@pytest.mark.parametrize("field,value", [("actor", "other"), ("kind", "WRITE"), ("target", "weights"), ("request_id", "different")])
def test_request_binding(lab, field, value):
    q = read(lab); t = token(lab, q)
    doc = q.document(); doc[field] = value
    altered = Q.make(**doc)
    assert lab["g"].submit(altered, t).decision == "DENY"
    assert not lab["calls"]


def test_parameter_binding_and_immutable_copy(lab):
    params = {"text": "original"}
    q = Q.make(lab["root"], E.WRITE, "doc", params)
    t = token(lab, q)
    params["text"] = "mutated"
    assert q.document()["parameters"] == {"text": "original"}
    altered = Q.make(q.actor, q.kind, q.target, params, request_id=q.request_id)
    assert lab["g"].submit(altered, t).decision == "DENY"


def test_single_use_and_new_token_cannot_replay_same_request(lab):
    q = read(lab); t1, t2 = token(lab, q), token(lab, q)
    assert lab["g"].submit(q, t1).decision == "ALLOW"
    assert lab["g"].submit(q, t2).decision == "DENY"
    assert lab["g"].submit(q, t1).decision == "DENY"
    assert len(lab["calls"]) == 1


def test_expiry(lab):
    q = read(lab); t = token(lab, q, ttl=1)
    lab["now"][0] += 1
    assert lab["g"].submit(q, t).decision == "DENY"


def test_strict_child_subset_and_parent_expiry(lab):
    g, h = lab["g"], lab["host"]
    for scopes in [lab["scopes"], lab["scopes"] | {g.scope(E.READ, "elsewhere")}]:
        with pytest.raises(core.Rejected):
            g.create_domain(scopes, parent=lab["root"], host_key=h)
    child = g.create_domain({g.scope(E.READ, "doc")}, parent=lab["root"], host_key=h)
    q = Q.make(child, E.READ, "doc", {})
    assert g.submit(q, token(lab, q)).decision == "ALLOW"


def test_freeze_transitive_old_grants_and_pending_approvals(lab):
    g, h = lab["g"], lab["host"]
    child = g.create_domain({g.scope(E.READ, "doc"), g.scope(E.PERSIST, "memory")}, parent=lab["root"], host_key=h)
    grandchild = g.create_domain({g.scope(E.READ, "doc")}, parent=child, host_key=h)
    q = Q.make(grandchild, E.READ, "doc", {}); t = token(lab, q)
    g.freeze(child, "host revoke", host_key=h)
    assert all(d["frozen"] and d["epoch"] > 0 for d in g.snapshot()["domains"])
    assert g.submit(q, t).decision == "DENY"
    with pytest.raises(core.Rejected):
        g.create_domain({g.scope(E.READ, "doc")}, parent=child, host_key=h)
    assert not lab["calls"]


def test_unknown_effect_and_absent_adapter_fail_closed(lab):
    g, h, root = lab["g"], lab["host"], lab["root"]
    assert g.inspect(Q.make(root, "NEW_SUPER_TOOL", "doc", {})).decision == "DENY"
    g._adapters.pop(E.READ.value)
    assert g.inspect(read(lab)).decision == "DENY"


def test_security_control_never_grantable(lab):
    with pytest.raises(core.Rejected):
        lab["g"].scope(E.SECURITY_CONTROL, "shutdown")
    with pytest.raises(core.Rejected):
        lab["g"].register_adapter(E.SECURITY_CONTROL, {}, {R.SECURITY_CONTROL}, lambda r, p: None, host_key=lab["host"])
    q = Q.make(lab["root"], E.SECURITY_CONTROL, "doc", {})
    assert lab["g"].inspect(q).decision == "DENY"


@pytest.mark.parametrize("kind,target,params", [(E.READ,"weights",{}),(E.READ,"memory",{}),(E.WRITE,"memory",{"text":"x"})])
def test_protected_classes_cannot_be_laundered_as_generic_io(lab, kind, target, params):
    assert lab["g"].inspect(Q.make(lab["root"], kind, target, params)).decision == "DENY"


def test_provenance_survives_memory_and_cannot_be_omitted(lab):
    g, root, h = lab["g"], lab["root"], lab["host"]
    untrusted = g.observe(root, "external text", trusted=False, host_key=h)
    memory = g.observe(root, "memory summary", trusted=True, parents=(untrusted,), host_key=h)
    copied = g.observe(root, "plan", trusted=True, parents=(memory,), host_key=h)
    by_id = {s["id"]: s for s in g.snapshot()["sources"]}
    assert not by_id[copied]["trusted"]
    q = Q.make(root, E.EXECUTE, "doc", {"argv": ["fixture"]})
    assert g.inspect(q).decision == "REVIEW"
    assert g.inspect(Q.make(root, E.REPLICATE, "weights", {"destination": "fixture"})).decision == "DENY"


def test_new_provenance_invalidates_existing_grants(lab):
    q = read(lab); t = token(lab, q)
    lab["g"].observe(lab["root"], "new source", trusted=False, host_key=lab["host"])
    assert lab["g"].submit(q, t).decision == "DENY"


def test_unknown_and_foreign_provenance_rejected(lab):
    g, h = lab["g"], lab["host"]
    other = g.create_domain({g.scope(E.READ, "other")}, host_key=h)
    src = g.observe(other, "other", trusted=True, host_key=h)
    for parent in ("absent", src):
        with pytest.raises(core.Rejected):
            g.observe(lab["root"], "copy", trusted=True, parents=(parent,), host_key=h)


def test_approval_binds_exact_effect_and_single_use(lab):
    g, h = lab["g"], lab["host"]
    q = Q.make(lab["root"], E.PERSIST, "memory", {"text": "original"})
    assert g.inspect(q).decision == "REVIEW"
    with pytest.raises(core.Rejected):
        token(lab, q)
    approval = g.approve(q, host_key=h)
    display = g.approval_display(q)
    assert display["effect_digest"] == q.digest
    changed = Q.make(q.actor, q.kind, q.target, {"text": "other"}, request_id=q.request_id)
    with pytest.raises(core.Rejected):
        token(lab, changed, approval=approval)
    t = token(lab, q, approval=approval)
    assert g.submit(q, t).decision == "ALLOW"
    with pytest.raises(core.Rejected):
        token(lab, q, approval=approval)


def test_expired_approval_denies_even_if_grant_not_expired(lab):
    g, q = lab["g"], Q.make(lab["root"], E.PERSIST, "memory", {"text": "x"})
    a = g.approve(q, host_key=lab["host"], ttl=1)
    t = token(lab, q, approval=a, ttl=60)
    lab["now"][0] += 2
    assert g.submit(q, t).decision == "DENY"


def test_identity_cannot_be_borrowed_from_another_root(lab):
    g, h = lab["g"], lab["host"]
    other = g.create_domain({g.scope(E.MESSAGE, "other")}, host_key=h)
    identity = g.register_identity(other, "alias", host_key=h)
    q = Q.make(lab["root"], E.MESSAGE, "outbox", {"body": "text", "identity": identity, "purpose": "notify"})
    assert g.inspect(q).decision == "DENY"


def test_communication_budget_cannot_be_split_across_identities(lab):
    g, h = lab["g"], lab["host"]
    for i in range(10):
        identity = g.register_identity(lab["root"], f"alias{i}", host_key=h)
        q = Q.make(lab["root"], E.MESSAGE, "outbox", {"body": "fixture", "identity": identity, "purpose": "notify"})
        a = g.approve(q, host_key=h)
        assert g.submit(q, token(lab, q, approval=a)).decision == "ALLOW"
    q = Q.make(lab["root"], E.MESSAGE, "outbox", {"body": "fixture", "identity": lab["identity"], "purpose": "notify"})
    assert g.inspect(q).decision == "DENY"
    assert len(lab["calls"]) == 10


def test_sentinel_freezes_only_authenticated_lineage(lab):
    q = read(lab); t = token(lab, q)
    mismatch = Q.make(q.actor, E.READ, q.target, {}, request_id="different")
    for _ in range(5):
        result = lab["g"].submit(mismatch, t)
    assert result.decision == "FREEZE"
    assert lab["g"].snapshot()["domains"][0]["frozen"]


def test_cleanup_failures_stay_visible_and_authority_stays_revoked(lab):
    g, h = lab["g"], lab["host"]
    g._revokers["memory"] = lambda ref: True
    g._revokers["weights"] = lambda ref: False
    result = g.freeze(lab["root"], "stop", host_key=h)
    assert result["resources"]["memory"] == "revoked"
    assert result["resources"]["weights"] == "pending_or_unsupported"
    assert all(d["frozen"] for d in g.snapshot()["domains"])


def test_shutdown_revokes_before_termination_and_cleanup(lab):
    g, h, order = lab["g"], lab["host"], []
    def terminate():
        assert g.snapshot()["domains"][0]["frozen"]
        order.append("terminated")
        return True
    def cleanup(ref):
        order.append("cleaned")
        return True
    g.register_terminator(lab["root"], terminate, host_key=h)
    g._revokers["memory"] = cleanup
    result = g.shutdown(lab["root"], host_key=h)
    assert result["termination"] == "confirmed" and order == ["terminated", "cleaned"]


def test_restart_retains_freeze_and_replay_state(lab):
    g, h, q = lab["g"], lab["host"], read(lab)
    t = token(lab, q)
    g.freeze(lab["root"], "persist revocation", host_key=h); g.close()
    reopened = G(lab["path"], lab["key"], host_key=h, clock=lambda: lab["now"][0])
    try:
        assert all(d["frozen"] for d in reopened.snapshot()["domains"])
        assert reopened.submit(q, t).decision == "DENY"
    finally:
        reopened.close()


def test_state_tamper_and_wrong_key_fail_closed(lab):
    g = lab["g"]
    with pytest.raises(core.IntegrityError):
        G(lab["path"], b"x" * 32, host_key=object())
    g._db.execute("UPDATE state SET body=?", (b'{}',))
    with pytest.raises(core.IntegrityError):
        g.submit(read(lab), "not a token")
    assert not lab["calls"]


def test_audit_failure_before_admission_prevents_effect(lab, monkeypatch):
    q = read(lab); t = token(lab, q)
    def fail(*args, **kwargs):
        raise core.IntegrityError("disk failed")
    monkeypatch.setattr(lab["g"], "_event", fail)
    with pytest.raises(core.IntegrityError):
        lab["g"].submit(q, t)
    assert not lab["calls"]


def test_completion_failure_is_not_reported_as_no_execution(lab, monkeypatch):
    g, q = lab["g"], read(lab); t = token(lab, q)
    original = g._event
    def fail_after(state, event, **kw):
        if event == "effect.finished":
            raise core.IntegrityError("completion failed")
        return original(state, event, **kw)
    monkeypatch.setattr(g, "_event", fail_after)
    result = g.submit(q, t)
    assert result.effect_state == "completed_audit_failed"
    assert len(lab["calls"]) == 1
    assert g.inspect(read(lab)).decision == "DENY"


def test_concurrent_token_use_at_most_once(lab):
    g, q = lab["g"], read(lab); t = token(lab, q)
    results = []
    threads = [threading.Thread(target=lambda: results.append(g.submit(q, t))) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(r.effect_state == "completed" for r in results) == 1
    assert len(lab["calls"]) == 1


def test_freeze_does_not_wait_for_already_admitted_adapter(lab):
    g, h, q = lab["g"], lab["host"], read(lab)
    entered, release = threading.Event(), threading.Event()
    def slow(ref, params):
        entered.set(); release.wait(3); return "done"
    g._adapters[E.READ.value] = core.Adapter({}, frozenset({R.PROJECT.value}), slow)
    t = token(lab, q)
    thread = threading.Thread(target=lambda: g.submit(q, t)); thread.start()
    assert entered.wait(2)
    g.freeze(lab["root"], "stop admitting", host_key=h)
    assert all(d["frozen"] for d in g.snapshot()["domains"])
    release.set(); thread.join()
    assert g.inspect(read(lab)).decision == "DENY"


def test_fleet_correlation_counts_roots_not_aliases(lab):
    g, h = lab["g"], lab["host"]
    for i in range(3):
        name = f"shared{i}"
        root = g.create_domain({g.scope(E.READ, name)}, host_key=h)
        g.register_resource(root, name, R.PROJECT, "shared:destination", host_key=h)
        g.observe(root, "source", trusted=True, host_key=h)
        for j in range(2):
            g.register_identity(root, f"alias{j}", host_key=h)
            q = Q.make(root, E.READ, name, {})
            assert g.submit(q, g.mint(q, host_key=h)).decision == "ALLOW"
    records = g.fleet_observations()
    assert len(records) == 1 and records[0]["independent_roots"] == 3
    assert records[0]["signal"] == "REVIEW" and not records[0]["authority_change"]


@pytest.mark.parametrize("params", [{"unexpected": True}, {"text": 1}, {"text": True}])
def test_schema_enforced_before_effect(lab, params):
    q = Q.make(lab["root"], E.WRITE, "doc", params)
    assert lab["g"].inspect(q).decision == "DENY"


@pytest.mark.parametrize("value", [float("nan"), 1.1, {1: "key"}, 2**54, {"x": "a" * 20000}])
def test_canonical_budget_and_numeric_validation(value):
    with pytest.raises(core.Rejected):
        core.canonical(value)


def test_wire_rejects_model_authority_claims_and_duplicate_keys():
    for wire in (b'{"actor":"a","actor":"b"}', b'{"approved":true}', b'[]'):
        with pytest.raises(core.Rejected):
            Q.from_wire(wire)


def test_wire_round_trip():
    q = Q.make("root", E.READ, "doc", {})
    assert Q.from_wire(core.canonical(q.document())).digest == q.digest


def test_restart_does_not_retry_uncertain_effect(lab, monkeypatch):
    g, q = lab["g"], read(lab); t = token(lab, q)
    original = g._event
    def fail_finish(state, event, **kw):
        if event == "effect.finished":
            raise core.IntegrityError("crash at completion")
        return original(state, event, **kw)
    monkeypatch.setattr(g, "_event", fail_finish)
    assert g.submit(q, t).effect_state == "completed_audit_failed"
    g.close()
    reopened = G(lab["path"], lab["key"], host_key=lab["host"], clock=lambda: lab["now"][0])
    try:
        assert reopened.snapshot()["supervisor_faulted"]
        assert reopened.inspect(read(lab)).decision == "DENY"
    finally:
        reopened.close()


def test_expired_parent_context_denies_descendant(lab):
    g, h = lab["g"], lab["host"]
    child = g.create_domain({g.scope(E.READ, "doc")}, parent=lab["root"], host_key=h)
    g.observe(lab["root"], "short lived intake", trusted=True, ttl=1, host_key=h)
    q = Q.make(child, E.READ, "doc", {}); t = token(lab, q)
    lab["now"][0] += 1
    assert g.submit(q, t).decision == "DENY"


def test_missing_terminator_never_reports_shutdown_complete(lab):
    result = lab["g"].shutdown(lab["root"], host_key=lab["host"])
    assert result["authority"] == "frozen"
    assert result["termination"] == "pending_or_unsupported"


def test_clock_rollback_does_not_revive_expired_grant(lab):
    q = read(lab); t = token(lab, q, ttl=1)
    lab["now"][0] += 2
    assert lab["g"].submit(q, t).decision == "DENY"
    lab["now"][0] -= 2
    with pytest.raises(core.IntegrityError):
        lab["g"].submit(q, t)
    assert not lab["calls"]


def test_request_id_is_namespaced_by_authenticated_actor(lab):
    g, h = lab["g"], lab["host"]
    first = read(lab, request_id="shared-request-id")
    assert g.submit(first, token(lab, first)).decision == "ALLOW"
    other = g.create_domain({g.scope(E.READ, "other-doc")}, host_key=h)
    g.register_resource(other, "other-doc", R.PROJECT, "other-reference", host_key=h)
    g.observe(other, "source", trusted=True, host_key=h)
    second = Q.make(other, E.READ, "other-doc", {}, request_id="shared-request-id")
    assert g.submit(second, g.mint(second, host_key=h)).decision == "ALLOW"

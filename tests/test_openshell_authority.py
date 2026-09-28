"""BULL's OpenShell adapter: decisions, provenance, approvals and gRPC contract.

The live qualification against a real OpenShell gateway is
tools/openshell_experiment.py; these tests run anywhere grpcio is installed.
"""

import json

import pytest

grpc = pytest.importorskip("grpc")

from bulldog.audit import AuditLedger
from bulldog.models import Capability
from bulldog.openshell.authority import OpenShellAuthority
from bulldog.openshell.grants import GrantError, host_matches, validate_grants

GRANTS = {
    "format": "bull-openshell-grants-v1",
    "host_ceiling": ["docs.internal", "api.internal", "*.example.com"],
    "sandboxes": {
        "coder": {"capabilities": ["network.outbound", "network.post"],
                  "trusted_sources": ["docs.internal"]},
        "reader": {"capabilities": ["network.outbound"], "trusted_sources": []},
        "keyed": {"capabilities": ["network.outbound", "credential.read"],
                  "trusted_sources": []},
    },
}
CEILING = frozenset({Capability.NETWORK_OUTBOUND, Capability.NETWORK_POST,
                     Capability.CREDENTIAL_READ})


@pytest.fixture
def authority(tmp_path):
    return OpenShellAuthority(GRANTS, CEILING, ledger=AuditLedger(tmp_path / "audit.jsonl"))


def ask(authority, sandbox="coder", method="GET", host="docs.internal", path="/x", body=b""):
    return authority.evaluate_request(
        sandbox=sandbox, sandbox_id="sb-1", request_id="r-1", method=method, scheme="http",
        host=host, port=80, path=path, query="", body=body, binary="/usr/bin/curl")


def test_trusted_read_then_post_is_allowed(authority):
    assert ask(authority).allowed
    verdict = ask(authority, method="POST", host="api.internal", body=b'{"a":1}')
    assert verdict.allowed and verdict.decision in ("ALLOW", "SANDBOX")


def test_capability_not_granted_is_denied(authority):
    verdict = ask(authority, sandbox="reader", method="POST", host="api.internal")
    assert not verdict.allowed and verdict.reason_code == "bull.denied"


def test_unknown_sandbox_gets_nothing(authority):
    assert not ask(authority, sandbox="stranger").allowed


def test_internet_content_taints_later_posts(authority):
    assert ask(authority, host="news.example.com").allowed  # untrusted read
    verdict = ask(authority, method="POST", host="api.internal", body=b"exfil")
    assert not verdict.allowed and verdict.reason_code == "bull.approval_required"
    assert verdict.decision == "ESCALATE" and verdict.approval_id


def test_approval_admits_exactly_one_identical_request(authority):
    ask(authority, host="news.example.com")
    first = ask(authority, method="POST", host="api.internal", body=b"payload")
    authority.approvals.approve(first.approval_id)
    changed = ask(authority, method="POST", host="api.internal", body=b"different")
    assert not changed.allowed  # the approval binds the exact body
    assert ask(authority, method="POST", host="api.internal", body=b"payload").allowed
    again = ask(authority, method="POST", host="api.internal", body=b"payload")
    assert not again.allowed  # single use


def test_every_decision_is_in_the_hash_chained_ledger(authority, tmp_path):
    ask(authority)
    ask(authority, sandbox="reader", method="POST", host="api.internal")
    assert authority.ledger.verify().valid
    records = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text().splitlines()]
    decisions = [r["data"]["allowed"] for r in records if r["event_type"] == "openshell_egress"]
    assert decisions == [True, False]


def op(name="coder", hosts=("docs.internal",)):
    return {"name": name, "spec": {"policy": {"networkPolicies": {
        "p": {"endpoints": [{"host": h, "port": 80} for h in hosts]}}}}}


def test_create_attaches_bull_middleware_to_every_host(authority):
    verdict, patches = authority.create_sandbox_patches(op(hosts=("docs.internal", "api.internal")))
    assert verdict.allowed
    attach = [p for p in patches if p["path"].endswith("/bull-governance")][0]["value"]
    assert attach["endpoints"]["include"] == ["api.internal", "docs.internal"]
    assert attach["onError"] == "fail_closed"


def test_create_outside_ceiling_is_refused(authority):
    verdict, patches = authority.create_sandbox_patches(op(hosts=("evil.test",)))
    assert not verdict.allowed and verdict.reason_code == "bull.outside_ceiling" and not patches


def test_create_validate_requires_full_mediation(authority):
    unmediated = op(hosts=("docs.internal",))
    assert not authority.validate_create(unmediated).allowed


def test_policy_widening_needs_approval_and_is_single_use(authority):
    authority.create_sandbox_patches(op())
    change = {"sandbox": "coder", "mergeOperations": [{"addRule": {"ruleName": "n", "rule": {
        "endpoints": [{"host": "api.internal", "port": 80}]}}}]}
    first = authority.validate_policy_change("UpdateConfig", change)
    assert not first.allowed and first.reason_code == "bull.approval_required"
    authority.approvals.approve(first.approval_id)
    assert authority.validate_policy_change("UpdateConfig", change).allowed
    # The approved host is now part of BULL's accepted set: no new authority.
    assert authority.validate_policy_change("UpdateConfig", change).reason_code == "bull.no_widening"


def test_widening_outside_ceiling_is_refused_outright(authority):
    authority.create_sandbox_patches(op())
    change = {"sandbox": "coder", "mergeOperations": [{"addRule": {"ruleName": "n", "rule": {
        "endpoints": [{"host": "attacker.test", "port": 443}]}}}]}
    assert authority.validate_policy_change("UpdateConfig", change).reason_code == "bull.outside_ceiling"


def test_replacement_policy_must_keep_bull(authority):
    authority.create_sandbox_patches(op())
    change = {"sandbox": "coder", "policy": op()["spec"]["policy"]}
    assert authority.validate_policy_change("UpdateConfig", change).reason_code == "bull.unmediated"


def test_global_policy_change_is_refused(authority):
    change = {"global": True, "policy": op()["spec"]["policy"]}
    assert not authority.validate_policy_change("UpdateConfig", change).allowed


def test_draft_approval_is_an_authority_increase(authority):
    verdict = authority.validate_policy_change("ApproveAllDraftChunks", {"name": "coder"})
    assert verdict.reason_code == "bull.approval_required"


def test_provider_attach_requires_credential_use_grant(authority):
    assert authority.validate_provider_attach(
        {"sandboxName": "coder", "providerName": "gh"}).reason_code == "bull.no_credential_use"
    assert authority.validate_provider_attach(
        {"sandboxName": "keyed", "providerName": "gh"}).reason_code == "bull.approval_required"


def test_grants_are_validated():
    with pytest.raises(GrantError):
        validate_grants({**GRANTS, "extra": 1})
    with pytest.raises(GrantError):
        validate_grants({**GRANTS, "sandboxes": {"x": {"capabilities": ["root.everything"]}}})
    assert host_matches("a.b.example.com", "*.example.com")
    assert not host_matches("example.com", "*.example.com")


def test_grpc_contract_round_trip(authority):
    """The real services over a real gRPC channel, as OpenShell calls them."""
    from bulldog.openshell._proto import gateway_interceptor_pb2 as gi
    from bulldog.openshell._proto import gateway_interceptor_pb2_grpc as gi_grpc
    from bulldog.openshell._proto import supervisor_middleware_pb2 as mw
    from bulldog.openshell._proto import supervisor_middleware_pb2_grpc as mw_grpc
    from google.protobuf import json_format, struct_pb2
    import grpc as _grpc
    from concurrent import futures
    from bulldog.openshell.services import BullInterceptor, BullMiddleware

    server = _grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    mw_grpc.add_SupervisorMiddlewareServicer_to_server(BullMiddleware(authority), server)
    gi_grpc.add_GatewayInterceptorServicer_to_server(BullInterceptor(authority), server)
    port = server.add_insecure_port("127.0.0.1:0")
    server.start()
    try:
        channel = _grpc.insecure_channel(f"127.0.0.1:{port}")
        middleware = mw_grpc.SupervisorMiddlewareStub(channel)
        manifest = middleware.Describe(mw.MiddlewareDescribeRequest())
        assert manifest.extension.protocol_version.major == 1
        assert manifest.bindings[0].phase == mw.SUPERVISOR_MIDDLEWARE_PHASE_PRE_CREDENTIALS
        result = middleware.EvaluateHttpRequest(mw.HttpRequestEvaluation(
            context=mw.RequestContext(sandbox="reader", sandbox_id="s", request_id="q"),
            target=mw.HttpRequestTarget(scheme="http", host="api.internal", port=80,
                                        method="POST", path="/v1"),
            body=b"x"))
        assert result.decision == mw.DECISION_DENY and result.reason_code == "bull.denied"
        interceptor = gi_grpc.GatewayInterceptorStub(channel)
        described = interceptor.Describe(gi.DescribeRequest())
        assert described.failure_policy == "fail_closed"
        assert {b.selector.rpc.split("/")[-1] for b in described.bindings} >= {
            "CreateSandbox", "UpdateConfig", "AttachSandboxProvider"}
        proposed = struct_pb2.Struct()
        json_format.ParseDict(op(hosts=("docs.internal",)), proposed)
        modified = interceptor.Evaluate(gi.InterceptorEvaluation(
            method="CreateSandbox",
            modify_operation=gi.ModifyOperationEvaluation(proposed_operation=proposed)))
        assert modified.allowed and any(p.path.endswith("bull-governance")
                                        for p in modified.patches)
    finally:
        server.stop(0)


def test_trusted_source_can_name_a_port(tmp_path):
    grants = {**GRANTS, "sandboxes": {"coder": {
        "capabilities": ["network.outbound", "network.post"],
        "trusted_sources": ["host.openshell.internal:8001"]}}}
    authority = OpenShellAuthority(grants, CEILING)

    def get(port):
        return authority.evaluate_request(
            sandbox="coder", sandbox_id="s", request_id="r", method="GET", scheme="http",
            host="host.openshell.internal", port=port, path="/", query="", body=b"", binary="")

    get(8001)
    assert authority.provenance("coder")[0].value == "local_trusted"
    get(8002)
    assert authority.provenance("coder")[0].value == "internet"


def test_restart_keeps_taint_and_approvals(tmp_path):
    state = tmp_path / "state.json"
    first = OpenShellAuthority(GRANTS, CEILING, state_path=state)
    ask(first, host="news.example.com")
    pending = ask(first, method="POST", host="api.internal", body=b"p")
    first.approvals.approve(pending.approval_id)
    restarted = OpenShellAuthority(GRANTS, CEILING, state_path=state)
    assert restarted.provenance("coder")[0].value == "internet"
    assert ask(restarted, method="POST", host="api.internal", body=b"p").allowed
    assert not ask(restarted, method="POST", host="api.internal", body=b"p").allowed


def test_new_port_on_an_allowed_host_is_widening(authority):
    authority.create_sandbox_patches(op(hosts=("docs.internal",)))
    change = {"sandbox": "coder", "mergeOperations": [{"addRule": {"ruleName": "n", "rule": {
        "endpoints": [{"host": "docs.internal", "port": 9}]}}}]}
    assert authority.validate_policy_change("UpdateConfig", change).reason_code == \
        "bull.approval_required"


def test_new_l7_rules_on_an_existing_endpoint_are_widening(authority):
    authority.create_sandbox_patches(op(hosts=("docs.internal",)))
    change = {"sandbox": "coder", "mergeOperations": [{"addAllowRules": {
        "host": "docs.internal", "port": 80, "rules": [{"allow": {"method": "DELETE"}}]}}]}
    assert authority.validate_policy_change("UpdateConfig", change).reason_code == \
        "bull.approval_required"


def test_replacement_policy_is_reattached_before_validation(authority):
    authority.create_sandbox_patches(op())
    replacement = {"sandbox": "coder", "policy": op()["spec"]["policy"]}
    patches = authority.update_config_patches(replacement)
    assert patches[-1]["path"] == "/policy/networkMiddlewares/bull-governance"

from pathlib import Path
import json
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import governed_agent as agent
from bulldog.session_guard import SessionGuard
from bulldog.audit import AuditLedger, AuditIntegrityError


@pytest.mark.parametrize('raw', ['{}', '[]', 'null', '{"tool":"shell"}',
    '{"tool":"inspect","argv":["anything"]}', '{"tool":"inspect","tool":"checksum"}',
    '{"tool":[]}', 'x' * 4097])
def test_untrusted_proposal_cannot_add_authority(raw):
    with pytest.raises((ValueError, TypeError)):
        agent.proposal(raw)


def test_complete_read_only_tool_surface():
    for name in agent.TOOLS:
        assert agent.proposal(json.dumps({'tool': name})) == name
        assert agent.TOOLS[name][:2] == ('/usr/bin/python3', '-I')


def event(name, data):
    return {'record_type': 'runtime_event', 'event_type': name, 'data': data}


def test_pending_read_recovers_without_advancing():
    rows = [event('agent_identity', {'id': 1}), event('agent_plan', {'step': 0, 'tool': 'inspect'})]
    pinned, plans, done = agent.recover(rows, {'id': 1}, SessionGuard())
    assert pinned and plans[0]['tool'] == 'inspect' and not done
    rows.append(event('agent_result', {'step': 0, 'tool': 'inspect'}))
    assert len(agent.recover(rows, {'id': 1}, SessionGuard())[2]) == 1


def test_identity_changes_refused():
    with pytest.raises(ValueError, match='identity changed'):
        agent.recover([event('agent_identity', {'id': 1})], {'id': 2}, SessionGuard())


@pytest.mark.parametrize('rows', [
    [event('agent_result', {'step': 0})],
    [event('agent_plan', {'step': 1, 'tool': 'inspect'})],
    [event('agent_plan', {'step': 0, 'tool': 'inspect'})] * 2,
    [event('agent_plan', {'step': 0, 'tool': 'inspect'}), event('agent_plan', {'step': 1, 'tool': 'checksum'})],
])
def test_ambiguous_history_refused(rows):
    with pytest.raises(ValueError):
        agent.recover(rows, {}, SessionGuard())


def test_security_history_survives_restart():
    row = dict(record_type='action_evaluation', actor='agent', task='test', operation='secret.get',
               resource='fixture', capability='credential.read', provenance=['local_trusted'],
               metadata={'security_context_id': 'stable'}, decision='DENY', risk=1, reasons=['no'], hard_block=True)
    guard = SessionGuard()
    agent.recover([row] * 40, {}, guard)
    history = guard.history['security-context:stable']
    assert len(history) == 32 and history[-1].evaluation.hard_block


def test_corrupt_audit_cannot_resume(tmp_path):
    ledger = AuditLedger(tmp_path / 'ledger')
    ledger.append_event('agent_identity', {'id': 1})
    assert len(agent.records(ledger)) == 1
    ledger.path.write_text(ledger.path.read_text().replace('"id":1', '"id":2').replace('"id": 1', '"id": 2'))
    with pytest.raises(AuditIntegrityError):
        agent.records(ledger)


def test_cloud_model_refused(monkeypatch):
    monkeypatch.setattr(agent, 'model_request', lambda _: {'models': [dict(name='remote', remote_model='cloud', capabilities=['completion'])]})
    with pytest.raises(ValueError, match='locally'):
        agent.local_model('remote')


def test_redirect_refused():
    with pytest.raises(ValueError, match='redirect'):
        agent.NoRedirect().redirect_request(None)


def test_uid_limit_remains_without_cgroup(monkeypatch):
    import bulldog.resource_limits as limits
    calls = []
    monkeypatch.setattr(limits, '_safe_limit', lambda key, value: calls.append((key, value)))
    limits.apply_resource_budget(limits.ResourceBudget())
    assert (limits.resource.RLIMIT_NPROC, 64) in calls
    calls.clear()
    limits.apply_resource_budget(limits.ResourceBudget(), enforce_uid_process_limit=False)
    assert all(key != limits.resource.RLIMIT_NPROC for key, _ in calls)
    assert (limits.resource.RLIMIT_AS, 512 * 1024 * 1024) in calls


def test_offline_verifier_rejects_unpinned_rewrite_and_false_completion(tmp_path):
    from tools.audit_governed_agent import inspect
    ledger = AuditLedger(tmp_path / 'ledger')
    ledger.append_event('agent_identity', {'id': 1})
    assert inspect(ledger.path)['status'] == 'INCOMPLETE'
    with pytest.raises(ValueError, match='head differs'):
        inspect(ledger.path, '0' * 64)
    ledger.append_event('agent_result', {'step': 0})
    with pytest.raises(ValueError, match='completion'):
        inspect(ledger.path)


def test_checkpoint_delivery_failure_blocks_then_explicit_reconcile(tmp_path):
    from bulldog.audit_transport import AnchorIdentity, HTTPSAnchorTransport
    from bulldog.anchor_service import AnchorError
    # Unit transport fixture; live soak uses authenticated external HTTPS.
    identity = AnchorIdentity('a' * 64, b'b' * 32)
    transport = HTTPSAnchorTransport('https://audit.example.invalid/v1/checkpoints', identity)
    ledger = AuditLedger(tmp_path / 'ledger', transport=transport)
    calls = []
    def unavailable(sequence, record):
        calls.append(sequence)
        raise AnchorError('fixture outage')
    transport.submit = unavailable
    with pytest.raises((AuditIntegrityError, AnchorError)):
        ledger.append_event('agent_identity', {'id': 1})
    assert not ledger.verify().valid
    with pytest.raises(AuditIntegrityError):
        ledger.append_event('should_not_execute', {})
    assert calls == [1]
    # Return the authenticated receipt using the transport's session key.
    from bulldog.anchor_service import authenticate
    def available(sequence, record):
        return authenticate({'version': 1, 'session': identity.session, 'sequence': sequence,
            'head_hash': record['record_hash'], 'accepted': True}, identity.key, purpose='acknowledgement')
    transport.submit = available
    ledger.reconcile_remote()
    assert ledger.verify().valid

import os
import pytest

from bulldog.effect_journal import DurableEffectJournal, EffectJournalError


def journal(tmp_path):
    root = tmp_path / "journal"
    root.mkdir(mode=0o700)
    events = []
    return (
        DurableEffectJournal(
            root, audit=lambda event, fields: events.append((event, fields))
        ),
        events,
    )


def test_effect_is_dispatched_at_most_once_and_exact_bytes_are_bound(tmp_path):
    gate, events = journal(tmp_path)
    effect = {"operation": "send", "target": "human@example.test", "body": "hello"}
    assert gate.begin("human-approved:0001", effect).state == "inflight"
    with pytest.raises(EffectJournalError, match="automatic dispatch is forbidden"):
        gate.begin("human-approved:0001", effect)
    with pytest.raises(EffectJournalError, match="different effect bytes"):
        gate.prepare("human-approved:0001", {**effect, "body": "changed"})
    assert [name for name, _ in events] == [
        "effect.intent_prepared",
        "effect.dispatch_started",
    ]


def test_uncertain_effect_requires_observation_and_never_retries(tmp_path):
    gate, events = journal(tmp_path)
    effect = {"operation": "publish", "target": "release", "artifact": "sha256:abc"}
    gate.begin("publish-release:01", effect)
    gate.mark_uncertain(
        "publish-release:01", reason="connection lost after request body"
    )
    with pytest.raises(EffectJournalError, match="automatic dispatch is forbidden"):
        gate.begin("publish-release:01", effect)
    result = gate.reconcile(
        "publish-release:01", observed="confirmed", receipt="server-event-99"
    )
    assert result.state == "confirmed" and result.attempts == 1
    assert [name for name, _ in events][-2:] == [
        "effect.outcome_uncertain",
        "effect.reconciled",
    ]


def test_journal_rejects_shared_directory(tmp_path):
    root = tmp_path / "journal"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    with pytest.raises(EffectJournalError, match="owner-only"):
        DurableEffectJournal(root, audit=lambda *_: None)

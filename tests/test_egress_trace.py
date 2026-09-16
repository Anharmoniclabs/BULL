import pytest

from bulldog.egress_proxy import EgressBroker
from bulldog.trace_model import TraceViolation


def test_egress_broker_emits_single_grant(tmp_path):

    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts={
            "example.com"
        },
    )

    assert broker.trace.state.broker_granted
    assert len(broker.trace.events) == 1
    assert (
        broker.trace.events[0].transition
        == "GrantBroker"
    )


def test_empty_egress_broker_has_no_grant(tmp_path):

    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts=set(),
    )

    assert not broker.trace.state.broker_granted
    assert broker.trace.events == []


def test_duplicate_broker_grant_remains_illegal(tmp_path):

    broker = EgressBroker(
        tmp_path / "egress.sock",
        allowed_hosts={
            "example.com"
        },
    )

    with pytest.raises(
        TraceViolation
    ):
        broker.trace.emit(
            "GrantBroker"
        )

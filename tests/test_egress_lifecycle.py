"""Repeat benign broker requests through a controlled transport fixture."""
from bulldog.egress_proxy import EgressBroker


def test_two_authorized_requests_have_separate_trace_lifecycles(tmp_path, monkeypatch):
    calls = []
    class Response:
        status = 200
        def read(self, size): return b"fixture"
        def getheaders(self): return []
    class Connection:
        def __init__(self, **kwargs): pass
        def request(self, method, path, headers): calls.append((method, path))
        def getresponse(self): return Response()
        def close(self): pass
    monkeypatch.setattr("bulldog.egress_proxy._PinnedHTTPSConnection", Connection)
    broker = EgressBroker(tmp_path / "unused.sock", allowed_hosts={"example.com"})
    monkeypatch.setattr(broker, "_resolve_public_addresses", lambda *args: ("192.0.2.1",))
    assert broker.fetch(method="GET", url="https://example.com/one").body == b"fixture"
    assert broker.fetch(method="GET", url="https://example.com/two").body == b"fixture"
    assert calls == [("GET", "/one"), ("GET", "/two")]

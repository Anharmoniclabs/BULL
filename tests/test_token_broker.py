"""Tests for bulldog.token_broker (real crypto paths, fail-closed)."""
import time
import pytest
from bulldog.token_broker import TokenBroker, BrokerError

@pytest.fixture
def broker():
    b = TokenBroker(default_ttl=2.0, grace_seconds=0.5)
    b.store_upstream_secret("api.example.com", b"sk-live-UPSTREAM-SECRET")
    return b

class TestVault:
    def test_roundtrip(self, broker):
        tok, _ = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com")
        assert broker.exchange(tok, "NETWORK_EGRESS",
                               "api.example.com") == b"sk-live-UPSTREAM-SECRET"

    def test_unknown_secret(self, broker):
        tok, _ = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com")
        with pytest.raises(BrokerError):
            broker.exchange(tok, "NETWORK_EGRESS", "nope.example.com")

class TestAttackPaths:
    def test_capability_mismatch_blocked(self, broker):
        tok, _ = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com")
        with pytest.raises(BrokerError):
            broker.exchange(tok, "FS_READ_PROJECT", "api.example.com")

    def test_target_mismatch_blocked(self, broker):
        tok, _ = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com")
        with pytest.raises(BrokerError):
            broker.exchange(tok, "NETWORK_EGRESS", "evil.example.com")

    def test_tampered_signature_blocked(self, broker):
        tok, _ = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com")
        p, s = tok.split(".")
        with pytest.raises(BrokerError):
            broker.verify(p + "." + s[:-2] + "AA")

    def test_malformed_token_blocked(self, broker):
        for bad in ["", "abc", "a.b.c", "...."]:
            with pytest.raises(BrokerError):
                broker.verify(bad)

    def test_expiry_blocked(self, broker):
        tok, _ = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com", ttl=0.2)
        time.sleep(0.35)
        with pytest.raises(BrokerError):
            broker.verify(tok)

    def test_revocation_blocked(self, broker):
        tok, meta = broker.mint("agent-1", "NETWORK_EGRESS", "api.example.com")
        broker.revoke(meta.jti)
        with pytest.raises(BrokerError):
            broker.verify(tok)

class TestRotation:
    def test_rotate_moves_minting_epoch(self, broker):
        _, m_old = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
        new_ep = broker.rotate()
        _, m_new = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
        assert m_new.epoch == new_ep > m_old.epoch

    def test_old_epoch_dies_after_grace(self, broker):
        tok, _ = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
        broker.verify(tok)  # valid now
        broker.rotate()
        broker.verify(tok)  # still valid in grace window
        time.sleep(0.6)     # grace = 0.5s
        with pytest.raises(BrokerError):
            broker.verify(tok)

    def test_reap_drops_dead_epochs(self, broker):
        broker.rotate()
        time.sleep(0.6)
        assert broker.reap() >= 1

    def test_revoke_all_kills_everything(self, broker):
        tok, _ = broker.mint("a", "NETWORK_EGRESS", "api.example.com")
        broker.revoke_all()
        with pytest.raises(BrokerError):
            broker.verify(tok)

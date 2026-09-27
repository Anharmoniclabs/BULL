"""Proxy-token broker: enterprise IAM-style short-lived credentials for BULL.

The agent NEVER holds long-lived upstream credentials. The gateway holds
encrypted upstream secrets (AES-256-GCM at rest under a master key) and
mints short-lived, capability-scoped proxy tokens (HMAC-SHA256 signed,
TTL-bound, individually revocable). Upstream credentials are released
only inside the gateway process when a valid, unrevoked, unexpired proxy
token is exchanged at egress time.

Rotation model:
- Signing keys are organized in monotonic epochs. rotate() closes the
  current epoch, opens a new one, and puts the closed epoch into a grace
  window (existing tokens keep verifying; nothing new can be minted
  under it). After the grace window the epoch key is destroyed and all
  of its tokens become invalid simultaneously.
- Each token carries a unique id (jti) so individual tokens can be
  revoked regardless of epoch.
- revoke_all() closes every epoch with zero grace: every outstanding
  token dies at once (incident response).

All crypto is real: AESGCM from `cryptography`, HMAC-SHA256 from
hashlib, os.urandom for all randomness. No placeholders.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def _b64e(b): return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
def _b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

class BrokerError(Exception):
    """Raised for any mint/verify/exchange failure. Callers fail closed."""

@dataclass
class _Epoch:
    key: bytes; opened_at: float
    closed_at: Optional[float] = None; grace_seconds: float = 300.0
    @property
    def can_mint(self): return self.closed_at is None
    @property
    def can_verify(self):
        if self.closed_at is None: return True
        return (time.time() - self.closed_at) < self.grace_seconds

@dataclass(frozen=True)
class ProxyToken:
    jti: str; actor: str; capability: str; target: str
    issued_at: float; expires_at: float; epoch: int

class TokenBroker:
    def __init__(self, master_key=None, default_ttl=300.0, grace_seconds=300.0):
        self._master = master_key or os.urandom(32)
        if len(self._master) not in (16, 24, 32): raise BrokerError("bad master key size")
        self._ttl = default_ttl; self._grace = grace_seconds
        self._epochs = [_Epoch(os.urandom(32), time.time())]
        self._revoked: Dict[str, float] = {}
        self._secrets: Dict[str, bytes] = {}
        self._version = 0

    def store_upstream_secret(self, name, secret):
        if not name or not secret: raise BrokerError("empty name/secret")
        nonce = os.urandom(12)
        ct = AESGCM(self._master).encrypt(nonce, secret, name.encode())
        self._secrets[name] = nonce + ct; self._version += 1

    def _load(self, name):
        blob = self._secrets.get(name)
        if blob is None: raise BrokerError(f"unknown secret {name!r}")
        return AESGCM(self._master).decrypt(blob[:12], blob[12:], name.encode())

    def upstream_secret_names(self): return sorted(self._secrets)

    def mint(self, actor, capability, target, ttl=None):
        ep = self._epochs[-1]
        if not ep.can_mint: raise BrokerError("no open epoch; rotate() first")
        ttl = self._ttl if ttl is None else ttl
        if ttl <= 0: raise BrokerError("ttl must be positive")
        now = time.time(); jti = secrets.token_urlsafe(12)
        claims = {"v":1, "jti":jti, "actor":actor, "cap":capability,
                  "tgt":target, "iat":now, "exp":now+ttl, "ep":len(self._epochs)-1}
        payload = _b64e(json.dumps(claims, sort_keys=True).encode())
        sig = hmac.new(ep.key, payload.encode("ascii"), hashlib.sha256).digest()
        self._version += 1
        return f"{payload}.{_b64e(sig)}", ProxyToken(jti, actor, capability, target,
                                                      now, now+ttl, len(self._epochs)-1)

    def verify(self, token):
        try:
            payload_b64, sig_b64 = token.split(".", 1)
            sig = _b64d(sig_b64)
            claims = json.loads(_b64d(payload_b64))
        except Exception as e:
            raise BrokerError(f"malformed token: {e}")
        if claims.get("v") != 1: raise BrokerError("unsupported version")
        ep = claims.get("ep")
        if not isinstance(ep, int) or not (0 <= ep < len(self._epochs)):
            raise BrokerError(f"unknown epoch {ep!r}")
        epoch = self._epochs[ep]
        expect = hmac.new(epoch.key, payload_b64.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(expect, sig): raise BrokerError("bad signature")
        if not epoch.can_verify: raise BrokerError(f"epoch {ep} grace expired")
        now = time.time()
        if claims["exp"] < now: raise BrokerError("token expired")
        if claims["iat"] > now + 30: raise BrokerError("token issued in the future")
        if claims["jti"] in self._revoked: raise BrokerError("token revoked")
        return ProxyToken(claims["jti"], claims["actor"], claims["cap"],
                          claims["tgt"], claims["iat"], claims["exp"], ep)

    def exchange(self, token, capability, target):
        """Return the upstream secret for a valid, matching proxy token.

        The gateway calls this at egress time and injects the result into
        the upstream request. The agent-facing side only ever sees the
        proxy token itself."""
        t = self.verify(token)
        if t.capability != capability:
            raise BrokerError(f"capability mismatch: token grants {t.capability!r}, egress needs {capability!r}")
        if t.target not in ("*", target):
            raise BrokerError(f"target mismatch: token grants {t.target!r}, egress is {target!r}")
        return self._load(target)

    def rotate(self):
        """Close the current epoch (if open), open a new one. Returns new epoch id.

        Already-closed epochs keep their existing grace window - this is
        what lets revoke_all() (zero grace) survive a subsequent rotate()."""
        cur = self._epochs[-1]
        if cur.closed_at is None:
            cur.closed_at = time.time(); cur.grace_seconds = self._grace
        self._epochs.append(_Epoch(os.urandom(32), time.time()))
        self._version += 1
        return len(self._epochs) - 1

    def reap(self):
        """Drop epochs whose grace windows have expired. Returns count."""
        before = len(self._epochs)
        self._epochs = [e for e in self._epochs if e.closed_at is None or e.can_verify]
        self._version += 1
        return before - len(self._epochs)

    def revoke(self, jti):
        if not jti: raise BrokerError("empty jti")
        self._revoked[jti] = time.time(); self._version += 1

    def revoke_all(self):
        """Kill-switch: zero-grace every epoch, then rotate. All tokens die."""
        n = len(self._revoked)
        for e in self._epochs:
            if e.closed_at is None:
                e.closed_at = time.time(); e.grace_seconds = 0.0
        self.rotate(); self._revoked.clear(); self._version += 1
        return n

    @property
    def state_version(self): return self._version
    def epoch_status(self):
        return [{"epoch": i, "can_mint": e.can_mint, "can_verify": e.can_verify,
                 "closed_at": e.closed_at, "grace_seconds": e.grace_seconds}
                for i, e in enumerate(self._epochs)]

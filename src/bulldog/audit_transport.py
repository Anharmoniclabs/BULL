"""Versioned production anchor transports with authenticated acknowledgements."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import select
import ssl
import time
import stat
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler, HTTPSHandler, Request

from .anchor_service import AnchorError, AnchorStore, MAX_FRAME, canonical, checkpoint, decode, verify


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise AnchorError("audit endpoint redirects are forbidden")


@dataclass(frozen=True)
class AnchorIdentity:
    session: str
    key: bytes

    def __post_init__(self):
        from .anchor_service import session_key
        session_key(self.key, self.session)  # Validate key size and session syntax.

    def check_ack(self, ack: dict, sequence: int, head_hash: str) -> None:
        verify(ack, self.key, purpose="acknowledgement")
        expected = {"version": 1, "session": self.session, "sequence": sequence,
                    "head_hash": head_hash, "accepted": True}
        if canonical({k: v for k, v in ack.items() if k != "mac"}) != canonical(expected):
            raise AnchorError("acknowledgement identity mismatch")


class HTTPSAnchorTransport:
    """Endpoint and session credentials are supplied by trusted deployment code."""

    def __init__(self, endpoint: str, identity: AnchorIdentity, *, timeout: float = 5,
                 test_ca: Path | None = None):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise AnchorError("anchor requires a credential-free HTTPS endpoint")
        if not 0 < timeout <= 30:
            raise AnchorError("anchor timeout must be between 0 and 30 seconds")
        self.identity, self.endpoint, self.timeout = identity, endpoint, timeout
        self.production_ready = test_ca is None and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        context = ssl.create_default_context(cafile=str(test_ca) if test_ca else None)
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=context))

    def submit(self, sequence: int, record: dict) -> dict:
        message = checkpoint(self.identity.session, sequence, record, self.identity.key, include_record=False)
        encoded = canonical(message)
        if len(encoded) > MAX_FRAME:
            raise AnchorError("audit record exceeds framing limit")
        request = Request(
            self.endpoint,
            data=encoded,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "BULL-AuditAnchor/1",
            },
            method="POST",
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            if response.status != 200:
                raise AnchorError("audit service did not accept checkpoint")
            ack = decode(response.read(MAX_FRAME + 1))
        self.identity.check_ack(ack, sequence, record["record_hash"])
        return ack


class RelayAnchorTransport:
    """Engine-only virtio port; messages contain no endpoint, headers or paths."""

    def __init__(self, port_fd: int, identity: AnchorIdentity, *, timeout: float = 5):
        if not 0 < timeout <= 30:
            raise AnchorError("anchor timeout must be between 0 and 30 seconds")
        self.fd, self.identity, self.timeout = port_fd, identity, timeout
        os.set_blocking(self.fd, False)
        os.set_inheritable(self.fd, False)
        self._acknowledged = False

    @property
    def production_ready(self) -> bool:
        # Readiness is earned by verifying a real collector acknowledgment.
        # Deployment/session authorization is separately checked at bootstrap.
        return self._acknowledged

    def submit(self, sequence: int, record: dict) -> dict:
        encoded = canonical(checkpoint(self.identity.session, sequence, record, self.identity.key)) + b"\n"
        if len(encoded) > MAX_FRAME:
            raise AnchorError("audit record exceeds framing limit")
        deadline = time.monotonic() + self.timeout
        remaining = memoryview(encoded)
        while remaining:
            wait = deadline - time.monotonic()
            if wait <= 0 or not select.select([], [self.fd], [], wait)[1]:
                raise AnchorError("relay write timeout")
            # Port is nonblocking to make the deadline cover writes too.
            try:
                written = os.write(self.fd, remaining)
            except BlockingIOError:
                continue
            if not written:
                raise AnchorError("relay disconnected")
            remaining = remaining[written:]
        raw = bytearray()
        while len(raw) <= MAX_FRAME:
            wait = deadline - time.monotonic()
            if wait <= 0 or not select.select([self.fd], [], [], wait)[0]:
                raise AnchorError("relay acknowledgement timeout")
            try:
                chunk = os.read(self.fd, 1)
            except BlockingIOError:
                continue
            if not chunk:
                raise AnchorError("relay disconnected")
            if chunk == b"\n":
                ack = decode(bytes(raw))
                self.identity.check_ack(ack, sequence, record["record_hash"])
                self._acknowledged = True
                return ack
            raw.extend(chunk)
        raise AnchorError("relay acknowledgement exceeds size limit")


class HostAnchorRelay:
    """Retain guest evidence locally; return success only after remote acceptance."""

    def __init__(self, evidence: AnchorStore, upstream: HTTPSAnchorTransport, session: str):
        if session != upstream.identity.session:
            raise AnchorError("relay session mismatch")
        self.evidence, self.upstream, self.session = evidence, upstream, session

    def handle(self, raw: bytes) -> bytes:
        message = decode(raw)
        if message.get("session") != self.session:
            raise AnchorError("relay rejects foreign session")
        if "record" not in message:
            raise AnchorError("relay requires complete local audit evidence")
        acknowledgement = self.evidence.accept(message)
        # Local evidence deliberately survives a failed upstream submission.
        self.upstream.submit(message["sequence"], message["record"])
        return canonical(acknowledgement) + b"\n"


_guest_relay: tuple[int, RelayAnchorTransport] | None = None


def bootstrap_guest_relay(fd: int, identity: AnchorIdentity, ledger_path: Path) -> RelayAnchorTransport:
    """Trusted guest bootstrap only; prove the real audit path before admission.

    No readiness flag or file descriptor is taken from model requests. The
    supervisor opens a dedicated virtio port and provisions session authority.
    The descriptor is never passed into a workload.
    """
    global _guest_relay
    if _guest_relay is not None:
        raise AnchorError("audit session already bootstrapped")
    if os.getpid() != 1 or not stat.S_ISCHR(os.fstat(fd).st_mode):
        raise AnchorError("relay bootstrap requires guest PID 1 and a character port")
    expected = Path('/sys/class/virtio-ports')
    devices = [p for p in expected.glob('*/name') if p.read_text().strip() == 'org.bull.audit']
    if len(devices) != 1:
        raise AnchorError("dedicated audit virtio port is unavailable")
    major, minor = map(int, devices[0].with_name('dev').read_text().strip().split(':'))
    if os.fstat(fd).st_rdev != os.makedev(major, minor):
        raise AnchorError("audit descriptor is not the dedicated virtio port")
    from .audit import AuditLedger
    transport = RelayAnchorTransport(fd, identity)
    ledger = AuditLedger(ledger_path, transport=transport)
    if ledger.verify().records != 0:
        raise AnchorError("one-shot audit session must start with an empty ledger")
    ledger.append_event('guest_bootstrap', {'session': identity.session})
    if not transport.production_ready or not ledger.verify().valid:
        raise AnchorError("guest audit bootstrap did not receive a valid acknowledgment")
    _guest_relay = (os.getpid(), transport)
    return transport


def production_transport_from_environment() -> HTTPSAnchorTransport | RelayAnchorTransport:
    """Use direct HTTPS or a live, acknowledged supervisor-owned guest relay."""
    from .anchor_service import session_key
    mode = os.environ.get("BULL_AUDIT_TRANSPORT", "https")
    if mode == 'relay':
        if (_guest_relay is None or _guest_relay[0] != os.getpid()
                or not _guest_relay[1].production_ready
                or _guest_relay[1].identity.session != os.environ.get('BULL_AUDIT_SESSION_ID')):
            raise AnchorError("production relay bootstrap is not provisioned")
        return _guest_relay[1]
    if mode != "https":
        raise AnchorError("production relay bootstrap is not provisioned; transport must be https")
    session = os.environ.get("BULL_AUDIT_SESSION_ID", "")
    master = os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_KEY", "").encode()
    identity = AnchorIdentity(session, session_key(master, session))
    transport = HTTPSAnchorTransport(os.environ.get("BULL_REMOTE_AUDIT_ANCHOR_URL", ""), identity)
    if not transport.production_ready or os.environ.get("BULL_AUDIT_TEST_CA"):
        raise AnchorError("test or local audit endpoints cannot satisfy production readiness")
    return transport

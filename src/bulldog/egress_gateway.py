"""Handle HTTP, TLS server-name and DNS requests in a configured guest.

Guest nftables rules redirect selected traffic to this service and drop other
output. The gateway itself does not install those rules. TLS bodies remain
opaque, and the bullgw identity is trusted for upstream access."""

from __future__ import annotations

import asyncio
import re
import socket
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Tuple

AuditFn = Callable[[Dict], None]


@dataclass(frozen=True)
class EgressRequest:
    kind: str  # "tls_sni" | "http_request" | "dns_query"
    host: str
    method: str = ""
    path: str = ""
    client: str = ""


class EgressPolicy:
    """Exact-match host allowlist with optional per-host method/path rules."""

    def __init__(self, host_rules: Dict[str, Dict]) -> None:
        if not host_rules:
            raise ValueError(
                "empty host_rules: gateway refuses to start with no policy (fail-closed)"
            )
        rules = {}
        for host, rule in host_rules.items():
            if (
                type(host) is not str
                or len(host) > 253
                or not re.fullmatch(
                    r"(?=.{1,253}$)[A-Za-z0-9]+(?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host
                )
                or ".." in host
                or type(rule) is not dict
                or set(rule) - {"methods", "paths"}
            ):
                raise ValueError("invalid egress host policy")
            methods, paths = rule.get("methods"), rule.get("paths")
            if methods is not None and (
                type(methods) is not list
                or not methods
                or any(
                    type(m) is not str or not re.fullmatch(r"[A-Z]+", m)
                    for m in methods
                )
            ):
                raise ValueError("invalid egress methods")
            if paths is not None and (
                type(paths) is not list
                or not paths
                or any(
                    type(p) is not str
                    or not p.startswith("/")
                    or "\r" in p
                    or "\n" in p
                    for p in paths
                )
            ):
                raise ValueError("invalid egress paths")
            key = host.lower()
            if key in rules:
                raise ValueError("duplicate egress host")
            rules[key] = dict(rule)
        self._rules = rules

    def decide(self, req: EgressRequest) -> Tuple[bool, str]:
        host = (req.host or "").lower().rstrip(".")
        if host in self._rules:
            rule = self._rules[host]
            # SNI reveals a hostname, never the HTTP method or path inside TLS.
            # A host with finer-grained rules must not silently become a broad
            # TLS tunnel just because the client switched protocols.
            if req.kind == "tls_sni" and ("methods" in rule or "paths" in rule):
                return (
                    False,
                    "TLS payload is opaque; method/path policy cannot be enforced",
                )
            if req.kind == "http_request" and not req.method:
                return False, "HTTP method is required"
            if (
                rule.get("methods")
                and req.method
                and req.method.upper() not in rule["methods"]
            ):
                return False, f"method {req.method} not permitted for {host}"
            if (
                rule.get("paths")
                and req.path
                and not any(req.path.startswith(p) for p in rule["paths"])
            ):
                return False, f"path {req.path} not permitted for {host}"
            return True, f"host {host} allowlisted"
        return False, f"host {host!r} not in allowlist"

    def allows_host(self, host: str) -> bool:
        return (host or "").lower().rstrip(".") in self._rules


def extract_sni(data: bytes) -> Optional[str]:
    """Parse a TLS ClientHello record and return its SNI hostname, or None.

    SNI is sent in the clear by design of TLS (RFC 6066), so no private
    keys are needed. SNI names are ASCII A-labels.
    """
    if len(data) < 5 or data[0] != 0x16:
        return None
    try:
        record_len = int.from_bytes(data[3:5], "big")
        body = data[5 : 5 + record_len]
        if len(body) < 4 or body[0] != 0x01:
            return None
        body = body[4:]
        if len(body) < 34:
            return None
        p = 2 + 32  # version + random
        p += 1 + body[p]  # session id
        p += 2 + int.from_bytes(body[p : p + 2], "big")  # cipher suites
        p += 1 + body[p]  # compression methods
        ext_len = int.from_bytes(body[p : p + 2], "big")
        p += 2
        end = min(len(body), p + ext_len)
        while p + 4 <= end:
            etype = int.from_bytes(body[p : p + 2], "big")
            elen = int.from_bytes(body[p + 2 : p + 4], "big")
            ext = body[p + 4 : p + 4 + elen]
            if etype == 0:
                if len(ext) < 5 or ext[2] != 0:
                    return None
                name_len = int.from_bytes(ext[3:5], "big")
                return ext[5 : 5 + name_len].decode("ascii", errors="replace")
            p += 4 + elen
    except (IndexError, ValueError):
        return None
    return None


def parse_http_head(data: bytes):
    try:
        head = data.split(b"\r\n\r\n", 1)[0]
        lines = head.decode("latin-1").split("\r\n")
        method, target, _proto = lines[0].split(" ", 2)
        headers = {}
        for line in lines[1:]:
            if not line or line[0].isspace() or ":" not in line:
                return None
            k, v = line.split(":", 1)
            key = k.strip().lower()
            if key in headers or not re.fullmatch(r"[a-z0-9-]+", key):
                return None
            headers[key] = v.strip()
        host = headers.get("host", "")
        if not target.startswith("/") or not host or not method.isalpha():
            return None
        return method.upper(), host, target, headers
    except Exception:
        return None


@dataclass
class GatewayConfig:
    listen_host: str = "127.0.0.1"
    transparent_port: int = 9443  # nftables REDIRECT target for tcp 80/443
    dns_port: int = 1953  # unprivileged nftables REDIRECT target for udp 53
    dns_upstream: Tuple[str, int] = ("127.0.0.53", 53)
    resolver: Callable[[str], Tuple[str, int]] = lambda h: (h, 443)
    # resolver maps a policy-approved hostname to the upstream (ip, port).
    # Production default resolves via allowlisted DNS; tests override.
    connect_timeout: float = 5.0
    peek_bytes: int = 2048


class EgressGateway:
    def __init__(
        self,
        policy: EgressPolicy,
        config: Optional[GatewayConfig] = None,
        audit: Optional[AuditFn] = None,
        header_injector: Optional[Callable[[EgressRequest], Dict[str, str]]] = None,
    ) -> None:
        if policy is None:
            raise ValueError("policy is required: no silent allow (fail-closed)")
        self.policy = policy
        self.cfg = config or GatewayConfig()
        self._audit = audit or (lambda rec: None)
        self._injector = header_injector
        self._server = None
        self.stats = {"tls_sni": 0, "http": 0, "dns": 0, "allowed": 0, "denied": 0}

    def _emit(self, **rec):
        rec.setdefault("ts", time.time())
        self._audit(rec)

    async def _handle_stream(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            first = await asyncio.wait_for(
                reader.read(self.cfg.peek_bytes), self.cfg.connect_timeout
            )
            if first and first[0] == 0x16:
                # TCP reads are not record boundaries. Accumulate one complete
                # bounded ClientHello record before authorizing a TLS tunnel.
                while len(first) < 5:
                    chunk = await asyncio.wait_for(
                        reader.read(5 - len(first)), self.cfg.connect_timeout
                    )
                    if not chunk:
                        raise ValueError("incomplete TLS record")
                    first += chunk
                needed = 5 + int.from_bytes(first[3:5], "big")
                if needed > 16389 or needed < 9:
                    raise ValueError("oversized or invalid TLS record")
                while len(first) < needed:
                    chunk = await asyncio.wait_for(
                        reader.read(min(needed - len(first), 4096)),
                        self.cfg.connect_timeout,
                    )
                    if not chunk:
                        raise ValueError("incomplete TLS ClientHello")
                    first += chunk
            elif first and first[:1] in (b"G", b"P", b"H", b"D", b"O"):
                # Never forward a partial header: a later Authorization line
                # would otherwise escape stripping and policy inspection.
                while b"\r\n\r\n" not in first:
                    if len(first) >= 16384:
                        raise ValueError("HTTP header exceeds limit")
                    chunk = await asyncio.wait_for(
                        reader.read(min(4096, 16384 - len(first))),
                        self.cfg.connect_timeout,
                    )
                    if not chunk:
                        raise ValueError("incomplete HTTP header")
                    first += chunk
        except (asyncio.TimeoutError, ConnectionError, ValueError):
            self.stats["denied"] += 1
            writer.close()
            return
        try:
            if first and first[0] == 0x16:
                await self._handle_tls(first, reader, writer, peer)
            elif first and first[:4] in (
                b"GET ",
                b"POST",
                b"PUT ",
                b"HEAD",
                b"DELE",
                b"PATC",
                b"OPTI",
            ):
                await self._handle_http(first, reader, writer, peer)
            else:
                self.stats["denied"] += 1
                self._emit(
                    event="deny",
                    kind="unknown_shape",
                    client=str(peer),
                    reason="traffic is neither TLS ClientHello nor HTTP; fail-closed",
                )
                writer.close()
        except Exception as exc:
            self.stats["denied"] += 1
            self._emit(
                event="deny",
                kind="error",
                client=str(peer),
                reason=f"gateway error: {exc!r}",
            )
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_tls(self, first, reader, writer, peer):
        sni = extract_sni(first)
        self.stats["tls_sni"] += 1
        req = EgressRequest("tls_sni", sni or "", client=str(peer))
        allowed, reason = self._decide(req)
        if not allowed:
            self.stats["denied"] += 1
            writer.close()
            return
        self.stats["allowed"] += 1
        ip, port = self.cfg.resolver(sni)
        await self._relay(first, reader, writer, ip, port)

    async def _handle_http(self, first, reader, writer, peer):
        self.stats["http"] += 1
        parsed = parse_http_head(first)
        if parsed is None:
            self.stats["denied"] += 1
            self._emit(
                event="deny",
                kind="http",
                client=str(peer),
                reason="unparseable HTTP head; fail-closed",
            )
            writer.close()
            return
        method, host, path, _ = parsed
        req = EgressRequest(
            "http_request", host, method=method, path=path, client=str(peer)
        )
        allowed, reason = self._decide(req)
        if not allowed:
            self.stats["denied"] += 1
            try:
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                await writer.drain()
            finally:
                writer.close()
            return
        self.stats["allowed"] += 1
        # Credential isolation: strip client Authorization; inject broker creds.
        head = first.split(b"\r\n\r\n", 1)[0].decode("latin-1")
        lines = [
            l for l in head.split("\r\n") if not l.lower().startswith("authorization:")
        ]
        if self._injector:
            for k, v in self._injector(req).items():
                lines.append(f"{k}: {v}")
        new_head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
        rest = first[len(head.encode("latin-1")) + 4 :]
        ip, port = self.cfg.resolver(host)
        await self._relay(new_head + rest, reader, writer, ip, port)

    def _decide(self, req):
        try:
            allowed, reason = self.policy.decide(req)
        except Exception as exc:
            return False, f"policy engine error (fail-closed): {exc!r}"
        self._emit(
            event="allow" if allowed else "deny",
            kind=req.kind,
            host=req.host,
            method=req.method,
            path=req.path,
            client=req.client,
            reason=reason,
        )
        return allowed, reason

    async def _relay(self, first, reader, writer, ip, port):
        try:
            ur, uw = await asyncio.wait_for(
                asyncio.open_connection(ip, port), self.cfg.connect_timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            self._emit(
                event="deny",
                kind="upstream_unreachable",
                reason=f"{ip}:{port}: {exc!r}",
            )
            writer.close()
            return
        uw.write(first)
        await uw.drain()

        async def pump(src, dst):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, asyncio.TimeoutError):
                pass
            finally:
                try:
                    dst.close()
                except Exception:
                    pass

        await asyncio.gather(pump(reader, uw), pump(ur, writer), return_exceptions=True)
        writer.close()

    def dns_decide(self, qname: str) -> bool:
        self.stats["dns"] += 1
        ok = self.policy.allows_host(qname)
        self._emit(
            event="allow" if ok else "deny",
            kind="dns_query",
            host=qname,
            reason="allowlisted" if ok else "not allowlisted; REFUSED",
        )
        return ok

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_stream, self.cfg.listen_host, self.cfg.transparent_port
        )
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _DnsProtocol(self),
            local_addr=(self.cfg.listen_host, self.cfg.dns_port),
        )
        self._dns_transport = transport

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if getattr(self, "_dns_transport", None):
            self._dns_transport.close()


class _DnsProtocol(asyncio.DatagramProtocol):
    """Minimal DNS filter: allowlisted names forwarded upstream and relayed,
    everything else REFUSED. The sandbox client sees a normal resolver - it
    never learns there is a policy in front of it."""

    def __init__(self, gw):
        self.gw = gw
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            qname = self._decode_qname(data)
        except Exception:
            qname = None
        if qname is None or not self.gw.dns_decide(qname):
            if self.transport:
                self.transport.sendto(self._refuse(data), addr)
            return
        import threading

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.connect(self.gw.cfg.dns_upstream)
        except OSError:
            return

        def fwd():
            try:
                sock.send(data)
                resp = sock.recv(4096)
                if self.transport:
                    self.transport.sendto(resp, addr)
            except OSError:
                if self.transport:
                    self.transport.sendto(self._refuse(data), addr)
            finally:
                sock.close()

        threading.Thread(target=fwd, daemon=True).start()

    @staticmethod
    def _decode_qname(data):
        if len(data) < 12:
            return None
        if int.from_bytes(data[4:6], "big") != 1:
            return None
        p, labels = 12, []
        while p < len(data) and data[p] != 0:
            l = data[p]
            if l == 0 or l > 63 or p + 1 + l > len(data):
                return None
            labels.append(data[p + 1 : p + 1 + l].decode("ascii", errors="strict"))
            p += 1 + l
        qname = ".".join(labels).lower()
        return qname or None

    @staticmethod
    def _refuse(data):
        hdr = bytearray(data[:12])
        hdr[2], hdr[3] = 0x81, 0x05  # response, REFUSED
        qend = 12
        while qend < len(data) and data[qend] != 0:
            qend += 1 + data[qend]
        qend += 5
        return bytes(hdr) + data[12:qend]

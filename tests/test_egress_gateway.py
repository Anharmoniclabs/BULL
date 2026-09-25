"""End-to-end tests for bulldog.egress_gateway (real sockets, real TLS)."""
import asyncio
import datetime
import json
import os
import socket
import ssl
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from bulldog.egress_gateway import (EgressGateway, EgressPolicy, GatewayConfig,
                                    extract_sni)

HTTP_HOST = "api.example.com"
TLS_HOST = "secure.example.org"
HOST_BAD = "evil.example"


class TestSniParser:
    def _clienthello(self, server_name):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        in_bio, out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
        ss = ctx.wrap_bio(in_bio, out_bio, server_hostname=server_name)
        try:
            ss.do_handshake()
        except Exception:
            pass
        return out_bio.read()

    def test_real_clienthello(self):
        hello = self._clienthello("api.example.com")
        assert extract_sni(hello) == "api.example.com"

    def test_garbage_rejected(self):
        assert extract_sni(b"GET / HTTP/1.1") is None
        assert extract_sni(b"") is None
        assert extract_sni(b"\x16\x03\x01\x00\x05\x01") is None


class TestEndToEnd:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.events = []
        self.policy = EgressPolicy({
            HTTP_HOST: {"methods": ["GET"], "paths": ["/v1/"]},
            TLS_HOST: {},
            # HOST_BAD deliberately absent -> must be denied
        })
        key = rsa.generate_private_key(65537, 2048)
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_HOST)]))
                .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, TLS_HOST)]))
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2026, 9, 1))
                .not_valid_after(datetime.datetime(2027, 9, 1))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.DNSName(TLS_HOST)]), critical=False)
                .sign(key, hashes.SHA256()))
        d = tempfile.mkdtemp()
        self.crt = os.path.join(d, "c.crt")
        pem = os.path.join(d, "k.pem")
        open(self.crt, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
        open(pem, "wb").write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_ctx.load_cert_chain(self.crt, pem)
        asyncio.run(self._run())
        yield

    async def _run(self):
        loop = asyncio.get_running_loop()
        async def http_origin(reader, writer):
            try:
                head = await asyncio.wait_for(reader.read(4096), 5)
                lines = head.split(b"\r\n")
                body = json.dumps({
                    "request_line": lines[0].decode("latin-1"),
                    "auth_value": next((l.decode("latin-1").split(":", 1)[1].strip()
                                        for l in lines
                                        if l.lower().startswith(b"authorization:")),
                                       None)}).encode()
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             + f"Content-Length: {len(body)}\r\n".encode()
                             + b"Connection: close\r\n\r\n" + body)
                await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        async def tls_echo(reader, writer):
            try:
                data = await asyncio.wait_for(reader.read(4096), 5)
                writer.write(b"TLS-OK:" + data[:32])
                await writer.drain()
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        origin_srv = await asyncio.start_server(http_origin, "127.0.0.1", 0)
        origin_port = origin_srv.sockets[0].getsockname()[1]
        tls_srv = await asyncio.start_server(tls_echo, "127.0.0.1", 0, ssl=self.tls_ctx)
        tls_port = tls_srv.sockets[0].getsockname()[1]

        def resolver(h):
            if h == HTTP_HOST:
                return ("127.0.0.1", origin_port)
            if h == TLS_HOST:
                return ("127.0.0.1", tls_port)
            return ("127.0.0.1", origin_port)

        gw = EgressGateway(self.policy, GatewayConfig(resolver=resolver),
                            audit=self.events.append,
                            header_injector=lambda req: {
                                "Authorization": "Bearer sk-live-REAL-SECRET"})
        gw_srv = await asyncio.start_server(gw._handle_stream, "127.0.0.1", 0)
        gw_port = gw_srv.sockets[0].getsockname()[1]
        self.gw = gw

        # HTTP allowed + credential isolation
        r, w = await asyncio.open_connection("127.0.0.1", gw_port)
        w.write(f"GET /v1/data HTTP/1.1\r\nHost: {HTTP_HOST}\r\n"
                "Authorization: Bearer AGENT-SENT-THIS\r\n"
                "Connection: close\r\n\r\n".encode())
        await w.drain()
        self.http_resp = await r.read(65536)
        w.close()

        # HTTP denied (method)
        r, w = await asyncio.open_connection("127.0.0.1", gw_port)
        w.write(f"POST /v1/data HTTP/1.1\r\nHost: {HTTP_HOST}\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n".encode())
        await w.drain()
        self.method_denied_resp = await r.read(65536)
        w.close()

        # HTTP denied (host)
        r, w = await asyncio.open_connection("127.0.0.1", gw_port)
        w.write(f"GET /x HTTP/1.1\r\nHost: {HOST_BAD}\r\n"
                "Connection: close\r\n\r\n".encode())
        await w.drain()
        self.host_denied_resp = await r.read(65536)
        w.close()

        # TLS allowed (worker thread keeps the event loop free)
        def tls_good():
            cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cctx.check_hostname = True
            cctx.verify_mode = ssl.CERT_REQUIRED
            cctx.load_verify_locations(self.crt)
            s = socket.create_connection(("127.0.0.1", gw_port), timeout=10)
            tls = cctx.wrap_socket(s, server_hostname=TLS_HOST)
            tls.sendall(b"hello-through-gateway")
            data = tls.recv(4096)
            tls.close()
            return data.startswith(b"TLS-OK:")
        self.tls_allowed = await loop.run_in_executor(None, tls_good)

        # TLS denied (SNI) -> connection killed during handshake
        def tls_bad():
            cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            cctx.check_hostname = False
            cctx.verify_mode = ssl.CERT_NONE
            s = socket.create_connection(("127.0.0.1", gw_port), timeout=10)
            try:
                tls = cctx.wrap_socket(s, server_hostname=HOST_BAD)
                tls.sendall(b"exfil")
                tls.recv(4096)
                return False
            except (ssl.SSLError, OSError):
                return True
            finally:
                try:
                    s.close()
                except Exception:
                    pass
        self.tls_blocked = await loop.run_in_executor(None, tls_bad)

        # unknown shape -> fail-closed
        r, w = await asyncio.open_connection("127.0.0.1", gw_port)
        w.write(b"\x07\xf0\x00\x01 binary garbage")
        await w.drain()
        await asyncio.sleep(0.2)
        self.unknown_denied = any(
            e.get("kind") == "unknown_shape" and e["event"] == "deny"
            for e in self.events)
        w.close()

        origin_srv.close()
        tls_srv.close()
        gw_srv.close()

    def test_http_allowed_and_relayed(self):
        assert b"200 OK" in self.http_resp

    def test_agent_authorization_stripped(self):
        seen = json.loads(self.http_resp.split(b"\r\n\r\n", 1)[1])
        assert seen["auth_value"] != "AGENT-SENT-THIS"

    def test_broker_credential_injected(self):
        seen = json.loads(self.http_resp.split(b"\r\n\r\n", 1)[1])
        assert seen["auth_value"] == "Bearer sk-live-REAL-SECRET"

    def test_method_denied_403(self):
        assert self.method_denied_resp.startswith(b"HTTP/1.1 403")

    def test_bad_host_denied_403(self):
        assert self.host_denied_resp.startswith(b"HTTP/1.1 403")

    def test_tls_allowed_sni_relayed(self):
        assert self.tls_allowed

    def test_tls_bad_sni_blocked(self):
        assert self.tls_blocked

    def test_dns_allowlist(self):
        assert self.gw.dns_decide(TLS_HOST)
        assert not self.gw.dns_decide("unknown.example")

    def test_unknown_shape_denied(self):
        assert self.unknown_denied

    def test_gateway_refuses_empty_policy(self):
        with pytest.raises(ValueError):
            EgressPolicy({})

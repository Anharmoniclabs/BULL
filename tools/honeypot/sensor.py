"""BULL-governed, low-interaction HTTP decoy. Never executes received code."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import time
from urllib.parse import unquote, urlsplit
from dataclasses import asdict

from bulldog.audit import AuditLedger
from bulldog.engine import BulldogEngine
from bulldog.models import ActionRequest, Capability, Decision, Provenance
from bulldog.policy import DeterministicPolicy

MAX_BODY = 8192
MAX_HEADER = 16384
MAX_RECORDS = 4000
FIXTURES = {
    "/decoy/": b'{"service":"operations","tools":"/api/tools"}',
    "/decoy/status": b'{"status":"ok","environment":"staging"}',
    "/decoy/README.md": b"Operations staging workspace. Application logs: /logs/app.log\n",
    "/decoy/logs/app.log": b"2026-09-23 INFO service started\n",
    "/decoy/api/tools": b'{"endpoint":"/api/tool","operations":["read","write","exec","post","credential"]}',
}
CAPABILITIES = {
    "read": Capability.FS_READ_PROJECT,
    "write": Capability.FS_WRITE_PROJECT,
    "exec": Capability.PROCESS_EXEC,
    "post": Capability.NETWORK_POST,
    "credential": Capability.CREDENTIAL_READ,
}


class Sensor:
    def __init__(self, state: Path, *, duration: int = 3600):
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state = state
        keyfile = state / "anchor.key"
        if not keyfile.exists():
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(secrets.token_bytes(32))
        self.ledger = AuditLedger(state / "audit.jsonl", anchor_path=state / "audit.anchor",
                                  anchor_key=keyfile.read_bytes(), max_ledger_bytes=8 * 1024 * 1024)
        self.engine = BulldogEngine(policy=DeterministicPolicy(project_root="/decoy"), ledger=self.ledger)
        self.deadline = time.monotonic() + duration
        self.counters = {"transport_rejections": 0, "audit_failures": 0,
                         "delivery_failures": 0, "budget_rejections": 0}
        self.run_id = secrets.token_hex(12)
        self.stopped = False
        self.ledger.append_event("sensor_started", {"run_id": self.run_id,
            "scope": "BULL policy-gated synthetic HTTP assets; no OS execution",
            "duration_seconds": duration, "source_revision": os.environ.get("BULL_SOURCE_REVISION", "unrecorded"),
            "source_ip": "unavailable through local Unix relay; forwarding headers untrusted"})

    def active(self):
        return not self.stopped and time.monotonic() < self.deadline

    def process(self, method: str, target: str, headers: dict[str, str], body: bytes):
        if not self.active():
            self.counters["budget_rejections"] += 1
            return 503, b"unavailable"
        try:
            verification = self.ledger.verify()
            if not verification.valid:
                raise RuntimeError("audit integrity check failed")
            if verification.records + 2 > MAX_RECORDS:
                self.stopped = True
                self.counters["budget_rejections"] += 1
                return 503, b"unavailable"
            path = urlsplit(target).path
            # Treat network input as data only. Client-supplied grants, provenance,
            # identities and metadata never enter the trusted ActionRequest.
            operation = "read" if method in ("GET", "HEAD") else "write"
            resource = "/decoy" + path
            if path == "/api/tool" and method == "POST":
                proposal = json.loads(body)
                if not isinstance(proposal, dict):
                    raise ValueError("tool request must be an object")
                operation = proposal.get("operation", "")
                if operation not in CAPABILITIES:
                    raise ValueError("unsupported operation")
                value = proposal.get("resource", "")
                if not isinstance(value, str) or len(value) > 2048:
                    raise ValueError("invalid resource")
                resource = "/decoy" + value if value.startswith("/") else value
            decoded = unquote(resource).lower()
            if operation == "read" and any(x in decoded for x in (".env", ".ssh", ".aws", "password", "credential", "/etc/shadow")):
                operation = "credential"
            event_id = secrets.token_hex(12)
            metadata = {"event_id": event_id, "run_id": self.run_id,
                "method": method, "target": target,
                "user_agent": headers.get("user-agent", "")[:512],
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "body_bytes": str(len(body)),
                "body_prefix_base64": base64.b64encode(body[:2048]).decode(),
                "body_truncated": str(len(body) > 2048).lower(),
                "source_attribution": "unknown", "security_context_id": "public-decoy"}
            action = ActionRequest(actor="internet-decoy", task="serve synthetic workspace",
                operation=operation, resource=resource, capability=CAPABILITIES[operation],
                granted_capabilities=frozenset({Capability.FS_READ_PROJECT}),
                provenance=(Provenance.INTERNET,), metadata=metadata)
            result = self.engine.evaluate(action)
            if result.decision != Decision.ALLOW:
                status, reply, effect = 403, b"access denied", "no_decoy_asset_returned"
            elif resource in FIXTURES and operation == "read":
                status, reply, effect = 200, FIXTURES[resource], "synthetic_asset_prepared"
            else:
                status, reply, effect = 404, b"not found", "no_matching_asset"
            # Commit planned response before transmitting; this is not a claim
            # that a remote client received the response.
            self.ledger.append_event("response_prepared", {"event_id": event_id,
                "status": status, "effect": effect, "response_sha256": hashlib.sha256(reply).hexdigest(),
                "response_bytes": len(reply), "remote_delivery": "unconfirmed"})
            return status, reply
        except (ValueError, TypeError, KeyError):
            return self.reject("invalid_tool_request")
        except Exception:
            self.counters["audit_failures"] += 1
            self.stopped = True
            return 503, b"unavailable"

    def reject(self, reason):
        self.counters["transport_rejections"] += 1
        try:
            if self.active() and self.ledger.verify().records < MAX_RECORDS:
                self.ledger.append_event("transport_rejected", {"reason": reason, "run_id": self.run_id})
        except Exception:
            self.counters["audit_failures"] += 1
            self.stopped = True
        return 400, b"bad request"

    def report(self):
        v = self.ledger.verify()
        records = [json.loads(x) for x in self.ledger.path.read_text().splitlines()]
        evaluations = [x for x in records if x.get("record_type") == "action_evaluation"]
        totals = {k: sum(e["decision"] == k for e in evaluations) for k in ("ALLOW", "DENY", "ESCALATE", "SANDBOX")}
        return {"schema": "bull-honeypot-v1", "run_id": self.run_id,
            "active": self.active() and v.valid, "mode": "live-listener",
            "scope": "policy-gated synthetic HTTP assets; no process execution or KVM",
            "remaining_seconds": max(0, int(self.deadline - time.monotonic())),
            "audit": asdict(v), "external_anchor": False,
            "counts": totals, "counters_since_start": self.counters,
            "events": records[-200:], "total_evaluations": len(evaluations),
            "attribution": "Traffic does not establish AI-agent or botnet identity.",
            "capture_limits": {"body_bytes": MAX_BODY, "retained_body_prefix": 2048,
                "records": MAX_RECORDS, "recent_events": 200}}


async def read_request(reader):
    raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=3)
    if len(raw) > MAX_HEADER:
        raise ValueError("headers too large")
    lines = raw[:-4].split(b"\r\n")
    method, target, version = lines[0].decode("ascii").split(" ")
    if version not in ("HTTP/1.0", "HTTP/1.1") or len(target) > 2048 or not target.startswith("/"):
        raise ValueError("invalid request line")
    if any(ord(c) < 33 or ord(c) > 126 for c in target) or not method.isalpha():
        raise ValueError("invalid request line")
    headers = {}
    for line in lines[1:]:
        k, v = line.decode("latin1").split(":", 1)
        if k != k.strip() or not k or k.lower() in headers:
            raise ValueError("ambiguous headers")
        headers[k.lower()] = v.strip()
    if "transfer-encoding" in headers or "expect" in headers:
        raise ValueError("unsupported framing")
    length = headers.get("content-length", "0")
    if not length.isascii() or not length.isdecimal() or int(length) > MAX_BODY:
        raise ValueError("body budget")
    body = await asyncio.wait_for(reader.readexactly(int(length)), timeout=3)
    return method, target, headers, body


async def serve(state, duration):
    sensor = Sensor(state, duration=duration)
    token = (state / "observer.token").read_text().strip()
    if len(token) < 40:
        raise ValueError("observer token must be at least 40 characters")
    dashboard = Path(__file__).with_name("dashboard.html").read_bytes()
    active = {False: 0, True: 0}

    async def handle(reader, writer, observer=False):
        if active[observer] >= (4 if observer else 12):
            sensor.counters["transport_rejections"] += 1
            writer.close()
            return
        active[observer] += 1
        mime = "text/plain; charset=utf-8"
        try:
            try:
                method, target, headers, body = await read_request(reader)
                if observer:
                    if method == "GET" and target == "/":
                        status, data, mime = 200, dashboard, "text/html; charset=utf-8"
                    elif method != "GET" or not hmac.compare_digest(headers.get("authorization", ""), "Bearer " + token):
                        status, data = 401, b"unauthorized"
                    elif target == "/api/events":
                        status, data, mime = 200, json.dumps(sensor.report()).encode(), "application/json"
                    else:
                        status, data = 404, b"not found"
                else:
                    status, data = sensor.process(method, target, headers, body)
                    if method == "HEAD":
                        data = b""
            except (ValueError, UnicodeError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                status, data = (400, b"bad request") if observer else sensor.reject("invalid_or_incomplete_http")
            except Exception:
                sensor.stopped = True
                status, data = 503, b"unavailable"
            reason = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 503: "Unavailable"}[status]
            prefix = (f"HTTP/1.1 {status} {reason}\r\nContent-Length: {len(data)}\r\nContent-Type: {mime}\r\n"
                      "Connection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                      "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'self'\r\n\r\n")
            writer.write(prefix.encode() + data)
            await asyncio.wait_for(writer.drain(), timeout=3)
        except (ConnectionError, asyncio.TimeoutError):
            sensor.counters["delivery_failures"] += 1
        finally:
            active[observer] -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    servers = []
    for name, observer in (("capture.sock", False), ("observer.sock", True)):
        path = state / name
        path.unlink(missing_ok=True)
        server = await asyncio.start_unix_server(
            lambda r, w, o=observer: handle(r, w, o), path=str(path), limit=MAX_HEADER)
        os.chmod(path, 0o600)
        servers.append(server)
    async with servers[0], servers[1]:
        await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--duration", type=int, default=3600)
    args = parser.parse_args()
    if not 60 <= args.duration <= 7200:
        parser.error("duration must be 60–7200 seconds")
    asyncio.run(serve(args.state, args.duration))

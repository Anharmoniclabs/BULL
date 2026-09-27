#!/usr/bin/env python3
"""Disposable network-namespace probe for BULL's nftables egress recipe.

No host nftables table is installed. Requires sudo permission to create a
network namespace, plus nft, ip, and an unprivileged nobody account. The lab
substitutes nobody for bullgw in a temporary rules copy; that difference is
recorded and cannot qualify the installed guest service/UID.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import pwd
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import shutil

ROOT = Path(__file__).resolve().parents[1]


def request(host: str, port: int, head: bytes) -> bytes:
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(head)
        chunks = []
        while True:
            block = sock.recv(4096)
            if not block:
                return b"".join(chunks)
            chunks.append(block)


def inside() -> int:
    if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("refusing to apply nftables rules in the host network namespace")
    sys.path.insert(0, str(ROOT / "src"))
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    nobody = pwd.getpwnam("nobody")
    if nobody.pw_uid == 0:
        raise RuntimeError("nobody must be unprivileged")
    rules = (ROOT / "deploy/egress_redirect.nft").read_text().replace('"bullgw"', str(nobody.pw_uid))
    if '"bullgw"' in rules or "meta skuid " + str(nobody.pw_uid) not in rules:
        raise RuntimeError("unexpected nft UID rule")
    with tempfile.TemporaryDirectory(prefix="bull-egress-netns-") as scratch:
        # A clean git worktree created by mktemp is owner-only. The gateway
        # intentionally runs as an unprivileged UID, so stage read-only public
        # modules in this namespace's temporary directory for its import.
        stage = Path(scratch) / "src"
        shutil.copytree(ROOT / "src/bulldog", stage / "bulldog",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        Path(scratch).chmod(0o755)
        for path in (stage, *stage.rglob("*")):
            path.chmod(0o755 if path.is_dir() else 0o644)
        file = Path(scratch) / "rules.nft"
        file.write_text(rules)
        subprocess.run(["nft", "-c", "-f", str(file)], check=True)
        subprocess.run(["nft", "-f", str(file)], check=True)

        class Origin(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"BULL-EGRESS-ALLOWED"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        origin = HTTPServer(("127.0.0.1", 18081), Origin)
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        # The recipe deliberately permits other loopback services. Create an
        # on-link, non-local destination so output uses veth0, not lo. A lab
        # counter before the default DROP proves that this traffic reached the
        # filter without adding an ACCEPT or changing the production verdict.
        subprocess.run(["ip", "link", "add", "veth0", "type", "veth", "peer", "name", "veth1"], check=True)
        subprocess.run(["ip", "addr", "add", "198.18.0.1/30", "dev", "veth0"], check=True)
        subprocess.run(["ip", "link", "set", "veth0", "up"], check=True)
        subprocess.run(["ip", "link", "set", "veth1", "up"], check=True)
        subprocess.run(["ip", "-6", "addr", "add", "2001:db8:42::1/64", "dev", "veth0"], check=True)
        route = subprocess.check_output(["ip", "route", "get", "198.18.0.2"], text=True)
        if " dev veth0 " not in route:
            raise RuntimeError("alternate-port target did not route off loopback")
        route6 = subprocess.check_output(["ip", "-6", "route", "get", "2001:db8:42::2"], text=True)
        if " dev veth0 " not in route6:
            raise RuntimeError("IPv6 alternate-port target did not route off loopback")
        subprocess.run(["nft", "add", "rule", "inet", "bull_egress", "filter_output",
                        "ip", "daddr", "198.18.0.2", "tcp", "dport", "81", "counter"], check=True)
        subprocess.run(["nft", "add", "rule", "inet", "bull_egress", "filter_output",
                        "ip6", "daddr", "2001:db8:42::2", "tcp", "dport", "81", "counter"], check=True)
        runner = """import asyncio
from bulldog.egress_gateway import EgressGateway,EgressPolicy,GatewayConfig
async def main():
 g=EgressGateway(EgressPolicy({'allowed.test':{'methods':['GET'],'paths':['/ok']}}),GatewayConfig(resolver=lambda h:('127.0.0.1',18081)))
 await g.start()
 await asyncio.Event().wait()
asyncio.run(main())"""

        def drop_privileges():
            os.setgroups([])
            os.setgid(nobody.pw_gid)
            os.setuid(nobody.pw_uid)

        gateway = subprocess.Popen([sys.executable, "-c", runner], cwd=stage,
                                   env=dict(os.environ, PYTHONPATH=str(stage)),
                                   preexec_fn=drop_privileges, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, start_new_session=True)
        checks = {}
        try:
            for _ in range(40):
                if gateway.poll() is not None:
                    reason = gateway.stderr.read(1500).decode("utf-8", "replace") if gateway.stderr else ""
                    raise RuntimeError("gateway exited before readiness: " + reason[-1200:])
                try:
                    with socket.create_connection(("127.0.0.1", 9443), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("gateway did not listen")
            allowed = request("127.0.0.1", 80, b"GET /ok HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n")
            checks["http_allowed_redirect"] = b"200 OK" in allowed and b"BULL-EGRESS-ALLOWED" in allowed
            denied = request("127.0.0.1", 80, b"GET /ok HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n")
            checks["http_denied_redirect"] = b"403 Forbidden" in denied
            try:
                request("198.18.0.2", 81, b"GET / HTTP/1.0\r\n\r\n")
                alternate_connected = True
            except OSError:
                alternate_connected = False
            chain = subprocess.check_output(["nft", "list", "chain", "inet", "bull_egress", "filter_output"], text=True)
            counted = re.search(r"ip daddr 198\.18\.0\.2 tcp dport 81 counter packets (\d+)", chain)
            checks["alternate_tcp_dropped"] = (not alternate_connected and "policy drop;" in chain
                                                and counted is not None and int(counted.group(1)) > 0)
            try:
                request("2001:db8:42::2", 81, b"GET / HTTP/1.0\r\n\r\n")
                ipv6_connected = True
            except OSError:
                ipv6_connected = False
            chain = subprocess.check_output(["nft", "list", "chain", "inet", "bull_egress", "filter_output"], text=True)
            counted6 = re.search(r"ip6 daddr 2001:db8:42::2 tcp dport 81 counter packets (\d+)", chain)
            checks["ipv6_alternate_dropped"] = (not ipv6_connected and "policy drop;" in chain
                                                and counted6 is not None and int(counted6.group(1)) > 0)
            # IPv6 port 80 is redirected by the inet rules, but this gateway
            # listens on IPv4 loopback only. Until dual-stack authorization is
            # implemented, IPv6 web traffic must stay closed.
            try:
                request("2001:db8:42::2", 80, b"GET / HTTP/1.0\r\nHost: allowed.test\r\n\r\n")
                ipv6_web_connected = True
            except OSError:
                ipv6_web_connected = False
            checks["ipv6_web_closed"] = not ipv6_web_connected
            query = bytes.fromhex("123401000001000000000000") + b"\x04evil\x04test\x00\x00\x01\x00\x01"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(2)
                udp.sendto(query, ("127.0.0.1", 53))
                response, _ = udp.recvfrom(512)
            checks["dns_denied_redirect"] = response[:2] == query[:2] and response[3] & 15 == 5
            gateway.terminate()
            gateway.wait(timeout=5)
            try:
                request("127.0.0.1", 80, b"GET /ok HTTP/1.0\r\nHost: allowed.test\r\n\r\n")
                checks["gateway_down_closed"] = False
            except OSError:
                checks["gateway_down_closed"] = True
            gateway = subprocess.Popen([sys.executable, "-c", runner], cwd=stage,
                                       env=dict(os.environ, PYTHONPATH=str(stage)),
                                       preexec_fn=drop_privileges, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.PIPE, start_new_session=True)
            for _ in range(40):
                if gateway.poll() is not None:
                    raise RuntimeError("gateway exited during restart")
                try:
                    with socket.create_connection(("127.0.0.1", 9443), timeout=.1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("gateway did not restart")
            again = request("127.0.0.1", 80, b"GET /ok HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n")
            checks["restart_still_denies"] = b"403 Forbidden" in again
        finally:
            if gateway.poll() is None:
                gateway.terminate()
                gateway.wait(timeout=5)
            origin.shutdown()
            origin.server_close()
        result = {"status": "PASS" if all(checks.values()) else "FAIL", "checks": checks,
                  "scope": "disposable dual-stack namespace; UID substituted for bullgw; no deployed guest/systemd service proof"}
        print(json.dumps(result), flush=True)
        return 0 if result["status"] == "PASS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--install-deps", action="store_true")
    args = parser.parse_args()
    if args.inside:
        return inside()
    missing = [name for name in ("sudo", "unshare", "ip", "nft") if not shutil.which(name)]
    if missing and args.install_deps:
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "-y", "nftables", "iproute2", "util-linux"], check=True)
        missing = [name for name in ("sudo", "unshare", "ip", "nft") if not shutil.which(name)]
    if missing:
        print(json.dumps({"status": "BLOCKED", "reason": "missing commands: " + ", ".join(missing)}))
        return 1
    command = ["sudo", "-n", "unshare", "--net", "--fork", sys.executable, str(Path(__file__).resolve()), "--inside"]
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=90)
    if result.stdout:
        print(result.stdout, end="")
    if result.returncode and (result.stderr or not result.stdout):
        print(json.dumps({"status": "BLOCKED_OR_FAIL", "reason": result.stderr[-1000:],
                          "scope": "no host nftables changes; isolated namespace only"}))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())

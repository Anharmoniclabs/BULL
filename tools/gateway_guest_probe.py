#!/usr/bin/env python3
"""Run only inside the disposable KVM gateway lab guest."""
import json
import os
import re
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


def command(*args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{args[0]} {args[1:]} exited {exc.returncode}: {exc.output[-500:]}") from exc


def request(host, port, payload):
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as exc:
        raise OSError(f"connect {host}:{port}: {exc}") from exc
    with sock:
        sock.settimeout(5)
        sock.sendall(payload)
        result = bytearray()
        while True:
            try:
                part = sock.recv(4096)
            except OSError as exc:
                raise OSError(f"receive {host}:{port} after {len(result)} bytes: {exc}") from exc
            if not part:
                return bytes(result)
            result.extend(part)


def closed(host, port, payload):
    try:
        request(host, port, payload)
    except OSError:
        return True
    return False


def gateway():
    return subprocess.Popen(
        ["/usr/bin/setpriv", "--reuid=23456", "--regid=23456", "--clear-groups",
         "/usr/bin/env", "PYTHONPATH=/opt/bull/src", "/usr/bin/python3",
         "-m", "bulldog.run_egress_gateway", "--policy", "/etc/bull/egress_policy.json"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def ready(process):
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError("gateway exited: " + process.stderr.read(1200).decode("utf-8", "replace"))
        try:
            with socket.create_connection(("127.0.0.1", 9443), timeout=.1):
                return
        except OSError:
            time.sleep(.1)
    raise RuntimeError("gateway did not listen")


def main():
    phase = "initialize"
    if os.getpid() == 1 or not os.path.exists("/proc/1/cmdline"):
        raise RuntimeError("guest initialization incomplete")
    command("/usr/sbin/ip", "link", "set", "lo", "up")
    devices = sorted(set(os.listdir("/sys/class/net")) - {"lo"})
    if len(devices) != 1:
        raise RuntimeError("expected one guest NIC, saw " + repr(devices))
    nic = devices[0]
    command("/usr/sbin/ip", "link", "set", nic, "up")
    command("/usr/sbin/ip", "addr", "add", "10.0.2.15/24", "dev", nic)
    command("/usr/sbin/ip", "-6", "addr", "add", "2001:db8:42::1/64", "dev", nic)
    if f" dev {nic} " not in command("/usr/sbin/ip", "route", "get", "10.0.2.2"):
        raise RuntimeError("IPv4 target not routed through guest NIC")
    if f" dev {nic} " not in command("/usr/sbin/ip", "-6", "route", "get", "2001:db8:42::2"):
        raise RuntimeError("IPv6 target not routed through guest NIC")

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            data = b"BULL-GUEST-ORIGIN"
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_args):
            pass

    origin = HTTPServer(("127.0.0.1", 443), Origin)
    Thread(target=origin.serve_forever, daemon=True).start()
    checks = {}
    process = None
    try:
        phase = "install nftables rules"
        command("/usr/sbin/nft", "-c", "-f", "/etc/bull/egress_redirect.nft")
        command("/usr/sbin/nft", "-f", "/etc/bull/egress_redirect.nft")
        command("/usr/sbin/nft", "add", "rule", "inet", "bull_egress", "filter_output",
                "ip", "daddr", "10.0.2.2", "tcp", "dport", "81", "counter")
        command("/usr/sbin/nft", "add", "rule", "inet", "bull_egress", "filter_output",
                "ip6", "daddr", "2001:db8:42::2", "tcp", "dport", "81", "counter")
        # Counter-only lab rules. They do not alter the deployed rule verdicts.
        command("/usr/sbin/nft", "insert", "rule", "inet", "bull_egress", "redirect_output",
                "ip", "daddr", "10.0.2.2", "tcp", "dport", "80", "counter")
        command("/usr/sbin/nft", "insert", "rule", "inet", "bull_egress", "filter_output",
                "oifname", "lo", "tcp", "dport", "9443", "counter")
        command("/usr/sbin/nft", "insert", "rule", "inet", "bull_egress", "filter_output",
                "tcp", "dport", "9443", "counter")
        command("/usr/bin/setpriv", "--reuid=23456", "--regid=23456", "--clear-groups",
                "/usr/bin/env", "PYTHONPATH=/opt/bull/src", "/usr/bin/python3", "-c",
                "import bulldog.run_egress_gateway")
        phase = "start gateway"
        process = gateway()
        ready(process)
        checks["gateway_uid"] = int(command("/usr/bin/id", "-u", "bullgw").strip()) == 23456 and \
            int(open(f"/proc/{process.pid}/status").read().split("Uid:", 1)[1].split()[0]) == 23456
        allowed_payload = b"GET /ok HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n"
        phase = "direct gateway HTTP relay"
        direct = request("127.0.0.1", 9443, allowed_payload)
        checks["direct_gateway_http"] = b"200 OK" in direct and b"BULL-GUEST-ORIGIN" in direct
        phase = "allowed HTTP redirect"
        allowed = request("10.0.2.2", 80, allowed_payload)
        checks["allowed_http"] = b"200 OK" in allowed and b"BULL-GUEST-ORIGIN" in allowed
        phase = "denied HTTP redirect"
        denied = request("10.0.2.2", 80, b"GET /ok HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n")
        checks["denied_http"] = b"403 Forbidden" in denied
        phase = "alternate IPv4 and IPv6 drops"
        checks["ipv4_alt_closed"] = closed("10.0.2.2", 81, b"GET / HTTP/1.0\r\n\r\n")
        checks["ipv6_alt_closed"] = closed("2001:db8:42::2", 81, b"GET / HTTP/1.0\r\n\r\n")
        checks["ipv6_web_closed"] = closed("2001:db8:42::2", 80, b"GET / HTTP/1.0\r\n\r\n")
        chain = command("/usr/sbin/nft", "list", "chain", "inet", "bull_egress", "filter_output")
        count4 = re.search(r"ip daddr 10\.0\.2\.2 tcp dport 81 counter packets (\d+)", chain)
        count6 = re.search(r"ip6 daddr 2001:db8:42::2 tcp dport 81 counter packets (\d+)", chain)
        checks["filter_drop_counters"] = ("policy drop;" in chain and count4 is not None
                                          and count6 is not None and int(count4.group(1)) > 0
                                          and int(count6.group(1)) > 0)
        phase = "denied DNS redirect"
        query = bytes.fromhex("123401000001000000000000") + b"\x06denied\x04test\x00\x00\x01\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(2)
            udp.sendto(query, ("10.0.2.2", 53))
            answer, _ = udp.recvfrom(512)
        checks["denied_dns"] = answer[:2] == query[:2] and answer[3] & 15 == 5
        phase = "gateway-down closure"
        process.terminate()
        process.wait(timeout=5)
        checks["gateway_down_closed"] = closed("10.0.2.2", 80, b"GET / HTTP/1.0\r\n\r\n")
        phase = "restart gateway and deny"
        process = gateway()
        ready(process)
        denied = request("10.0.2.2", 80, b"GET /ok HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n")
        checks["restart_still_denies"] = b"403 Forbidden" in denied
    except Exception as exc:
        counters = {}
        if phase == "allowed HTTP redirect":
            for chain in ("redirect_output", "filter_output"):
                try:
                    rules = command("/usr/sbin/nft", "list", "chain", "inet", "bull_egress", chain)
                    counters[chain] = re.findall(r"(?:ip daddr 10\.0\.2\.2 tcp dport 80|oifname \"?lo\"? tcp dport 9443|tcp dport 9443) counter packets (\d+)", rules)
                except Exception:
                    counters[chain] = "unavailable"
        raise RuntimeError(f"{phase}: {type(exc).__name__}: {exc}; completed_checks={checks}; counters={counters}") from exc
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        origin.shutdown()
        origin.server_close()
    print("BULL_GATEWAY_KVM_RESULT=" + json.dumps({
        "status": "PASS" if checks and all(checks.values()) else "FAIL", "checks": checks, "guest_nic": nic,
        "scope": "disposable Debian KVM lab guest, restricted QEMU user networking; direct init startup, no systemd or production image"
    }, sort_keys=True), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("BULL_GATEWAY_KVM_RESULT=" + json.dumps({"status": "FAIL", "reason": type(exc).__name__ + ": " + str(exc)[:500]}), flush=True)
        raise

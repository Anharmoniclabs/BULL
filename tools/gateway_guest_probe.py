#!/usr/bin/env python3
"""Run only inside the disposable KVM gateway lab guest."""

import base64
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
        return subprocess.check_output(
            args, text=True, stderr=subprocess.STDOUT, timeout=10
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"{args[0]} {args[1:]} exited {exc.returncode}: {exc.output[-500:]}"
        ) from exc


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
                raise OSError(
                    f"receive {host}:{port} after {len(result)} bytes: {exc}"
                ) from exc
            if not part:
                return bytes(result)
            result.extend(part)


def closed(host, port, payload):
    try:
        request(host, port, payload)
    except OSError:
        return True
    return False


def agent_request(host, port, payload, *, timeout=5):
    """Make the network attempt as the dedicated untrusted workload UID."""
    program = """import base64,socket,sys
h,p,t,b=sys.argv[1],int(sys.argv[2]),float(sys.argv[3]),base64.b64decode(sys.argv[4])
s=socket.create_connection((h,p),timeout=t);s.settimeout(t);s.sendall(b);out=bytearray()
while True:
 x=s.recv(4096)
 if not x: break
 out.extend(x)
s.close();sys.stdout.buffer.write(base64.b64encode(bytes(out)))
"""
    result = subprocess.run(
        [
            "/usr/bin/setpriv",
            "--reuid=23457",
            "--regid=23457",
            "--clear-groups",
            "/usr/bin/python3",
            "-c",
            program,
            host,
            str(port),
            str(timeout),
            base64.b64encode(payload).decode("ascii"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout + 2,
    )
    if result.returncode != 0:
        raise OSError(result.stderr.decode("utf-8", "replace")[-500:])
    return base64.b64decode(result.stdout, validate=True)


def agent_closed(host, port, payload):
    try:
        agent_request(host, port, payload, timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return True
    return False


def gateway():
    return subprocess.Popen(
        [
            "/usr/bin/setpriv",
            "--reuid=23456",
            "--regid=23456",
            "--clear-groups",
            "/usr/bin/env",
            "PYTHONPATH=/opt/bull/src",
            "/usr/bin/python3",
            "-m",
            "bulldog.run_egress_gateway",
            "--policy",
            "/etc/bull/egress_policy.json",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )


def ready(process):
    for _ in range(80):
        if process.poll() is not None:
            raise RuntimeError(
                "gateway exited: "
                + process.stderr.read(1200).decode("utf-8", "replace")
            )
        try:
            with socket.create_connection(("127.0.0.1", 9443), timeout=0.1):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("gateway did not listen")


def service_ready():
    for _ in range(80):
        active = (
            subprocess.run(
                [
                    "/usr/bin/systemctl",
                    "is-active",
                    "--quiet",
                    "bull-egress-gateway.service",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).returncode
            == 0
        )
        if active:
            try:
                with socket.create_connection(("127.0.0.1", 9443), timeout=0.1):
                    return
            except OSError:
                pass
        time.sleep(0.1)
    raise RuntimeError("systemd gateway service did not listen")


def main():
    phase = "initialize"
    systemd = "--systemd" in sys.argv[1:]
    if systemd:
        print("BULL_GATEWAY_KVM_PHASE=probe_started", flush=True)
    if os.getpid() == 1 or not os.path.exists("/proc/1/cmdline"):
        raise RuntimeError("guest initialization incomplete")
    if systemd:
        if not os.path.exists("/run/systemd/system"):
            raise RuntimeError("systemd was not started as guest init")
        if (
            command(
                "/usr/bin/systemctl", "is-active", "bull-egress-redirect.service"
            ).strip()
            != "active"
        ):
            raise RuntimeError("systemd redirect unit inactive")
    else:
        command("/usr/sbin/ip", "link", "set", "lo", "up")
    devices = sorted(set(os.listdir("/sys/class/net")) - {"lo"})
    if len(devices) != 1:
        raise RuntimeError("expected one guest NIC, saw " + repr(devices))
    nic = devices[0]
    if not systemd:
        command("/usr/sbin/ip", "link", "set", nic, "up")
        command("/usr/sbin/ip", "addr", "add", "10.0.2.15/24", "dev", nic)
        command("/usr/sbin/ip", "-6", "addr", "add", "2001:db8:42::1/64", "dev", nic)
    if f" dev {nic} " not in command("/usr/sbin/ip", "route", "get", "10.0.2.2"):
        raise RuntimeError("IPv4 target not routed through guest NIC")
    if f" dev {nic} " not in command(
        "/usr/sbin/ip", "-6", "route", "get", "2001:db8:42::2"
    ):
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
        if not systemd:
            command("/usr/sbin/nft", "-f", "/etc/bull/egress_redirect.nft")
        command(
            "/usr/sbin/nft",
            "add",
            "rule",
            "inet",
            "bull_egress",
            "filter_output",
            "ip",
            "daddr",
            "10.0.2.2",
            "tcp",
            "dport",
            "81",
            "counter",
        )
        command(
            "/usr/sbin/nft",
            "add",
            "rule",
            "inet",
            "bull_egress",
            "filter_output",
            "ip6",
            "daddr",
            "2001:db8:42::2",
            "tcp",
            "dport",
            "81",
            "counter",
        )
        # Counter-only lab rules. They do not alter the deployed rule verdicts.
        command(
            "/usr/sbin/nft",
            "insert",
            "rule",
            "inet",
            "bull_egress",
            "redirect_output",
            "ip",
            "daddr",
            "10.0.2.2",
            "tcp",
            "dport",
            "80",
            "counter",
        )
        command(
            "/usr/sbin/nft",
            "insert",
            "rule",
            "inet",
            "bull_egress",
            "filter_output",
            "oifname",
            "lo",
            "tcp",
            "dport",
            "9443",
            "counter",
        )
        command(
            "/usr/sbin/nft",
            "insert",
            "rule",
            "inet",
            "bull_egress",
            "filter_output",
            "tcp",
            "dport",
            "9443",
            "counter",
        )
        command(
            "/usr/bin/setpriv",
            "--reuid=23456",
            "--regid=23456",
            "--clear-groups",
            "/usr/bin/env",
            "PYTHONPATH=/opt/bull/src",
            "/usr/bin/python3",
            "-c",
            "import bulldog.run_egress_gateway",
        )
        phase = "start gateway"
        if systemd:
            service_ready()
            print("BULL_GATEWAY_KVM_PHASE=gateway_ready", flush=True)
            pid = int(
                command(
                    "/usr/bin/systemctl",
                    "show",
                    "-p",
                    "MainPID",
                    "--value",
                    "bull-egress-gateway.service",
                ).strip()
            )
        else:
            process = gateway()
            ready(process)
            pid = process.pid
        checks["gateway_uid"] = (
            pid > 1
            and int(command("/usr/bin/id", "-u", "bullgw").strip()) == 23456
            and int(open(f"/proc/{pid}/status").read().split("Uid:", 1)[1].split()[0])
            == 23456
        )
        checks["agent_workload_uid"] = (
            int(command("/usr/bin/id", "-u", "bullagent").strip()) == 23457
        )
        if systemd:
            checks["service_units_active"] = (
                command(
                    "/usr/bin/systemctl", "is-active", "bull-egress-gateway.service"
                ).strip()
                == "active"
                and command(
                    "/usr/bin/systemctl", "is-enabled", "bull-egress-gateway.service"
                ).strip()
                == "enabled"
                and command(
                    "/usr/bin/systemctl", "is-enabled", "bull-egress-redirect.service"
                ).strip()
                == "enabled"
            )
        allowed_payload = (
            b"GET /ok HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n"
        )
        phase = "direct gateway HTTP relay"
        direct = request("127.0.0.1", 9443, allowed_payload)
        checks["direct_gateway_http"] = (
            b"200 OK" in direct and b"BULL-GUEST-ORIGIN" in direct
        )
        phase = "allowed HTTP redirect"
        allowed = agent_request("10.0.2.2", 80, allowed_payload)
        checks["allowed_http"] = (
            b"200 OK" in allowed and b"BULL-GUEST-ORIGIN" in allowed
        )
        phase = "denied HTTP redirect"
        denied = agent_request(
            "10.0.2.2",
            80,
            b"GET /ok HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        )
        checks["denied_http"] = b"403 Forbidden" in denied
        phase = "alternate IPv4 and IPv6 drops"
        checks["ipv4_alt_closed"] = agent_closed(
            "10.0.2.2", 81, b"GET / HTTP/1.0\r\n\r\n"
        )
        checks["ipv6_alt_closed"] = agent_closed(
            "2001:db8:42::2", 81, b"GET / HTTP/1.0\r\n\r\n"
        )
        checks["ipv6_web_closed"] = agent_closed(
            "2001:db8:42::2", 80, b"GET / HTTP/1.0\r\n\r\n"
        )
        chain = command(
            "/usr/sbin/nft", "list", "chain", "inet", "bull_egress", "filter_output"
        )
        count4 = re.search(
            r"ip daddr 10\.0\.2\.2 tcp dport 81 counter packets (\d+)", chain
        )
        count6 = re.search(
            r"ip6 daddr 2001:db8:42::2 tcp dport 81 counter packets (\d+)", chain
        )
        checks["filter_drop_counters"] = (
            "policy drop;" in chain
            and count4 is not None
            and count6 is not None
            and int(count4.group(1)) > 0
            and int(count6.group(1)) > 0
        )
        phase = "denied DNS redirect"
        query = (
            bytes.fromhex("123401000001000000000000")
            + b"\x06denied\x04test\x00\x00\x01\x00\x01"
        )
        dns_program = """import base64,socket,sys
q=base64.b64decode(sys.argv[1]);s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2)
s.sendto(q,('10.0.2.2',53));a,_=s.recvfrom(512);sys.stdout.buffer.write(base64.b64encode(a))
"""
        dns = subprocess.run(
            [
                "/usr/bin/setpriv",
                "--reuid=23457",
                "--regid=23457",
                "--clear-groups",
                "/usr/bin/python3",
                "-c",
                dns_program,
                base64.b64encode(query).decode("ascii"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=True,
        )
        answer = base64.b64decode(dns.stdout, validate=True)
        checks["denied_dns"] = answer[:2] == query[:2] and answer[3] & 15 == 5
        phase = "gateway-down closure"
        if systemd:
            print("BULL_GATEWAY_KVM_PHASE=stopping_gateway", flush=True)
            command("/usr/bin/systemctl", "stop", "bull-egress-gateway.service")
        else:
            process.terminate()
            process.wait(timeout=5)
        checks["gateway_down_closed"] = agent_closed(
            "10.0.2.2", 80, b"GET / HTTP/1.0\r\n\r\n"
        )
        phase = "restart gateway and deny"
        if systemd:
            command("/usr/bin/systemctl", "start", "bull-egress-gateway.service")
            service_ready()
            print("BULL_GATEWAY_KVM_PHASE=gateway_restarted", flush=True)
        else:
            process = gateway()
            ready(process)
        denied = agent_request(
            "10.0.2.2",
            80,
            b"GET /ok HTTP/1.1\r\nHost: denied.test\r\nConnection: close\r\n\r\n",
        )
        checks["restart_still_denies"] = b"403 Forbidden" in denied
    except Exception as exc:
        counters = {}
        if phase == "allowed HTTP redirect":
            for chain in ("redirect_output", "filter_output"):
                try:
                    rules = command(
                        "/usr/sbin/nft", "list", "chain", "inet", "bull_egress", chain
                    )
                    counters[chain] = re.findall(
                        r"(?:ip daddr 10\.0\.2\.2 tcp dport 80|oifname \"?lo\"? tcp dport 9443|tcp dport 9443) counter packets (\d+)",
                        rules,
                    )
                except Exception:
                    counters[chain] = "unavailable"
        raise RuntimeError(
            f"{phase}: {type(exc).__name__}: {exc}; completed_checks={checks}; counters={counters}"
        ) from exc
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
        origin.shutdown()
        origin.server_close()
    print(
        "BULL_GATEWAY_KVM_RESULT="
        + json.dumps(
            {
                "status": "PASS" if checks and all(checks.values()) else "FAIL",
                "checks": checks,
                "guest_nic": nic,
                "scope": (
                    "disposable Debian KVM candidate with actual systemd gateway and redirect units; not pinned production image"
                    if systemd
                    else "disposable Debian KVM lab guest, restricted QEMU user networking; direct init startup, no systemd or production image"
                ),
            },
            sort_keys=True,
        ),
        flush=True,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            "BULL_GATEWAY_KVM_RESULT="
            + json.dumps(
                {"status": "FAIL", "reason": type(exc).__name__ + ": " + str(exc)[:500]}
            ),
            flush=True,
        )
        raise

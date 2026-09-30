#!/usr/bin/env python3
"""Loopback gRPC/destination qualification and durable ledger scaling.

This observes BULL's protocol boundary; it is not the native NVIDIA supervisor.
The local OpenShell layer records are explicit contract fixtures, named as such.
"""
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import argparse
import json
from pathlib import Path
import platform
import secrets
import shutil
import statistics
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import grpc
from bulldog.audit import AuditLedger
from bulldog.models import Capability
from bulldog.openshell.authority import OpenShellAuthority
from bulldog.openshell.ocsf import correlate_exact
from bulldog.openshell.services import BullMiddleware
from bulldog.openshell._proto import supervisor_middleware_pb2 as mw
from bulldog.openshell._proto import supervisor_middleware_pb2_grpc as rpc


def scaling(out, sizes):
    # Preserve every fsync/checkpoint/anchor operation; no I/O mocks or batching.
    key = secrets.token_bytes(32)
    ledger = AuditLedger(out / "scaling-ledger.jsonl", anchor_path=out / "scaling.anchor",
                         anchor_key=key, max_ledger_bytes=2 * 1024**3)
    rows, previous = [], 0
    started = time.monotonic()
    for size in sizes:
        samples = []
        for i in range(previous, size):
            begin = time.perf_counter()
            ledger.append_event("scale", {"i": i})
            if i >= size - min(300, size - previous):
                samples.append((time.perf_counter() - begin) * 1000)
        row = {"records": size, "sample_count": len(samples),
               "append_p50_ms": statistics.median(samples),
               "append_p95_ms": sorted(samples)[int(.95 * (len(samples)-1))],
               "full_verifications_during_append": ledger.full_verifications,
               "elapsed_seconds": time.monotonic() - started,
               "bytes": ledger.path.stat().st_size}
        rows.append(row)
        print(json.dumps({"scaling": row}), flush=True)
        (out / "scaling-progress.json").write_text(json.dumps(rows, indent=2)+"\n")
        previous = size
    before = time.monotonic(); verified = ledger.verify()
    return {"rows": rows, "final_verification": vars(verified),
            "final_verification_seconds": time.monotonic() - before,
            "scope": "single persistent writer; real fsync plus authenticated local checkpoint"}


def concurrent_requests(out, count, workers):
    receipts, events, effects_lock = [], [], threading.Lock()
    class Destination(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            body = self.rfile.read(int(self.headers['content-length']))
            with effects_lock:
                receipts.append({"request_id": self.headers.get("X-BULL-Request-ID"),
                                 "decision_id": self.headers.get("X-BULL-Decision-ID"),
                                 "action_digest": self.headers.get("X-BULL-Action-Digest"),
                                 "sandbox_id": "sandbox-fixed", "body": body.decode()})
            self.send_response(200); self.send_header("Content-Length", "2")
            self.end_headers(); self.wfile.write(b"ok")
    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)
    threading.Thread(target=destination.serve_forever, daemon=True).start()
    grants = {"format": "bull-openshell-grants-v1", "host_ceiling": ["127.0.0.1"],
              "sandboxes": {"coder": {"capabilities": ["network.post"], "trusted_sources": []}}}
    ledger = AuditLedger(out / "concurrency-ledger.jsonl", anchor_path=out / "concurrency.anchor",
                         anchor_key=secrets.token_bytes(32))
    authority = OpenShellAuthority(grants, frozenset({Capability.NETWORK_POST}), ledger=ledger,
                                   state_path=out / "authority-state.json")
    service = BullMiddleware(authority, timeout=10, capacity=workers)
    server = grpc.server(ThreadPoolExecutor(max_workers=workers))
    rpc.add_SupervisorMiddlewareServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0"); server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = rpc.SupervisorMiddlewareStub(channel)
    url = f"http://127.0.0.1:{destination.server_port}/records"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def send(i):
        req = mw.HttpRequestEvaluation(
            context=mw.RequestContext(sandbox="coder", sandbox_id="sandbox-fixed", request_id=f"trusted-{i}"),
            target=mw.HttpRequestTarget(method="POST", scheme="http", host="127.0.0.1",
                                        port=destination.server_port, path="/records"),
            body=b"identical", headers=[mw.HttpHeader(name="X-BULL-Request-ID", value="forged")])
        result = stub.EvaluateHttpRequest(req, timeout=12)
        identity = {"request_id": result.metadata.get("bull_request_id"),
                    "decision_id": result.metadata.get("bull_decision_id"),
                    "action_digest": result.metadata.get("bull_action_digest"),
                    "sandbox_id": "sandbox-fixed"}
        # A deterministic local layer fixture enforces method/path. These are
        # not native OCSF exports, and are labelled accordingly in the result.
        layer_allow = req.target.method == "POST" and req.target.path == "/records"
        with effects_lock:
            events.extend([dict(identity, engine="l7", action="ALLOWED" if layer_allow else "DENIED"),
                           dict(identity, engine="middleware", action="ALLOWED" if result.decision == mw.DECISION_ALLOW else "DENIED")])
        if result.decision == mw.DECISION_ALLOW and layer_allow:
            headers = {m.write.name: m.write.value for m in result.header_mutations if m.HasField("write")}
            with opener.open(urllib.request.Request(url, data=b"identical", headers=headers, method="POST"), timeout=10) as response:
                response.read()
        return result.reason_code
    begin = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            codes = list(pool.map(send, range(count)))
        verification = ledger.verify()
        records = [json.loads(line) for line in ledger.path.read_text().splitlines()]
        correlation = correlate_exact(records, events, receipts)
        (out / "contract-layer-events.jsonl").write_text("".join(json.dumps(e)+"\n" for e in events))
        (out / "destination-receipts.jsonl").write_text("".join(json.dumps(e)+"\n" for e in receipts))
        (out / "exact-correlation.json").write_text(json.dumps(correlation, indent=2)+"\n")
        return {"requests": count, "concurrency": workers, "effects": len(receipts),
                "elapsed_seconds": time.monotonic()-begin, "ledger_verification": vars(verification),
                "correlation": correlation["summary"],
                "reason_codes": {c: codes.count(c) for c in set(codes)},
                "scope": "real BULL gRPC + real loopback HTTP effects; native OpenShell layer is a contract fixture"}
    finally:
        channel.close(); server.stop(0); service.gate.close()
        destination.shutdown(); destination.server_close()


def fault_requests(out):
    """Real RPCs and a loopback destination, including transport loss."""
    from concurrent.futures import TimeoutError
    receipts = []
    class Destination(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            receipts.append(self.headers.get("X-BULL-Request-ID"))
            self.rfile.read(int(self.headers['content-length']))
            self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()
    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)
    threading.Thread(target=destination.serve_forever, daemon=True).start()
    grants = {"format": "bull-openshell-grants-v1", "host_ceiling": ["127.0.0.1"],
              "sandboxes": {"coder": {"capabilities": ["network.post"], "trusted_sources": []}}}
    authority = OpenShellAuthority(grants, frozenset({Capability.NETWORK_POST}),
                                   ledger=AuditLedger(out / "fault-ledger.jsonl"),
                                   state_path=out / "fault-state.json")
    delay, fail = [0], [False]
    original = authority.policy.evaluate
    def inject(action):
        wait = delay[0]; reset = fail[0]
        time.sleep(wait / 1000)
        if reset: raise ConnectionResetError("injected reset")
        return original(action)
    authority.policy.evaluate = inject
    service = BullMiddleware(authority, timeout=.2, capacity=8)
    server = grpc.server(ThreadPoolExecutor(max_workers=8))
    rpc.add_SupervisorMiddlewareServicer_to_server(service, server)
    port = server.add_insecure_port("127.0.0.1:0"); server.start()
    channel = grpc.insecure_channel(f"127.0.0.1:{port}")
    stub = rpc.SupervisorMiddlewareStub(channel)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    rows = []
    def probe(label, rid=None, expected=True, rpc_timeout=1):
        before = len(receipts); begin = time.monotonic()
        req = mw.HttpRequestEvaluation(
            context=mw.RequestContext(sandbox="coder", sandbox_id="fault-sandbox", request_id=rid or label),
            target=mw.HttpRequestTarget(method="POST", scheme="http", host="127.0.0.1",
                                        port=destination.server_port, path="/records"), body=b"identical")
        try:
            result = stub.EvaluateHttpRequest(req, timeout=rpc_timeout)
            code = result.reason_code
            if result.decision == mw.DECISION_ALLOW:
                headers = {m.write.name: m.write.value for m in result.header_mutations if m.HasField("write")}
                with opener.open(urllib.request.Request(
                    f"http://127.0.0.1:{destination.server_port}/records", data=b"identical",
                    headers=headers, method="POST"), timeout=2) as response: response.read()
        except grpc.RpcError as exc:
            code = "grpc_" + exc.code().name.lower()
        elapsed = time.monotonic() - begin
        if delay[0] >= 200: time.sleep(delay[0]/1000+.05)
        hit = len(receipts)-before
        rows.append({"case":label,"reason_code":code,"elapsed_seconds":elapsed,
                     "destination_effects":hit,"pass":hit==int(expected)})
    try:
        for wait in [10,50,100,250,1000,5000]:
            delay[0] = wait; probe("delay_"+str(wait),expected=wait<200)
        delay[0] = 0; fail[0] = True; probe("reset",expected=False)
        fail[0] = False; probe("first_delivery",rid="duplicate")
        probe("duplicate_delivery",rid="duplicate",expected=False)
        delay[0] = 100; probe("short_client_deadline",expected=False,rpc_timeout=.03)
        delay[0] = 0; time.sleep(.15)
        server.stop(0).wait(); probe("authority_down",expected=False)
        return {"cases":rows,"passed":all(r["pass"] for r in rows),
                "scope":"real BULL gRPC, injected policy faults, observed loopback HTTP destination"}
    finally:
        channel.close(); server.stop(0); service.gate.close()
        destination.shutdown(); destination.server_close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--requests", type=int, default=10_000)
    parser.add_argument("--workers", type=int, default=32)
    parser.add_argument("--sizes", default="1000,10000,100000,1000000")
    parser.add_argument("--skip-scaling", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    result = {"source": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "working_tree_modified": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
              "python": platform.python_version(),
              "native_openshell": {"docker": shutil.which("docker"), "openshell": shutil.which("openshell"),
                                   "status": "NOT_RUN"}}
    result["faults"] = fault_requests(args.output)
    print(json.dumps({"faults": result["faults"]}), flush=True)
    result["concurrency"] = concurrent_requests(args.output, args.requests, args.workers)
    print(json.dumps({"concurrency": result["concurrency"]}), flush=True)
    if not args.skip_scaling:
        result["scaling"] = scaling(args.output, [int(s) for s in args.sizes.split(',')])
    result["passed"] = result["faults"]["passed"] and result["concurrency"]["correlation"]["exact"] and result["concurrency"]["ledger_verification"]["valid"]
    if "scaling" in result: result["passed"] &= result["scaling"]["final_verification"]["valid"]
    (args.output / "report.json").write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1
if __name__ == '__main__': raise SystemExit(main())

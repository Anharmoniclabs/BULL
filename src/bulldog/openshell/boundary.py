"""Bounded admission and durable replay rejection outside the agent sandbox.

Workers only compute decisions. They never perform destination effects. A
timed-out caller receives DENY even if a non-cancellable worker later returns
ALLOW. Hung workers retain their slots, so overload becomes explicit denial.
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass
import hashlib
import json
import math
import secrets
import sqlite3
import threading
import time


class BoundaryDenied(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class RequestIdentity:
    request_id: str
    decision_id: str
    action_digest: str
    upstream_request_id: str


class RequestBoundary:
    def __init__(self, path=None, *, max_requests=100_000):
        self._lock = threading.Lock()
        self.max_requests = max_requests
        self.db = sqlite3.connect(str(path) if path else ":memory:",
                                  check_same_thread=False)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS requests "
                        "(sandbox TEXT, upstream TEXT, request_id TEXT UNIQUE, "
                        "PRIMARY KEY(sandbox, upstream))")
        self.count = self.db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]

    def issue(self, request) -> RequestIdentity:
        ctx, target = request.context, request.target
        if not ctx.sandbox_id or not ctx.request_id or len(ctx.request_id) > 256:
            raise BoundaryDenied("bull_identity_missing")
        request_id, decision_id = secrets.token_hex(16), secrets.token_hex(16)
        payload = [ctx.sandbox, ctx.sandbox_id, target.method.upper(), target.scheme,
                   target.host.lower(), target.port, target.path, target.query,
                   hashlib.sha256(bytes(request.body)).hexdigest(), request_id]
        digest = hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()
        with self._lock:
            if self.count >= self.max_requests:
                raise BoundaryDenied("bull_replay_capacity")
            try:
                with self.db:
                    self.db.execute("INSERT INTO requests VALUES (?, ?, ?)",
                                    (ctx.sandbox_id, ctx.request_id, request_id))
            except sqlite3.IntegrityError as exc:
                raise BoundaryDenied("bull_replayed_request") from exc
            self.count += 1
        return RequestIdentity(request_id, decision_id, digest, ctx.request_id)


class DecisionBudget:
    def __init__(self, seconds, context=None):
        self.deadline = time.monotonic() + seconds
        self.cancelled = threading.Event()
        self.context = context

    def check(self):
        if self.cancelled.is_set() or time.monotonic() >= self.deadline:
            raise BoundaryDenied("bull_timeout")
        if self.context is not None and not self.context.is_active():
            raise BoundaryDenied("bull_cancelled")


class DecisionGate:
    def __init__(self, *, timeout=0.25, capacity=16):
        if not math.isfinite(timeout) or timeout <= 0 or capacity < 1:
            raise ValueError("positive finite decision timeout and capacity required")
        self.timeout = timeout
        self.pool = ThreadPoolExecutor(max_workers=capacity, thread_name_prefix="bull-decision")
        self.slots = threading.BoundedSemaphore(capacity)

    def call(self, operation, context=None):
        remaining = context.time_remaining() if context is not None else None
        timeout = min(self.timeout, remaining) if remaining is not None else self.timeout
        budget = DecisionBudget(max(0, timeout), context)
        budget.check()
        if not self.slots.acquire(blocking=False):
            raise BoundaryDenied("bull_backpressure")
        try:
            future = self.pool.submit(operation, budget)
        except Exception:
            self.slots.release()
            raise
        future.add_done_callback(lambda _: self.slots.release())
        try:
            result = future.result(timeout=max(0, budget.deadline - time.monotonic()))
            budget.check()
            return result
        except TimeoutError as exc:
            budget.cancelled.set()
            future.cancel()
            raise BoundaryDenied("bull_timeout") from exc

    def close(self):
        self.pool.shutdown(wait=False, cancel_futures=True)

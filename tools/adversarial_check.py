#!/usr/bin/env python3
"""BULL adversarial test — single-file command-line tool.

Modes (auto-selected, or forced):
  offline    No network, no checkout. Runs every MAC-forgery attack against
             the verbatim anchor-service crypto copied line-for-line from
             Anharmoniclabs/BULL commit 23140fe (session_key, authenticate,
             verify, canonical in src/bulldog/anchor_service.py).
  checkout   bulldog package importable on this machine: runs the same
             attacks against the REAL package, plus canonicalizer, dispatcher,
             egress and multi-agent break-in probes.
  clone      Network available: shallow-clones the repo, then runs checkout mode.

Usage:
  python tools/adversarial_check.py             # auto
  python tools/adversarial_check.py --offline   # force offline mode
  python tools/adversarial_check.py --clone     # force clone from GitHub
  python tools/adversarial_check.py --repo URL  # custom repo URL
  python tools/adversarial_check.py --pytest    # also run the repo's own pytest suite

Exit codes: 0 = every attack rejected; 1 = at least one attack succeeded;
2 = no testable surface found.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_URL = "https://github.com/Anharmoniclabs/BULL.git"
VERBATIM_COMMIT = "23140fec8afa98473277a668bedee63082a82dd9"
RESULTS: list[tuple[str, str, str]] = []


def record(name: str, ok: bool, detail: str) -> None:
    RESULTS.append((name, "PASS" if ok else "FAIL", detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} -- {detail}")


def expect_reject(name: str, fn, *args, **kwargs) -> None:
    try:
        fn(*args, **kwargs)
    except Exception as exc:
        record(name, True, f"rejected ({type(exc).__name__})")
        return
    record(name, False, "ATTACK SUCCEEDED - call returned normally")


# ---------------------------------------------------------------------------
# Verbatim copies of BULL's anchor crypto, commit 23140fe (src/bulldog/
# anchor_service.py). Only AnchorError is a local stand-in for the repo's
# exception class. In checkout/clone mode the real package is used instead.
# ---------------------------------------------------------------------------

class AnchorError(Exception):
    pass


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def session_key(master: bytes, session: str) -> bytes:
    if len(master) < 32 or not isinstance(session, str) or not re.fullmatch(r"[a-f0-9]{64}", session):
        raise AnchorError("invalid session or master key")
    return hmac.digest(master, b"bull-anchor-session-v1:" + session.encode(), "sha256")


def authenticate(payload: dict, key: bytes, *, purpose: str) -> dict:
    body = {k: v for k, v in payload.items() if k != "mac"}
    return dict(body, mac=hmac.new(key, purpose.encode() + b"\x00" + canonical(body), hashlib.sha256).hexdigest())


def verify(payload: dict, key: bytes, *, purpose: str) -> None:
    expected = authenticate(payload, key, purpose=purpose)["mac"]
    supplied = payload.get("mac")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        raise AnchorError("authentication failed")


def load_reference_module():
    import types
    mod = types.ModuleType("bull_anchor_reference")
    mod.AnchorError = AnchorError
    mod.canonical = canonical
    mod.session_key = session_key
    mod.authenticate = authenticate
    mod.verify = verify
    return mod


def load_real_module(root: Path):
    sys.path.insert(0, str(root / "src"))
    import bulldog.anchor_service as anchor
    return anchor


# ---------------------------------------------------------------------------
# Attack suites
# ---------------------------------------------------------------------------

def attack_anchor(anchor, label: str) -> None:
    print(f"\n[{label}] anchor-service MAC layer")
    sk, auth, ver, can = anchor.session_key, anchor.authenticate, anchor.verify, anchor.canonical

    master = secrets.token_bytes(32)
    session = hashlib.sha256(b"probe-session").hexdigest()
    key = sk(master, session)
    payload = {"sequence": 1, "body": "hello", "purpose": "probe"}
    signed = auth(payload, key, purpose="probe")

    # sanity: an honest signature must verify
    try:
        ver(signed, key, purpose="probe")
        record("sanity: honest signature verifies", True, "accepted, as it should be")
    except Exception as exc:
        record("sanity: honest signature verifies", False, f"rejected honest signature: {exc}")

    expect_reject("forgery: tampered body", ver, dict(signed, body="goodbye"), key, purpose="probe")
    expect_reject("forgery: all-zero MAC", ver, dict(signed, mac="0" * 64), key, purpose="probe")
    expect_reject("forgery: truncated MAC", ver, dict(signed, mac="0" * 32), key, purpose="probe")
    expect_reject("forgery: non-string MAC", ver, dict(signed, mac=12345), key, purpose="probe")
    expect_reject("forgery: missing MAC key", ver, {k: v for k, v in signed.items() if k != "mac"}, key, purpose="probe")
    expect_reject("forgery: uppercase-hex MAC", ver, dict(signed, mac=signed["mac"].upper()), key, purpose="probe")
    expect_reject("key confusion: cross-session key", ver, signed, sk(master, "e" * 64), purpose="probe")
    expect_reject("purpose substitution: guest-deployment vs probe", ver, auth(payload, key, purpose="guest-deployment"), key, purpose="probe")
    expect_reject("length extension: appended field", ver, dict(signed, extra="attacker"), key, purpose="probe")
    expect_reject("forgery: naive sha256(purpose||body)", ver,
                  dict(payload, mac=hashlib.sha256(b"probe\x00" + can(payload)).hexdigest()), key, purpose="probe")
    expect_reject("forgery: HMAC without purpose domain", ver,
                  dict(payload, mac=hmac.new(key, can(payload), hashlib.sha256).hexdigest()), key, purpose="probe")
    expect_reject("weak key: short master", sk, b"x" * 31, session)
    expect_reject("weak key: uppercase session id", sk, master, "A" * 64)
    expect_reject("weak key: non-hex session id", sk, master, "not-hex!")
    expect_reject("weak key: non-string session", sk, master, 12345)
    expect_reject("canonical: NaN value", can, {"x": float("nan")})
    expect_reject("canonical: Infinity value", can, {"x": float("inf")})
    expect_reject("type confusion: payload not a dict", ver, ["mac", "list"], key, purpose="probe")

    # determinism / separation properties (PASS = property holds)
    same = can({"b": 2, "a": 1}) == can({"a": 1, "b": 2})
    record("canonical: key-order determinism", same, "reordered dicts encode identically")
    diff = sk(master, session) != sk(master, "d" * 64)
    record("keys: session domain separation", diff, "distinct sessions derive distinct keys")


def attack_canonicalizer(root: Path) -> None:
    print("\n[checkout] filesystem canonicalizer")
    from bulldog.canonicalizer import canonicalize_filesystem_resource
    hostile = [
        ("NUL byte", "ws\x00space"),
        ("dot-dot traversal", "/workspace/../../etc/passwd"),
        ("encoded traversal", "/workspace/%2e%2e/%2e%2e/etc/shadow"),
        ("double-encoded traversal", "/workspace/%252e%252e/etc"),
        ("unicode slash U+2215", "ws\u2215secret"),
        ("unicode slash U+2044", "ws\u2044secret"),
        ("fullwidth full stop U+FF0E", "file\uff0e\uff0e/root"),
        ("NFD dot folding", "cafe\u0301/../root"),
        ("trailing dot", "workspace/secret."),
        ("trailing space", "workspace/secret "),
        ("dot-slash only", "./"),
        ("dotdot alone", ".."),
        ("mixed separators", "/workspace\\..\\..\\etc"),
        ("empty string", ""),
        ("just separators", "//////"),
    ]
    for lbl, p in hostile:
        expect_reject(f"canonicalizer: {lbl}", canonicalize_filesystem_resource, p)
    try:
        if canonicalize_filesystem_resource("a\\b") == canonicalize_filesystem_resource("a/b"):
            record("canonicalizer: backslash conflation", False,
                   "'a\\b' and 'a/b' share one authorization identity")
        else:
            record("canonicalizer: backslash conflation", True, "distinct identities")
    except Exception:
        record("canonicalizer: backslash conflation", True, "one form rejected")


def attack_dispatcher(root: Path) -> None:
    print("\n[checkout] dispatcher execution boundary")
    import inspect
    from bulldog.canonicalizer import ActionCanonicalizationError, TrustedExecutionContext
    from bulldog.dispatcher import CapabilityDispatcher, DispatchDenied, DispatchRequest
    from bulldog.models import Capability, Provenance

    try:
        from bulldog.approval import ApprovalRequired
    except ImportError:
        class ApprovalRequired(Exception):
            pass

    # CapabilityDispatcher is the development/compatibility surface (it warns
    # as much); ProductionDispatcher requires a provisioned production host.
    dispatch = CapabilityDispatcher()
    trusted = TrustedExecutionContext(
        actor="redteam-probe",
        provenance=(Provenance.HUMAN,),
        security_context_id="redteam-probe-ctx",
    )

    def make(resource: str, caps) -> DispatchRequest:
        return DispatchRequest(
            proposal={"task": "redteam probe", "operation": "execute", "resource": resource},
            trusted=trusted,
            granted_capabilities=frozenset(caps),
            authorized_command=(resource,),
        )

    # Auto-fill whatever keyword arguments the current execute() signature
    # requires (e.g. project_root, timeout) so the harness survives API drift.
    sig = inspect.signature(dispatch.execute)
    project_dir = Path(tempfile.mkdtemp(prefix="bull-redteam-"))
    extra: dict = {}
    for name, param in sig.parameters.items():
        if name in ("self", "request", "command") or param.default is not param.empty:
            continue
        ann = param.annotation
        ann_str = ann if isinstance(ann, str) else getattr(ann, "__name__", str(ann))
        if name == "project_root" or "Path" in ann_str:
            extra[name] = project_dir
        elif name == "timeout" or ann_str == "int":
            extra[name] = 60
        elif ann_str == "bool":
            extra[name] = False
        else:
            extra[name] = "redteam-probe"
    if extra:
        print(f"    [info] execute() auto-filled kwargs: {sorted(extra)}")

    def expect_deny(name: str, fn, *args, **kwargs) -> None:
        """Strict gate check: only a real denial outcome counts as PASS.
        A TypeError, FileNotFoundError or other unexpected exception is a
        possible enforcement gap and is recorded as FAIL, not as a rejection.
        """
        try:
            result = fn(*args, **kwargs)
        except (DispatchDenied, ActionCanonicalizationError, ApprovalRequired) as exc:
            record(name, True, f"denied ({type(exc).__name__})")
            return
        except Exception as exc:
            record(name, False,
                   f"unexpected outcome ({type(exc).__name__}: {exc}) - possible enforcement gap")
            return
        if getattr(result, 'executed', None) is False and result.evaluation.decision.value == 'DENY':
            record(name, True, 'explicit denied ExecutionResult; no execution')
            return
        record(name, False, "unexpected execution result without explicit denial")

    if not callable(getattr(dispatch, "execute", None)):
        record("dispatcher: entry points", False, "no execute entry found - update harness")
        return

    hostile = [
        ("empty resource", "", [""]),
        ("traversal resource", "/usr/bin/../../etc/passwd", ["/usr/bin/../../etc/passwd"]),
        ("NUL resource", "/bin/ls\x00/usr/bin/ls", ["/bin/ls\x00/usr/bin/ls"]),
        ("relative traversal", "../../etc/shadow", ["../../etc/shadow"]),
        ("nonexistent hostile path", "/bin/sh -c cat /etc/shadow", ["/bin/sh -c cat /etc/shadow"]),
    ]
    for lbl, res, cmd in hostile:
        expect_deny(f"dispatcher.execute: {lbl}", dispatch.execute,
                    make(res, [Capability.PROCESS_EXEC]), cmd, **extra)

    # capability omission: a clean executable must still be denied without the grant
    expect_deny("dispatcher.execute: no PROCESS_EXEC grant", dispatch.execute,
                make("/usr/bin/ls", []), ["/usr/bin/ls"], **extra)
    # argv0 substitution: authorized resource must equal command[0]
    expect_deny("dispatcher.execute: argv0 substitution", dispatch.execute,
                make("/usr/bin/ls", [Capability.PROCESS_EXEC]), ["/usr/bin/echo", "pwned"], **extra)
    # command tuple must match host authorization exactly
    expect_deny("dispatcher.execute: mismatched command tuple", dispatch.execute,
                make("/usr/bin/ls", [Capability.PROCESS_EXEC]), ["/usr/bin/ls", "--extra", "arg"], **extra)

    print("    Source/API probes only; run deployment_check.py for production/KVM qualification.")


def attack_multiagent(root: Path) -> None:
    print("\n[checkout] multi-agent bus")
    import dataclasses
    import typing
    import uuid
    from bulldog.multiagent.bus import MessageBus
    from bulldog.multiagent import contracts

    bus = MessageBus(max_hops=2)
    expect_reject("multiagent: string garbage", bus.deliver, "not-an-envelope")
    expect_reject("multiagent: dict envelope", bus.deliver, {"recipient": "ghost"})

    env_cls = getattr(contracts, "Envelope", None)
    ident_cls = getattr(contracts, "AgentIdentity", None)
    if env_cls is None or ident_cls is None or not dataclasses.is_dataclass(env_cls):
        record("multiagent: contracts", False, "Envelope/AgentIdentity not found; update harness")
        return

    ident_hints = typing.get_type_hints(ident_cls)
    env_hints = typing.get_type_hints(env_cls)

    def make_identity(agent_id: str):
        kwargs = {}
        for f in dataclasses.fields(ident_cls):
            if f.default is not dataclasses.MISSING and f.default_factory is not dataclasses.MISSING:
                continue
            if f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING:
                continue
            t = ident_hints.get(f.name, str)
            if t is str or f.name == "agent_id":
                kwargs[f.name] = agent_id
            elif t is int:
                kwargs[f.name] = 0
            elif t is bool:
                kwargs[f.name] = False
            elif t is type(None):
                kwargs[f.name] = None
            elif typing.get_origin(t) in (tuple, list, set, frozenset):
                kwargs[f.name] = []
            else:
                try:
                    kwargs[f.name] = t()
                except Exception:
                    kwargs[f.name] = None
        return ident_cls(**kwargs)

    try:
        make_identity("probe-agent")
    except Exception as exc:
        record("multiagent: identity construction", False, f"could not build AgentIdentity: {exc}")
        return

    RECIPIENT_FIELDS = ("recipient", "to", "target", "destination")

    def build_env(recipient_id: str):
        kwargs = {}
        for f in dataclasses.fields(env_cls):
            t = env_hints.get(f.name, str)
            # recipient-like fields are ALWAYS overridden, even when they
            # carry defaults (e.g. a default recipient of "*").
            if f.name in RECIPIENT_FIELDS:
                if isinstance(t, type) and t is ident_cls:
                    kwargs[f.name] = make_identity(recipient_id)
                else:
                    kwargs[f.name] = recipient_id
                continue
            if f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING:
                continue
            if isinstance(t, type) and t is ident_cls:
                kwargs[f.name] = make_identity(f"probe-{f.name}")
            elif t is str:
                kwargs[f.name] = "probe"
            elif t is int:
                kwargs[f.name] = 1
            elif t is bool:
                kwargs[f.name] = False
            elif isinstance(t, type) and issubclass(t, uuid.UUID):
                kwargs[f.name] = uuid.uuid4()
            elif t is type(None):
                kwargs[f.name] = None
            elif typing.get_origin(t) in (tuple, list, set, frozenset):
                kwargs[f.name] = []
            else:
                try:
                    kwargs[f.name] = t()
                except Exception:
                    kwargs[f.name] = None
        return env_cls(**kwargs)

    try:
        ghost = build_env("ghost-agent")
    except Exception as exc:
        record("multiagent: envelope construction", False, f"could not build Envelope: {exc}")
        return
    expect_reject("multiagent: unregistered recipient", bus.deliver, ghost)

    result_cls = getattr(contracts, "AgentResult", None)

    def make_result():
        if result_cls is None or not dataclasses.is_dataclass(result_cls):
            return None
        kwargs = {}
        hints = typing.get_type_hints(result_cls)
        for f in dataclasses.fields(result_cls):
            if f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING:
                continue
            t = hints.get(f.name, str)
            if t is str:
                kwargs[f.name] = "probe"
            elif t is int:
                kwargs[f.name] = 0
            elif t is bool:
                kwargs[f.name] = False
            elif t is type(None):
                kwargs[f.name] = None
            elif typing.get_origin(t) in (tuple, list, set, frozenset):
                kwargs[f.name] = []
            else:
                try:
                    kwargs[f.name] = t()
                except Exception:
                    kwargs[f.name] = None
        try:
            return result_cls(**kwargs)
        except Exception:
            return None

    # register every identity the harness-built envelopes can reference
    # (recipients AND senders), so delivery is not refused for an
    # unregistered sender before the hop chain can even start.
    sender_ids = []
    for f in dataclasses.fields(env_cls):
        if f.default is not dataclasses.MISSING or f.default_factory is not dataclasses.MISSING:
            if f.name not in RECIPIENT_FIELDS:
                continue
        t = env_hints.get(f.name, str)
        if isinstance(t, type) and t is ident_cls and f.name not in RECIPIENT_FIELDS:
            sender_ids.append(f"probe-{f.name}")
    for sid in sender_ids:
        try:
            bus.register(make_identity(sid), lambda env: make_result())
        except Exception:
            pass

    # forwarding chain longer than max_hops must be stopped by the hop limit
    names = [f"chain{i}" for i in range(6)]
    received = []

    def handler_for(i, envelope):
        received.append(i)
        if i + 1 < len(names):
            bus.deliver(envelope.forwarded(names[i + 1], envelope.message_type, dict(envelope.payload)))
        return make_result()

    for i, name in enumerate(names):
        bus.register(make_identity(name), (lambda idx: lambda env: handler_for(idx, env))(i))
    stop_exc = None
    try:
        bus.deliver(build_env(names[0]))
    except Exception as exc:
        stop_exc = exc
    ok = 1 <= len(received) <= 3
    detail = f"{len(received)} deliveries before stop (max_hops=2)"
    if stop_exc is not None:
        detail += f"; stopped by {type(stop_exc).__name__}: {stop_exc}"
    if len(received) == 0:
        detail += " - chain never started; envelope rejected before first handler"
    record("multiagent: hop limit", ok, detail)


def run_repo_pytest(root: Path) -> None:
    print("\n[checkout] running the repository's own test suite")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", str(root / "tests")],
                       capture_output=True, text=True, timeout=1800)
    tail = (r.stdout or r.stderr).strip().splitlines()[-3:]
    print("\n".join("    " + line for line in tail))
    record("repo pytest suite", r.returncode == 0, f"exit {r.returncode}")


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def find_checkout() -> Path | None:
    for parent in [Path.cwd(), *Path.cwd().parents, Path.home()]:
        if (parent / "src" / "bulldog" / "__init__.py").exists():
            return parent
    return None


def have_network(timeout: float = 5.0) -> bool:
    try:
        socket.create_connection(("github.com", 443), timeout=timeout).close()
        return True
    except OSError:
        return False


def clone(url: str) -> Path | None:
    tmp = Path(tempfile.mkdtemp(prefix="bull-test-"))
    print(f"cloning {url} -> {tmp}")
    r = subprocess.run(["git", "clone", "--depth", "1", url, str(tmp / "BULL")],
                       capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print("clone failed:", r.stderr.strip()[:300])
        shutil.rmtree(tmp, ignore_errors=True)
        return None
    return tmp / "BULL"


def main() -> int:
    ap = argparse.ArgumentParser(description="BULL adversarial test")
    ap.add_argument("--offline", action="store_true", help="force verbatim-crypto offline mode")
    ap.add_argument("--clone", action="store_true", help="force network clone mode")
    ap.add_argument("--repo", default=REPO_URL)
    ap.add_argument("--pytest", action="store_true", help="also run the repo's pytest suite")
    args = ap.parse_args()

    print("=" * 74)
    print("BULL adversarial test")
    print("=" * 74)

    root = find_checkout()
    if args.offline:
        root = None
    elif args.clone:
        root = clone(args.repo)

    if root is not None:
        print(f"mode: checkout ({root})")
        anchor = load_real_module(root)
        attack_anchor(anchor, "real bulldog.anchor_service")
        for fn in (attack_canonicalizer, attack_dispatcher, attack_multiagent):
            try:
                fn(root)
            except Exception as exc:
                record(f"{fn.__name__} crash", False, f"{type(exc).__name__}: {exc}")
        if args.pytest:
            run_repo_pytest(root)
    else:
        print(f"mode: offline verbatim crypto (no checkout, no network)")
        print(f"source: commit {VERBATIM_COMMIT[:8]}, src/bulldog/anchor_service.py")
        attack_anchor(load_reference_module(), "verbatim anchor crypto")

    failed = [r for r in RESULTS if r[1] == "FAIL"]
    print("\n" + "=" * 74)
    print(f"RESULT: {len(RESULTS)} probes -- {len(RESULTS) - len(failed)} held, {len(failed)} BROKEN")
    for name, _, detail in failed:
        print(f"  !! {name}: {detail}")
    if not failed:
        print("Selected source/API probes passed; no deployment or hardware certification.")
    print("=" * 74)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

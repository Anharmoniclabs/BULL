"""Experimental, host-side lifecycle gate. Not a production runtime replacement.

Keep this object, its signing key and adapter callbacks OUTSIDE the agent process.
Only submit(request, grant) is an agent-facing entry point. There are no default
OS/network adapters. Durable state is authenticated, but a full old-database
rollback needs an independent checkpoint to detect. Already admitted effects
require host-owned cancellation/termination hooks; revocation cannot undo them.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import threading
import time
from typing import Callable, Mapping


class Rejected(RuntimeError):
    """Request or host operation failed validation."""


class IntegrityError(RuntimeError):
    """Authenticated local control state could not be verified."""


class Effect(str, Enum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    NETWORK = "NETWORK"
    MESSAGE = "MESSAGE"
    PUBLISH = "PUBLISH"
    CREDENTIAL_USE = "CREDENTIAL_USE"
    DELEGATE = "DELEGATE"
    REPLICATE = "REPLICATE"
    PERSIST = "PERSIST"
    SECURITY_CONTROL = "SECURITY_CONTROL"


class ResourceClass(str, Enum):
    PROJECT = "PROJECT"
    MESSAGE_DESTINATION = "MESSAGE_DESTINATION"
    PROTECTED_STATE = "PROTECTED_STATE"
    CREDENTIAL = "CREDENTIAL"
    DURABLE = "DURABLE"
    SECURITY_CONTROL = "SECURITY_CONTROL"


MAX_WIRE = 16384
MAX_STATE = 8 * 1024 * 1024
MAX_EVENTS = 20000


def canonical(value: object, *, limit: int = MAX_WIRE) -> bytes:
    """Restricted canonical JSON: string keys, finite-depth, integer-only numbers."""
    def check(v: object, depth: int = 0) -> None:
        if depth > 12:
            raise Rejected("object nesting exceeds budget")
        if v is None or type(v) in (str, bool):
            return
        if type(v) is int:
            if abs(v) > 2**53 - 1:
                raise Rejected("integer outside interoperable range")
            return
        if type(v) is list:
            for item in v:
                check(item, depth + 1)
            return
        if type(v) is dict and all(type(k) is str for k in v):
            for item in v.values():
                check(item, depth + 1)
            return
        raise Rejected("only null, booleans, strings, bounded integers, lists and objects are accepted")
    check(value)
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    if len(raw) > limit:
        raise Rejected("serialized data exceeds budget")
    return raw


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _text(value: object, label: str, size: int = 256) -> str:
    if type(value) is not str or not value.strip() or len(value) > size or any(ord(c) < 32 for c in value):
        raise Rejected(f"invalid {label}")
    return value


@dataclass(frozen=True)
class EffectRequest:
    """Proposal, never authority. Mutable caller dictionaries are copied to bytes."""
    actor: str
    kind: str
    target: str
    parameters: bytes
    request_id: str

    @classmethod
    def make(cls, actor: str, kind: str | Effect, target: str,
             parameters: dict, *, request_id: str | None = None) -> "EffectRequest":
        if type(parameters) is not dict:
            raise Rejected("parameters must be an object")
        return cls(_text(actor, "actor"), _text(str(kind.value if isinstance(kind, Effect) else kind), "effect"),
                   _text(target, "target"), canonical(parameters),
                   _text(request_id or secrets.token_hex(16), "request id", 128))

    @classmethod
    def from_wire(cls, wire: bytes) -> "EffectRequest":
        if not isinstance(wire, bytes) or len(wire) > MAX_WIRE:
            raise Rejected("invalid request body")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise Rejected("duplicate JSON key")
                result[key] = value
            return result
        try:
            obj = json.loads(wire, object_pairs_hook=unique)
            if type(obj) is not dict or set(obj) != {"actor", "kind", "target", "parameters", "request_id"}:
                raise Rejected("unexpected or missing request fields")
            return cls.make(**obj)
        except (ValueError, TypeError, KeyError, UnicodeError) as exc:
            raise Rejected("invalid canonical effect request") from exc

    def document(self) -> dict:
        _text(self.actor, "actor"); _text(self.kind, "effect"); _text(self.target, "target")
        _text(self.request_id, "request id", 128)
        if type(self.parameters) is not bytes or len(self.parameters) > MAX_WIRE:
            raise Rejected("invalid parameter bytes")
        try:
            params = json.loads(self.parameters)
        except (ValueError, UnicodeError) as exc:
            raise Rejected("invalid parameter encoding") from exc
        if type(params) is not dict or canonical(params) != self.parameters:
            raise Rejected("parameters are not canonical")
        return {"actor": self.actor, "kind": self.kind, "target": self.target,
                "parameters": params, "request_id": self.request_id}

    @property
    def digest(self) -> str:
        return digest(self.document())


@dataclass(frozen=True)
class Outcome:
    decision: str
    reason: str
    effect_state: str = "not_admitted"
    output: object = None
    receipt: str | None = None


@dataclass(frozen=True)
class Adapter:
    schema: Mapping[str, type]
    resource_classes: frozenset[str]
    invoke: Callable[[str, dict], object]


class LifecycleGovernor:
    """Four-plane reference gate with SQLite-serialized host state.

    Trusted methods require identity of the private host_key argument. This is
    API separation, not an in-process sandbox: hostile Python must never share
    this process. Root/domain identity must be bound by a real host transport.
    """
    def __init__(self, database: str | Path, signing_key: bytes, *, host_key: object,
                 clock: Callable[[], float] = time.time, denial_limit: int = 5):
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise ValueError("provide at least 32 random host-held key bytes")
        if host_key is None or type(denial_limit) is not int or denial_limit < 2:
            raise ValueError("host key and denial limit >= 2 required")
        self._key, self._host_key, self._clock = signing_key, host_key, clock
        self._denial_limit = denial_limit
        self._lock = threading.RLock()
        self._adapters: dict[str, Adapter] = {}
        self._revokers: dict[str, Callable[[str], bool]] = {}
        self._terminators: dict[str, Callable[[], bool]] = {}
        self._faulted = False
        path = Path(database)
        if path.is_symlink():
            raise IntegrityError("state database cannot be a symlink")
        fresh = not path.exists()
        if fresh:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        self._db = sqlite3.connect(path, isolation_level=None, check_same_thread=False, timeout=5)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        if fresh:
            self._db.execute("CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL, mac TEXT NOT NULL)")
            value = {"version": 1, "domains": {}, "sources": {}, "resources": {}, "identities": {},
                     "approvals": {}, "grants": {}, "used": [], "used_requests": [], "denials": {}, "events": [], "head": "0" * 64, "last_time": self._now()}
            raw = canonical(value, limit=MAX_STATE)
            self._db.execute("INSERT INTO state VALUES(1,?,?)", (raw, self._mac(b"state", raw)))
        self.verify()
        recovered = self._load()
        pending = {e["effect_digest"] for e in recovered["events"] if e["event"] == "effect.admitted"}
        completed = {e["effect_digest"] for e in recovered["events"]
                     if e["event"] == "effect.finished" and e.get("effect_state") == "completed"}
        # A crash or uncertain completion never silently grants a retry on restart.
        self._faulted = bool(pending - completed)

    def close(self) -> None:
        self._db.close()

    def _mac(self, purpose: bytes, payload: bytes) -> str:
        return hmac.new(self._key, b"BULL-LIFECYCLE-v1\0" + purpose + b"\0" + payload, hashlib.sha256).hexdigest()

    def _host(self, key: object) -> None:
        if key is not self._host_key:
            raise Rejected("host-only operation; natural language is not authority")

    def _now(self) -> int:
        return int(self._clock())

    def _load(self) -> dict:
        try:
            row = self._db.execute("SELECT body,mac FROM state WHERE id=1").fetchone()
            if row is None or len(row[0]) > MAX_STATE or not hmac.compare_digest(row[1], self._mac(b"state", row[0])):
                raise IntegrityError("state authentication failed")
            state = json.loads(row[0])
            if state["version"] != 1:
                raise IntegrityError("unknown state version")
            return state
        except (sqlite3.Error, ValueError, KeyError, TypeError) as exc:
            raise IntegrityError("state unavailable or malformed") from exc

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                state = self._load()
                if self._now() < state["last_time"]:
                    raise IntegrityError("host clock moved backwards; refuse authority changes")
                state["last_time"] = self._now()
                yield state
                raw = canonical(state, limit=MAX_STATE)
                self._db.execute("UPDATE state SET body=?,mac=? WHERE id=1", (raw, self._mac(b"state", raw)))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _event(self, state: dict, event: str, **fields) -> str:
        if len(state["events"]) >= MAX_EVENTS:
            raise IntegrityError("audit capacity exhausted; no new admission")
        body = {"sequence": len(state["events"]) + 1, "time": self._now(),
                "event": event, "previous": state["head"], **fields}
        tag = self._mac(b"event", canonical(body))
        state["events"].append({**body, "receipt": tag})
        state["head"] = tag
        return tag

    def verify(self) -> dict:
        with self._lock:
            state = self._load()
            previous = "0" * 64
            for index, event in enumerate(state["events"], 1):
                body = {k: v for k, v in event.items() if k != "receipt"}
                if body["sequence"] != index or body["previous"] != previous or not hmac.compare_digest(event["receipt"], self._mac(b"event", canonical(body))):
                    raise IntegrityError("audit chain authentication failed")
                previous = event["receipt"]
            if previous != state["head"]:
                raise IntegrityError("audit head mismatch")
            return {"valid": True, "records": len(state["events"]), "head": previous,
                    "remote_anchor": False, "scope": "local HMAC chain; full rollback not detected"}

    def register_adapter(self, kind: Effect, schema: Mapping[str, type],
                         classes: set[ResourceClass], invoke: Callable[[str, dict], object], *, host_key: object) -> None:
        self._host(host_key)
        if not isinstance(kind, Effect) or kind == Effect.SECURITY_CONTROL or not callable(invoke):
            raise Rejected("no agent adapter for sovereignty/security controls")
        if not classes or any(not isinstance(c, ResourceClass) for c in classes):
            raise Rejected("explicit resource classes required")
        if any(type(k) is not str or t not in (str, bool, int, list) for k, t in schema.items()):
            raise Rejected("unsupported adapter schema")
        with self._lock:
            if kind.value in self._adapters:
                raise Rejected("adapter replacement requires a new supervisor")
            self._adapters[kind.value] = Adapter(dict(schema), frozenset(c.value for c in classes), invoke)

    @staticmethod
    def scope(kind: Effect, target: str) -> str:
        if not isinstance(kind, Effect) or kind == Effect.SECURITY_CONTROL:
            raise Rejected("security control authority is never grantable")
        if "|" in _text(target, "target"):
            raise Rejected("invalid scope target")
        return kind.value + "|" + target

    def _chain(self, state: dict, actor: str) -> list[dict]:
        result, seen = [], set()
        while actor is not None:
            if actor in seen or len(result) > 8 or actor not in state["domains"]:
                raise Rejected("unknown or cyclic lineage")
            seen.add(actor)
            node = state["domains"][actor]
            result.append(node)
            actor = node["parent"]
        return result

    def _active(self, state: dict, actor: str) -> list[dict]:
        chain = self._chain(state, actor)
        for node in chain:
            if node["frozen"]:
                raise Rejected("lineage frozen; revocation outranks grants")
            if node["expires"] <= self._now():
                raise Rejected("lineage expired")
        return chain

    def _stamp(self, state: dict, actor: str) -> list:
        return [[n["id"], n["epoch"], n["context_version"]] for n in self._active(state, actor)]

    def create_domain(self, scopes: set[str], *, host_key: object, parent: str | None = None,
                      ttl: int = 3600) -> str:
        self._host(host_key)
        if type(ttl) is not int or not 1 <= ttl <= 86400 or not scopes:
            raise Rejected("bounded lifetime and nonempty scope set required")
        for item in scopes:
            kind, sep, target = item.partition("|")
            if not sep or self.scope(Effect(kind), target) != item:
                raise Rejected("invalid scope")
        with self._transaction() as state:
            expires = self._now() + ttl
            if parent:
                chain = self._active(state, parent)
                if len(chain) >= 8 or not set(scopes) < set(chain[0]["scopes"]):
                    raise Rejected("child scope must be a strict subset; depth limited to eight")
                expires = min(expires, *(n["expires"] for n in chain))
            domain_id = secrets.token_hex(16)
            root = state["domains"][parent]["root"] if parent else domain_id
            state["domains"][domain_id] = {"id": domain_id, "root": root, "parent": parent,
                "scopes": sorted(scopes), "expires": expires, "frozen": False,
                "epoch": 0, "context_version": 0, "sources": []}
            self._event(state, "domain.delegated" if parent else "domain.created", actor=domain_id, root=root, parent=parent)
        return domain_id

    def register_resource(self, owner: str, name: str, resource_class: ResourceClass, reference: str,
                          *, host_key: object, revoke: Callable[[str], bool] | None = None) -> str:
        self._host(host_key)
        _text(name, "resource"); _text(reference, "host resource reference", 2048)
        if not isinstance(resource_class, ResourceClass):
            raise Rejected("unknown resource class")
        with self._transaction() as state:
            self._active(state, owner)
            if name in state["resources"]:
                raise Rejected("resource id is immutable")
            state["resources"][name] = {"id": name, "owner": owner,
                "root": state["domains"][owner]["root"], "class": resource_class.value,
                "reference": reference, "state": "active"}
            self._event(state, "resource.registered", actor=owner, target=name, resource_class=resource_class.value)
        if revoke:
            self._revokers[name] = revoke
        return name

    def register_identity(self, owner: str, label: str, *, host_key: object) -> str:
        self._host(host_key); _text(label, "identity label")
        with self._transaction() as state:
            self._active(state, owner)
            identity = secrets.token_hex(16)
            state["identities"][identity] = {"id": identity, "owner": owner,
                "root": state["domains"][owner]["root"], "kind": "agent", "label": label}
            self._event(state, "identity.registered", actor=owner, identity=identity, kind="agent")
        return identity

    def observe(self, actor: str, content: str, *, trusted: bool, host_key: object,
                parents: tuple[str, ...] = (), ttl: int = 3600) -> str:
        self._host(host_key)
        if type(trusted) is not bool or type(content) is not str or type(ttl) is not int or not 1 <= ttl <= 86400:
            raise Rejected("invalid provenance record")
        content_hash = digest(content)
        with self._transaction() as state:
            chain = self._active(state, actor)
            root = chain[-1]
            expires = min(self._now() + ttl, *(n["expires"] for n in chain))
            effective_trust = trusted
            for source in parents:
                item = state["sources"].get(source)
                if not item or item["root"] != root["id"] or item["expires"] <= self._now():
                    raise Rejected("missing, expired or foreign provenance parent")
                effective_trust = effective_trust and item["trusted"]
                expires = min(expires, item["expires"])
            source = secrets.token_hex(16)
            state["sources"][source] = {"id": source, "root": root["id"], "owner": actor,
                "digest": content_hash, "parents": list(parents), "trusted": effective_trust, "expires": expires}
            # Conservative root-wide taint: a proposal cannot omit inherited memory.
            root["sources"].append(source)
            root["context_version"] += 1
            self._event(state, "provenance.observed", actor=actor, root=root["id"], source=source,
                        trusted=effective_trust, parents=list(parents))
        return source

    def _policy(self, state: dict, request: EffectRequest) -> tuple[str, str]:
        doc = request.document()
        if self._faulted:
            return "DENY", "supervisor faulted; human recovery required"
        if self._now() < state["last_time"]:
            return "DENY", "host clock moved backwards"
        if request.kind not in {k.value for k in Effect} or request.kind == Effect.SECURITY_CONTROL.value:
            return "DENY", "unknown or host-only effect; no generic fallback"
        chain = self._active(state, request.actor)
        root = chain[-1]
        resource = state["resources"].get(request.target)
        if not resource or resource["root"] != root["id"] or resource["state"] != "active":
            return "DENY", "resource missing, foreign or revoked"
        if any(request.kind + "|" + request.target not in n["scopes"] for n in chain):
            return "DENY", "effect and target outside current lineage authority"
        klass = resource["class"]
        if klass == ResourceClass.SECURITY_CONTROL.value:
            return "DENY", "shutdown and security controls are host-only"
        if klass == ResourceClass.PROTECTED_STATE.value and request.kind != Effect.REPLICATE.value:
            return "DENY", "protected state requires an explicit REPLICATE effect"
        if klass == ResourceClass.DURABLE.value and request.kind != Effect.PERSIST.value:
            return "DENY", "durable resource requires an explicit PERSIST effect"
        if klass == ResourceClass.CREDENTIAL.value and request.kind != Effect.CREDENTIAL_USE.value:
            return "DENY", "credentials require a credential-use adapter"
        adapter = self._adapters.get(request.kind)
        if adapter is None or klass not in adapter.resource_classes:
            return "DENY", "no registered typed adapter for this effect and resource class"
        params = doc["parameters"]
        if set(params) != set(adapter.schema) or any(type(params[k]) is not t for k, t in adapter.schema.items()):
            return "DENY", "parameters do not match the exact adapter schema"
        for v in params.values():
            if type(v) is list and any(type(item) is not str for item in v):
                return "DENY", "adapter lists must contain strings only"
        sources = [state["sources"][sid] for sid in root["sources"]]
        if not sources or any(s["expires"] <= self._now() for s in sources):
            return "DENY", "trusted intake context is missing or expired"
        tainted = any(not s["trusted"] for s in sources)
        if request.kind in {Effect.MESSAGE.value, Effect.PUBLISH.value}:
            identity = state["identities"].get(params.get("identity"))
            if not identity or identity["root"] != root["id"] or identity["owner"] not in {n["id"] for n in chain}:
                return "DENY", "external identity is not bound to this lineage"
            if not str(params.get("purpose", "")).strip():
                return "DENY", "external communication needs a bound purpose"
            recent = sum(e["event"] == "effect.admitted" and e.get("root") == root["id"]
                         and e.get("kind") in {Effect.MESSAGE.value, Effect.PUBLISH.value}
                         and self._now() - e["time"] < 60 for e in state["events"])
            if recent >= 10:
                return "DENY", "root-wide communication budget exhausted (10 per minute)"
        if tainted and (klass in {ResourceClass.PROTECTED_STATE.value, ResourceClass.CREDENTIAL.value}):
            return "DENY", "untrusted-derived influence cannot export protected state or use credentials"
        if request.kind in {Effect.REPLICATE.value, Effect.PERSIST.value, Effect.CREDENTIAL_USE.value,
                            Effect.MESSAGE.value, Effect.PUBLISH.value, Effect.DELEGATE.value}:
            return "REVIEW", "high-consequence effect requires exact host approval"
        if tainted and request.kind != Effect.READ.value:
            return "REVIEW", "untrusted provenance persists through memory; review required"
        return "ALLOW", "exact effect, target, schema and current lineage checks pass"

    def inspect(self, request: EffectRequest) -> Outcome:
        with self._lock:
            state = self._load()
            try:
                decision, reason = self._policy(state, request)
            except Rejected as exc:
                decision, reason = "DENY", str(exc)
            return Outcome(decision, reason)

    def approval_display(self, request: EffectRequest) -> dict:
        # Deterministic display material, NOT independent hardware approval.
        with self._lock:
            state = self._load()
            return {"effect": request.document(), "effect_digest": request.digest,
                    "lineage_stamp": self._stamp(state, request.actor),
                    "meaning": "Approve these exact bytes only; no model-written summary is authority"}

    def approve(self, request: EffectRequest, *, host_key: object, ttl: int = 120) -> str:
        self._host(host_key)
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise Rejected("approval lifetime must be 1..300 seconds")
        with self._transaction() as state:
            decision, reason = self._policy(state, request)
            if decision not in {"ALLOW", "REVIEW"}:
                raise Rejected(reason)
            aid = secrets.token_hex(16)
            state["approvals"][aid] = {"digest": request.digest, "actor": request.actor,
                "stamp": self._stamp(state, request.actor), "expires": self._now() + ttl, "used": False}
            self._event(state, "approval.host_recorded", actor=request.actor, effect_digest=request.digest,
                        note="host API approval; physical presence not established")
        return aid

    def mint(self, request: EffectRequest, *, host_key: object, approval: str | None = None,
             ttl: int = 60) -> str:
        self._host(host_key)
        if type(ttl) is not int or not 1 <= ttl <= 300:
            raise Rejected("grant lifetime must be 1..300 seconds")
        with self._transaction() as state:
            decision, reason = self._policy(state, request)
            stamp = self._stamp(state, request.actor)
            if decision == "DENY":
                raise Rejected(reason)
            if decision == "REVIEW":
                a = state["approvals"].get(approval)
                if not a or a["used"] or a["digest"] != request.digest or a["stamp"] != stamp or a["expires"] <= self._now():
                    raise Rejected("missing, stale or mismatched exact host approval")
            gid = secrets.token_hex(16)
            grant = {"digest": request.digest, "actor": request.actor, "stamp": stamp,
                     "expires": self._now() + ttl, "approval": approval if decision == "REVIEW" else None}
            state["grants"][gid] = grant
            self._event(state, "grant.minted", actor=request.actor, effect_digest=request.digest, grant_id=gid)
            token = gid + "." + self._mac(b"grant", canonical({"id": gid, **grant}))
        return token

    def _freeze(self, state: dict, root: str, reason: str) -> None:
        for domain in state["domains"].values():
            if domain["root"] == root:
                domain["frozen"] = True
                domain["epoch"] += 1
        for resource in state["resources"].values():
            if resource["root"] == root and resource["state"] != "revoked":
                resource["state"] = "revocation_pending"
        for a in state["approvals"].values():
            if state["domains"][a["actor"]]["root"] == root:
                a["used"] = True
        self._event(state, "sovereignty.root_frozen", root=root, reason=reason)

    def _deny(self, state: dict, request: EffectRequest, reason: str, authenticated_actor: str | None) -> Outcome:
        decision = "DENY"
        if authenticated_actor:
            root = state["domains"][authenticated_actor]["root"]
            history = [t for t in state["denials"].get(root, []) if self._now() - t < 60]
            history.append(self._now()); state["denials"][root] = history
            if len(history) >= self._denial_limit and not state["domains"][root]["frozen"]:
                self._freeze(state, root, "authenticated repeated-denial threshold")
                decision = "FREEZE"
        receipt = self._event(state, "effect.denied", actor=authenticated_actor,
                              effect_digest=request.digest, decision=decision, reason=reason)
        return Outcome(decision, reason, receipt=receipt)

    def submit(self, request: EffectRequest, token: str) -> Outcome:
        """Only agent-facing call. Admission is durable before adapter invocation."""
        request.document()  # Parse errors cannot reach an adapter or mint authority.
        with self._transaction() as state:
            authenticated_actor = None
            grant = None
            gid = ""
            if type(token) is str and len(token) <= 256 and token.count(".") == 1:
                gid, signature = token.split(".")
                grant = state["grants"].get(gid)
                if grant and hmac.compare_digest(signature, self._mac(b"grant", canonical({"id": gid, **grant}))):
                    authenticated_actor = grant["actor"]
            if not authenticated_actor:
                return self._deny(state, request, "no authentic host-issued grant", None)
            try:
                decision, reason = self._policy(state, request)
                if decision == "DENY":
                    raise Rejected(reason)
                if grant["actor"] != request.actor or grant["digest"] != request.digest:
                    raise Rejected("effect bytes differ from authorized request")
                if grant["expires"] <= self._now() or grant["stamp"] != self._stamp(state, request.actor):
                    raise Rejected("grant expired or lineage/provenance epoch changed")
                if gid in state["used"] or request.actor + ":" + request.request_id in state["used_requests"]:
                    raise Rejected("single-use grant or request already consumed")
                if decision == "REVIEW":
                    approval = state["approvals"].get(grant["approval"])
                    if not approval or approval["used"] or approval["expires"] <= self._now() or approval["digest"] != request.digest or approval["stamp"] != grant["stamp"]:
                        raise Rejected("review approval unavailable or consumed")
                    approval["used"] = True
            except Rejected as exc:
                return self._deny(state, request, str(exc), authenticated_actor)
            resource = dict(state["resources"][request.target])
            adapter = self._adapters[request.kind]
            state["used"].append(gid)
            state["used_requests"].append(request.actor + ":" + request.request_id)
            admission = self._event(state, "effect.admitted", actor=request.actor, root=resource["root"],
                kind=request.kind, target=request.target, effect_digest=request.digest,
                target_fingerprint=hashlib.sha256(resource["reference"].encode()).hexdigest(),
                consequence="reviewed" if decision == "REVIEW" else "routine")
        # Once committed, this is an in-flight effect; never automatically retry it.
        try:
            output = adapter.invoke(resource["reference"], request.document()["parameters"])
            output_digest = digest(output)
        except Exception as exc:
            self._finish(request, "adapter_error", type(exc).__name__)
            return Outcome("DENY", "adapter failed; partial effect possible; grant remains consumed", "indeterminate", receipt=admission)
        receipt = self._finish(request, "completed", output_digest)
        if receipt is None:
            return Outcome("DENY", "effect ran but completion audit failed; supervisor faulted", "completed_audit_failed", receipt=admission)
        return Outcome("ALLOW", "typed adapter completed; no other authority implied", "completed", output, receipt)

    def _finish(self, request: EffectRequest, state_label: str, output_digest: str) -> str | None:
        if state_label != "completed":
            self._faulted = True
        try:
            with self._transaction() as state:
                return self._event(state, "effect.finished", actor=request.actor, effect_digest=request.digest,
                                   effect_state=state_label, output_digest=output_digest)
        except Exception:
            self._faulted = True
            return None

    def freeze(self, actor: str, reason: str, *, host_key: object) -> dict:
        self._host(host_key); _text(reason, "freeze reason", 1024)
        with self._transaction() as state:
            root = self._chain(state, actor)[-1]["id"]
            self._freeze(state, root, reason)
        return self.cleanup(root, host_key=host_key)

    def cleanup(self, actor: str, *, host_key: object) -> dict:
        self._host(host_key)
        with self._lock:
            state = self._load()
            root = self._chain(state, actor)[-1]["id"]
            if not state["domains"][root]["frozen"]:
                raise Rejected("revoke authority before cleanup")
            resources = [dict(r) for r in state["resources"].values() if r["root"] == root and r["state"] == "revocation_pending"]
        outcomes = {}
        for resource in resources:
            callback = self._revokers.get(resource["id"])
            try:
                success = callback is not None and callback(resource["reference"]) is True
            except Exception:
                success = False
            with self._transaction() as state:
                if success:
                    state["resources"][resource["id"]]["state"] = "revoked"
                self._event(state, "resource.cleanup", root=root, target=resource["id"], confirmed=success)
            outcomes[resource["id"]] = "revoked" if success else "pending_or_unsupported"
        return {"root": root, "authority": "frozen", "resources": outcomes}

    def register_terminator(self, actor: str, callback: Callable[[], bool], *, host_key: object) -> None:
        self._host(host_key)
        with self._lock:
            root = self._active(self._load(), actor)[-1]["id"]
            self._terminators[root] = callback

    def shutdown(self, actor: str, *, host_key: object) -> dict:
        self._host(host_key)
        with self._transaction() as state:
            root = self._chain(state, actor)[-1]["id"]
            self._freeze(state, root, "host shutdown requested")
        callback = self._terminators.get(root)
        try:
            terminated = callback is not None and callback() is True
        except Exception:
            terminated = False
        with self._transaction() as state:
            self._event(state, "sovereignty.termination", root=root, confirmed=terminated)
        result = self.cleanup(root, host_key=host_key)
        return {**result, "termination": "confirmed" if terminated else "pending_or_unsupported"}

    def fleet_observations(self, window_seconds: int = 300) -> list[dict]:
        with self._lock:
            state = self._load()
            targets = {}
            for event in state["events"]:
                if event["event"] == "effect.admitted" and self._now() - event["time"] <= window_seconds:
                    targets.setdefault(event["target_fingerprint"], set()).add(event["root"])
            return [{"target_fingerprint": target, "independent_roots": len(roots),
                     "signal": "REVIEW" if len(roots) >= 3 else "OBSERVE",
                     "authority_change": False} for target, roots in sorted(targets.items())]

    def snapshot(self) -> dict:
        with self._lock:
            state = self._load()
            return {"domains": [{k: d[k] for k in ("id", "root", "parent", "frozen", "epoch", "context_version")}
                                for d in state["domains"].values()],
                    "resources": [{k: r[k] for k in ("id", "owner", "class", "state")}
                                  for r in state["resources"].values()],
                    "sources": list(state["sources"].values()), "events": state["events"],
                    "grant_count": len(state["grants"]), "consumed_grants": len(state["used"]), "supervisor_faulted": self._faulted,
                    "audit": self.verify(), "production_boundary": False}

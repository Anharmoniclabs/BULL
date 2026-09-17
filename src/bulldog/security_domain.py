from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import secrets
import threading
from typing import Callable, Iterable, Sequence
from urllib.parse import urlsplit

from .audit import AuditLedger
from .models import Capability, Provenance


class SecurityDomainError(RuntimeError):
    pass


@dataclass(frozen=True)
class GoalTransition:
    sequence: int
    previous_intent_hash: str
    next_intent_hash: str
    reason: str
    approved_by: str


@dataclass
class SecurityDomain:
    """Host-issued authority boundary for one agent/model execution identity."""

    domain_id: str
    root_domain_id: str
    parent_domain_id: str | None
    actor: str
    capability_ceiling: frozenset[Capability]
    egress_hosts: frozenset[str]
    provenance: tuple[Provenance, ...]
    initial_intent_hash: str
    current_intent_hash: str
    initial_command_hash: str | None
    model_id: str | None
    model_id_hash: str | None
    domain_fingerprint: str
    spawn_depth: int
    frozen: bool = False
    freeze_reason: str | None = None
    transitions: list[GoalTransition] = field(default_factory=list)


def hash_intent(text: str) -> str:
    normalized = " ".join(str(text).split())
    if not normalized:
        raise SecurityDomainError("initial intent cannot be empty")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def hash_command(command: Sequence[str] | None) -> str | None:
    if command is None:
        return None
    encoded = json.dumps(
        [str(item) for item in command],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def hash_model_id(model_id: str | None) -> str | None:
    if model_id is None:
        return None
    normalized = str(model_id).strip()
    if not normalized:
        raise SecurityDomainError("model_id cannot be empty")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _domain_fingerprint(
    *,
    domain_id: str,
    root_domain_id: str,
    parent_domain_id: str | None,
    actor: str,
    model_id_hash: str | None,
    initial_intent_hash: str,
    initial_command_hash: str | None,
    capability_ceiling: frozenset[Capability],
    egress_hosts: frozenset[str],
) -> str:
    payload = json.dumps(
        {
            "domain_id": domain_id,
            "root_domain_id": root_domain_id,
            "parent_domain_id": parent_domain_id,
            "actor": actor,
            "model_id_hash": model_id_hash,
            "initial_intent_hash": initial_intent_hash,
            "initial_command_hash": initial_command_hash,
            "capability_ceiling": sorted(
                capability.value for capability in capability_ceiling
            ),
            "egress_hosts": sorted(egress_hosts),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class SecurityDomainRegistry:
    """
    Trusted host-side registry for multi-agent authority and lineage.

    Security properties:
      - domain IDs are host generated and non-model-controlled
      - children require explicit `agent.spawn` authority
      - children can only receive subsets of parent capabilities/egress hosts
      - all agents in one root domain share one behavioral security context
      - model ID, initial intent and initial command can be bound into a domain
        fingerprint for complete execution-lineage auditing
      - domains can be frozen individually or root-wide
      - goal changes require an explicit trusted transition record
      - optional AuditLedger writes lifecycle/dispatch/broker events into the
        same tamper-evident chain used by BULL policy decisions
    """

    def __init__(
        self,
        *,
        max_spawn_depth: int = 8,
        audit: Callable[[dict], None] | None = None,
        ledger: AuditLedger | None = None,
        strict_identity_binding: bool = False,
    ):
        if max_spawn_depth < 0:
            raise ValueError("max_spawn_depth must be >= 0")

        self.max_spawn_depth = int(max_spawn_depth)
        self.audit = audit
        self.ledger = ledger
        self.strict_identity_binding = bool(strict_identity_binding)
        self._domains: dict[str, SecurityDomain] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _normalize_hosts(hosts: Iterable[str]) -> frozenset[str]:
        normalized = set()
        for host in hosts:
            value = str(host).strip().lower().rstrip(".")
            if not value:
                raise SecurityDomainError("empty egress host")
            if "/" in value or "://" in value:
                raise SecurityDomainError(
                    "egress authority must be an exact hostname"
                )
            normalized.add(value)
        return frozenset(normalized)

    @staticmethod
    def _new_id() -> str:
        return secrets.token_urlsafe(24)

    def _validate_identity_binding(
        self,
        *,
        model_id: str | None,
        initial_command: Sequence[str] | None,
    ) -> None:
        if not self.strict_identity_binding:
            return
        if model_id is None or not str(model_id).strip():
            raise SecurityDomainError(
                "strict identity binding requires model_id"
            )
        if initial_command is None or len(initial_command) == 0:
            raise SecurityDomainError(
                "strict identity binding requires initial_command"
            )

    def create_root(
        self,
        *,
        actor: str,
        initial_prompt: str,
        capability_ceiling: Iterable[Capability],
        provenance: tuple[Provenance, ...] = (Provenance.HUMAN,),
        egress_hosts: Iterable[str] = (),
        initial_command: Sequence[str] | None = None,
        model_id: str | None = None,
    ) -> SecurityDomain:
        self._validate_identity_binding(
            model_id=model_id,
            initial_command=initial_command,
        )

        intent_hash = hash_intent(initial_prompt)
        command_hash = hash_command(initial_command)
        normalized_model = None if model_id is None else str(model_id).strip()
        model_hash = hash_model_id(normalized_model)
        domain_id = self._new_id()
        capabilities = frozenset(capability_ceiling)
        hosts = self._normalize_hosts(egress_hosts)
        fingerprint = _domain_fingerprint(
            domain_id=domain_id,
            root_domain_id=domain_id,
            parent_domain_id=None,
            actor=str(actor),
            model_id_hash=model_hash,
            initial_intent_hash=intent_hash,
            initial_command_hash=command_hash,
            capability_ceiling=capabilities,
            egress_hosts=hosts,
        )

        domain = SecurityDomain(
            domain_id=domain_id,
            root_domain_id=domain_id,
            parent_domain_id=None,
            actor=str(actor),
            capability_ceiling=capabilities,
            egress_hosts=hosts,
            provenance=tuple(provenance),
            initial_intent_hash=intent_hash,
            current_intent_hash=intent_hash,
            initial_command_hash=command_hash,
            model_id=normalized_model,
            model_id_hash=model_hash,
            domain_fingerprint=fingerprint,
            spawn_depth=0,
        )

        with self._lock:
            self._domains[domain.domain_id] = domain

        self._emit(self._domain_event("security_domain_created", domain))
        return domain

    def spawn_child(
        self,
        *,
        parent_domain_id: str,
        actor: str,
        initial_prompt: str,
        capability_ceiling: Iterable[Capability],
        egress_hosts: Iterable[str] = (),
        provenance_append: tuple[Provenance, ...] = (),
        initial_command: Sequence[str] | None = None,
        model_id: str | None = None,
    ) -> SecurityDomain:
        self._validate_identity_binding(
            model_id=model_id,
            initial_command=initial_command,
        )

        with self._lock:
            parent = self.require_active(parent_domain_id)

            if Capability.AGENT_SPAWN not in parent.capability_ceiling:
                raise SecurityDomainError(
                    "parent domain lacks agent.spawn authority"
                )

            child_capabilities = frozenset(capability_ceiling)
            if not child_capabilities.issubset(parent.capability_ceiling):
                raise SecurityDomainError(
                    "child capability ceiling exceeds parent authority"
                )

            child_hosts = self._normalize_hosts(egress_hosts)
            if not child_hosts.issubset(parent.egress_hosts):
                raise SecurityDomainError(
                    "child egress authority exceeds parent authority"
                )

            depth = parent.spawn_depth + 1
            if depth > self.max_spawn_depth:
                raise SecurityDomainError("maximum agent spawn depth exceeded")

            intent_hash = hash_intent(initial_prompt)
            command_hash = hash_command(initial_command)
            normalized_model = None if model_id is None else str(model_id).strip()
            model_hash = hash_model_id(normalized_model)
            domain_id = self._new_id()
            fingerprint = _domain_fingerprint(
                domain_id=domain_id,
                root_domain_id=parent.root_domain_id,
                parent_domain_id=parent.domain_id,
                actor=str(actor),
                model_id_hash=model_hash,
                initial_intent_hash=intent_hash,
                initial_command_hash=command_hash,
                capability_ceiling=child_capabilities,
                egress_hosts=child_hosts,
            )
            domain = SecurityDomain(
                domain_id=domain_id,
                root_domain_id=parent.root_domain_id,
                parent_domain_id=parent.domain_id,
                actor=str(actor),
                capability_ceiling=child_capabilities,
                egress_hosts=child_hosts,
                provenance=parent.provenance + tuple(provenance_append),
                initial_intent_hash=intent_hash,
                current_intent_hash=intent_hash,
                initial_command_hash=command_hash,
                model_id=normalized_model,
                model_id_hash=model_hash,
                domain_fingerprint=fingerprint,
                spawn_depth=depth,
            )
            self._domains[domain_id] = domain

        self._emit(self._domain_event("security_domain_spawned", domain))
        return domain

    def get(self, domain_id: str) -> SecurityDomain:
        try:
            return self._domains[str(domain_id)]
        except KeyError as exc:
            raise SecurityDomainError("unknown security domain") from exc

    def require_active(self, domain_id: str) -> SecurityDomain:
        domain = self.get(domain_id)
        if domain.frozen:
            raise SecurityDomainError(
                "security domain is frozen"
                + (
                    f": {domain.freeze_reason}"
                    if domain.freeze_reason
                    else ""
                )
            )
        return domain

    def assert_capabilities(
        self,
        domain_id: str,
        requested: Iterable[Capability],
    ) -> None:
        domain = self.require_active(domain_id)
        requested_set = frozenset(requested)
        if not requested_set.issubset(domain.capability_ceiling):
            raise SecurityDomainError(
                "dispatch requested authority outside domain ceiling"
            )

    def parent_capabilities(
        self,
        domain_id: str,
    ) -> frozenset[Capability] | None:
        domain = self.require_active(domain_id)
        if domain.parent_domain_id is None:
            return None
        return self.get(domain.parent_domain_id).capability_ceiling

    def trusted_context(self, domain_id: str):
        from .canonicalizer import TrustedExecutionContext

        domain = self.require_active(domain_id)
        return TrustedExecutionContext(
            actor=domain.actor,
            provenance=domain.provenance,
            security_context_id="root-domain:" + domain.root_domain_id,
            domain_id=domain.domain_id,
            root_domain_id=domain.root_domain_id,
            parent_domain_id=domain.parent_domain_id,
            initial_intent_hash=domain.initial_intent_hash,
            initial_command_hash=domain.initial_command_hash,
            model_id=domain.model_id,
            model_id_hash=domain.model_id_hash,
            domain_fingerprint=domain.domain_fingerprint,
            spawn_depth=domain.spawn_depth,
        )

    def transition_goal(
        self,
        domain_id: str,
        *,
        next_goal: str,
        reason: str,
        approved_by: str,
    ) -> GoalTransition:
        if not str(reason).strip() or not str(approved_by).strip():
            raise SecurityDomainError(
                "goal transition requires reason and trusted approver"
            )

        with self._lock:
            domain = self.require_active(domain_id)
            transition = GoalTransition(
                sequence=len(domain.transitions) + 1,
                previous_intent_hash=domain.current_intent_hash,
                next_intent_hash=hash_intent(next_goal),
                reason=str(reason),
                approved_by=str(approved_by),
            )
            domain.current_intent_hash = transition.next_intent_hash
            domain.transitions.append(transition)

        self._emit({
            "event": "security_domain_goal_transition",
            "domain_id": domain.domain_id,
            "root_domain_id": domain.root_domain_id,
            "domain_fingerprint": domain.domain_fingerprint,
            "sequence": transition.sequence,
            "previous_intent_hash": transition.previous_intent_hash,
            "next_intent_hash": transition.next_intent_hash,
            "reason": transition.reason,
            "approved_by": transition.approved_by,
        })
        return transition

    def assert_egress(self, domain_id: str, url: str) -> None:
        domain = self.require_active(domain_id)
        hostname = (urlsplit(str(url)).hostname or "").lower().rstrip(".")
        if not hostname or hostname not in domain.egress_hosts:
            raise SecurityDomainError(
                "egress destination is outside domain authority"
            )

    def freeze(self, domain_id: str, reason: str) -> None:
        with self._lock:
            domain = self.get(domain_id)
            domain.frozen = True
            domain.freeze_reason = str(reason)

        self._emit({
            "event": "security_domain_frozen",
            "domain_id": domain.domain_id,
            "root_domain_id": domain.root_domain_id,
            "domain_fingerprint": domain.domain_fingerprint,
            "reason": domain.freeze_reason,
        })

    def freeze_root(self, root_domain_id: str, reason: str) -> None:
        frozen_ids = []
        with self._lock:
            for domain in self._domains.values():
                if domain.root_domain_id == str(root_domain_id):
                    domain.frozen = True
                    domain.freeze_reason = str(reason)
                    frozen_ids.append(domain.domain_id)

        self._emit({
            "event": "security_domain_root_frozen",
            "root_domain_id": str(root_domain_id),
            "domain_ids": sorted(frozen_ids),
            "reason": str(reason),
        })

    def record_dispatch(
        self,
        domain_id: str,
        *,
        capability: Capability,
        resource: str,
        command: Sequence[str],
    ) -> None:
        domain = self.require_active(domain_id)
        self._emit({
            "event": "security_domain_dispatch",
            "domain_id": domain.domain_id,
            "root_domain_id": domain.root_domain_id,
            "domain_fingerprint": domain.domain_fingerprint,
            "model_id_hash": domain.model_id_hash,
            "current_intent_hash": domain.current_intent_hash,
            "initial_command_hash": domain.initial_command_hash,
            "command_hash": hash_command(command),
            "capability": capability.value,
            "resource": str(resource),
        })

    def record_broker_event(
        self,
        domain_id: str,
        *,
        broker: str,
        operation: str,
        allowed: bool,
        detail: dict | None = None,
    ) -> None:
        domain = self.require_active(domain_id)
        self._emit({
            "event": "security_domain_broker",
            "domain_id": domain.domain_id,
            "root_domain_id": domain.root_domain_id,
            "domain_fingerprint": domain.domain_fingerprint,
            "model_id_hash": domain.model_id_hash,
            "broker": str(broker),
            "operation": str(operation),
            "allowed": bool(allowed),
            "detail": dict(detail or {}),
        })

    @staticmethod
    def _domain_event(event: str, domain: SecurityDomain) -> dict:
        return {
            "event": event,
            "domain_id": domain.domain_id,
            "root_domain_id": domain.root_domain_id,
            "parent_domain_id": domain.parent_domain_id,
            "actor": domain.actor,
            "model_id": domain.model_id,
            "model_id_hash": domain.model_id_hash,
            "domain_fingerprint": domain.domain_fingerprint,
            "capability_ceiling": sorted(
                cap.value for cap in domain.capability_ceiling
            ),
            "egress_hosts": sorted(domain.egress_hosts),
            "initial_intent_hash": domain.initial_intent_hash,
            "initial_command_hash": domain.initial_command_hash,
            "spawn_depth": domain.spawn_depth,
        }

    def _emit(self, event: dict) -> None:
        payload = dict(event)
        if self.ledger is not None:
            event_type = str(payload.get("event", "security_domain_event"))
            self.ledger.append_event(event_type, payload)
        if self.audit is not None:
            self.audit(payload)

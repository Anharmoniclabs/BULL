from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import secrets
import threading
from typing import Sequence

from .audit import AuditLedger
from .canonicalizer import TrustedExecutionContext
from .models import Capability, Provenance


class AgentIsolationError(RuntimeError):
    pass


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _command_text(command: Sequence[str]) -> str:
    return json.dumps(
        [str(part) for part in command],
        separators=(",", ":"),
        ensure_ascii=False,
    )


@dataclass(frozen=True)
class AgentExecutionEnvelope:
    """Host-owned immutable identity for one isolated agent."""

    agent_id: str
    model_id: str
    initial_intent: str
    initial_command: tuple[str, ...]
    provenance: tuple[Provenance, ...]
    granted_capabilities: frozenset[Capability]

    sandbox_id: str
    security_context_id: str
    intent_hash: str
    initial_command_hash: str
    lineage_hash: str

    parent_agent_id: str | None = None
    parent_capabilities: frozenset[Capability] | None = None

    @property
    def initial_command_text(self) -> str:
        return _command_text(self.initial_command)

    def trusted_context(self) -> TrustedExecutionContext:
        return TrustedExecutionContext(
            actor=self.agent_id,
            provenance=self.provenance,
            security_context_id=self.security_context_id,
            agent_id=self.agent_id,
            sandbox_id=self.sandbox_id,
            model_id=self.model_id,
            parent_agent_id=self.parent_agent_id,
            intent_hash=self.intent_hash,
            initial_command_hash=self.initial_command_hash,
            lineage_hash=self.lineage_hash,
            initial_intent=self.initial_intent,
            initial_command=self.initial_command_text,
        )


class AgentIsolationRegistry:
    """
    Trusted multi-agent authority and lineage registry.

    Guarantees:
      - every agent receives a distinct sandbox/security-context identity
      - child capabilities can never exceed the parent capability set
      - creating a child requires AGENT_SPAWN authority in the parent
      - model identity, initial intent, and bootstrap command are immutable
      - agent lifecycle and scoped broker activity can share one audit chain
    """

    def __init__(
        self,
        *,
        ledger: AuditLedger | None = None,
    ):
        self.ledger = ledger
        self._agents: dict[str, AgentExecutionEnvelope] = {}
        self._revoked: set[str] = set()
        self._lock = threading.RLock()

    def register_agent(
        self,
        *,
        agent_id: str,
        model_id: str,
        initial_intent: str,
        initial_command: Sequence[str],
        provenance: tuple[Provenance, ...],
        granted_capabilities: frozenset[Capability],
        parent_agent_id: str | None = None,
    ) -> AgentExecutionEnvelope:
        agent_id = str(agent_id).strip()
        model_id = str(model_id).strip()
        initial_intent = str(initial_intent).strip()
        command = tuple(str(part) for part in initial_command)

        if not agent_id:
            raise AgentIsolationError("agent_id cannot be empty")
        if not model_id:
            raise AgentIsolationError("model_id cannot be empty")
        if not initial_intent:
            raise AgentIsolationError("initial_intent cannot be empty")
        if not command or not command[0]:
            raise AgentIsolationError("initial_command cannot be empty")

        with self._lock:
            if agent_id in self._agents:
                raise AgentIsolationError(
                    f"agent already registered: {agent_id}"
                )

            parent_caps = None
            parent_lineage = "ROOT"

            if parent_agent_id is not None:
                parent = self._get_active_unlocked(parent_agent_id)
                parent_caps = parent.granted_capabilities
                parent_lineage = parent.lineage_hash

                if Capability.AGENT_SPAWN not in parent_caps:
                    raise AgentIsolationError(
                        "parent lacks agent.spawn capability"
                    )

                if not granted_capabilities.issubset(parent_caps):
                    raise AgentIsolationError(
                        "child capability set exceeds parent authority"
                    )

            intent_hash = _sha256_text(initial_intent)
            command_text = _command_text(command)
            command_hash = _sha256_text(command_text)

            lineage_payload = json.dumps(
                {
                    "agent_id": agent_id,
                    "model_id": model_id,
                    "intent_hash": intent_hash,
                    "initial_command_hash": command_hash,
                    "parent_agent_id": parent_agent_id,
                    "parent_lineage_hash": parent_lineage,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            lineage_hash = _sha256_text(lineage_payload)

            nonce = secrets.token_hex(16)
            sandbox_digest = _sha256_text(lineage_hash + ":" + nonce)
            sandbox_id = "bull-agent-" + sandbox_digest[:24]
            security_context_id = (
                "agent:" + agent_id + ":" + lineage_hash[:20]
            )

            envelope = AgentExecutionEnvelope(
                agent_id=agent_id,
                model_id=model_id,
                initial_intent=initial_intent,
                initial_command=command,
                provenance=tuple(provenance),
                granted_capabilities=frozenset(granted_capabilities),
                sandbox_id=sandbox_id,
                security_context_id=security_context_id,
                intent_hash=intent_hash,
                initial_command_hash=command_hash,
                lineage_hash=lineage_hash,
                parent_agent_id=parent_agent_id,
                parent_capabilities=parent_caps,
            )

            self._agents[agent_id] = envelope

            if self.ledger is not None:
                self.ledger.append_event(
                    "agent_registered",
                    self._audit_data(envelope),
                )

            return envelope

    def get(self, agent_id: str) -> AgentExecutionEnvelope:
        with self._lock:
            return self._get_active_unlocked(agent_id)

    def revoke(self, agent_id: str) -> None:
        with self._lock:
            envelope = self._get_active_unlocked(agent_id)
            self._revoked.add(envelope.agent_id)
            if self.ledger is not None:
                self.ledger.append_event(
                    "agent_revoked",
                    self._audit_data(envelope),
                )

    def assert_binding(
        self,
        *,
        agent_id: str,
        model_id: str,
        initial_intent: str,
        initial_command: Sequence[str],
    ) -> AgentExecutionEnvelope:
        """Fail closed if a caller tries to reuse an identity with new intent."""
        envelope = self.get(agent_id)
        if str(model_id) != envelope.model_id:
            raise AgentIsolationError("model identity drift detected")
        if _sha256_text(str(initial_intent).strip()) != envelope.intent_hash:
            raise AgentIsolationError("agent intent drift detected")
        if _sha256_text(_command_text(initial_command)) != (
            envelope.initial_command_hash
        ):
            raise AgentIsolationError("initial command drift detected")
        return envelope

    def record_event(
        self,
        *,
        agent_id: str,
        event_type: str,
        data: dict | None = None,
    ) -> str | None:
        """Append an agent-scoped event without logging bearer tokens/secrets."""
        with self._lock:
            envelope = self._get_active_unlocked(agent_id)
            if self.ledger is None:
                return None
            payload = {
                "agent": self._audit_data(envelope),
                "event": dict(data or {}),
            }
            return self.ledger.append_event(
                event_type,
                payload,
            )

    def _get_active_unlocked(
        self,
        agent_id: str,
    ) -> AgentExecutionEnvelope:
        try:
            envelope = self._agents[str(agent_id)]
        except KeyError:
            raise AgentIsolationError(
                f"unknown agent: {agent_id}"
            )
        if envelope.agent_id in self._revoked:
            raise AgentIsolationError(
                f"agent is revoked: {agent_id}"
            )
        return envelope

    @staticmethod
    def _audit_data(
        envelope: AgentExecutionEnvelope,
    ) -> dict:
        return {
            "agent_id": envelope.agent_id,
            "model_id": envelope.model_id,
            "sandbox_id": envelope.sandbox_id,
            "security_context_id": envelope.security_context_id,
            "parent_agent_id": envelope.parent_agent_id,
            "intent_hash": envelope.intent_hash,
            "initial_command_hash": envelope.initial_command_hash,
            "lineage_hash": envelope.lineage_hash,
            "initial_intent": envelope.initial_intent,
            "initial_command": list(envelope.initial_command),
            "provenance": [value.value for value in envelope.provenance],
            "granted_capabilities": sorted(
                capability.value
                for capability in envelope.granted_capabilities
            ),
        }

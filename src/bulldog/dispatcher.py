from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .agent_isolation import (
    AgentIsolationRegistry,
    AgentIsolationError,
)
from .canonicalizer import (
    TrustedExecutionContext,
    canonicalize_action,
)
from .egress_proxy import EgressBroker, EgressResponse
from .models import Capability
from .production_gate import verify_production_environment
from .runtime import BulldogRuntime
from .secret_broker import SecretBroker, request_secret


class DispatchDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class DispatchRequest:
    """Trusted wrapper around an untrusted model proposal."""

    proposal: dict
    trusted: TrustedExecutionContext
    granted_capabilities: frozenset[Capability]
    parent_capabilities: frozenset[Capability] | None = None


class CapabilityDispatcher:
    """
    Central BULL reference-monitor entry point.

    In multi-agent mode, agent identity, sandbox identity, lineage, initial
    intent, bootstrap command, parent authority, and broker identity are all
    taken from the trusted registry rather than model-controlled fields.
    """

    def __init__(
        self,
        *,
        runtime: BulldogRuntime | None = None,
        secret_broker: SecretBroker | None = None,
        egress_broker: EgressBroker | None = None,
        agent_registry: AgentIsolationRegistry | None = None,
        production_mode: bool = False,
    ):
        if production_mode:
            verify_production_environment(
                package_root=Path(__file__).resolve().parent,
            )

        self.runtime = runtime if runtime is not None else BulldogRuntime()
        self.secret_broker = secret_broker
        self.egress_broker = egress_broker
        self.agent_registry = agent_registry
        self.production_mode = bool(production_mode)

        # If the registry has a tamper-evident ledger, bind runtime action
        # decisions to the same chain when possible. Refuse two different
        # ledgers because that would split the audit history.
        if self.agent_registry is not None and self.agent_registry.ledger is not None:
            engine = getattr(self.runtime, "engine", None)
            if engine is not None:
                existing = getattr(engine, "ledger", None)
                if existing is None:
                    engine.ledger = self.agent_registry.ledger
                elif existing is not self.agent_registry.ledger:
                    raise DispatchDenied(
                        "runtime and agent registry must share one audit ledger"
                    )

    def canonicalize(self, request: DispatchRequest):
        return canonicalize_action(
            request.proposal,
            trusted=request.trusted,
            granted_capabilities=request.granted_capabilities,
            parent_capabilities=request.parent_capabilities,
        )

    def execute(
        self,
        request: DispatchRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float = 30.0,
    ):
        action = self.canonicalize(request)
        return self.runtime.execute(
            action,
            command,
            project_root=project_root,
            timeout=timeout,
        )

    def _request_for_agent(
        self,
        *,
        agent_id: str,
        proposal: dict,
    ) -> DispatchRequest:
        if self.agent_registry is None:
            raise DispatchDenied("agent isolation registry is not configured")
        try:
            envelope = self.agent_registry.get(agent_id)
        except AgentIsolationError as exc:
            raise DispatchDenied(str(exc)) from exc

        return DispatchRequest(
            proposal=proposal,
            trusted=envelope.trusted_context(),
            granted_capabilities=envelope.granted_capabilities,
            parent_capabilities=envelope.parent_capabilities,
        )

    def execute_agent(
        self,
        *,
        agent_id: str,
        proposal: dict,
        command: Sequence[str],
        project_root: str | Path,
        timeout: float = 30.0,
    ):
        request = self._request_for_agent(
            agent_id=agent_id,
            proposal=proposal,
        )
        return self.execute(
            request,
            command,
            project_root=project_root,
            timeout=timeout,
        )

    def get_secret(
        self,
        *,
        token: str,
        name: str,
        sandbox_id: str | None = None,
        timeout: float = 3.0,
    ) -> str:
        if self.agent_registry is not None:
            raise DispatchDenied(
                "unscoped secret access is disabled in multi-agent mode"
            )
        if self.secret_broker is None:
            raise DispatchDenied("secret broker is not configured")

        return request_secret(
            socket_path=self.secret_broker.socket_path,
            token=token,
            name=name,
            sandbox_id=sandbox_id,
            timeout=timeout,
        )

    def get_secret_for_agent(
        self,
        *,
        agent_id: str,
        token: str,
        name: str,
        timeout: float = 3.0,
    ) -> str:
        if self.secret_broker is None:
            raise DispatchDenied("secret broker is not configured")
        if self.agent_registry is None:
            raise DispatchDenied("agent isolation registry is not configured")

        try:
            envelope = self.agent_registry.get(agent_id)
        except AgentIsolationError as exc:
            raise DispatchDenied(str(exc)) from exc

        try:
            value = request_secret(
                socket_path=self.secret_broker.socket_path,
                token=token,
                name=name,
                sandbox_id=envelope.sandbox_id,
                timeout=timeout,
            )
        except Exception as exc:
            self.agent_registry.record_event(
                agent_id=agent_id,
                event_type="agent_secret_access",
                data={
                    "name": str(name),
                    "allowed": False,
                    "error_type": type(exc).__name__,
                },
            )
            raise

        self.agent_registry.record_event(
            agent_id=agent_id,
            event_type="agent_secret_access",
            data={
                "name": str(name),
                "allowed": True,
            },
        )
        return value

    def fetch_egress(
        self,
        *,
        url: str,
        method: str = "GET",
    ) -> EgressResponse:
        if self.agent_registry is not None:
            raise DispatchDenied(
                "unscoped egress is disabled in multi-agent mode"
            )
        if self.egress_broker is None:
            raise DispatchDenied("egress broker is not configured")
        return self.egress_broker.fetch(
            method=method,
            url=url,
        )

    def fetch_egress_for_agent(
        self,
        *,
        agent_id: str,
        url: str,
        method: str = "GET",
    ) -> EgressResponse:
        if self.egress_broker is None:
            raise DispatchDenied("egress broker is not configured")
        if self.agent_registry is None:
            raise DispatchDenied("agent isolation registry is not configured")

        try:
            envelope = self.agent_registry.get(agent_id)
        except AgentIsolationError as exc:
            raise DispatchDenied(str(exc)) from exc

        required = (
            Capability.NETWORK_POST
            if method.upper() not in {"GET", "HEAD"}
            else Capability.NETWORK_OUTBOUND
        )
        if required not in envelope.granted_capabilities:
            self.agent_registry.record_event(
                agent_id=agent_id,
                event_type="agent_egress",
                data={
                    "method": method.upper(),
                    "url": str(url),
                    "allowed": False,
                    "reason": f"missing {required.value}",
                },
            )
            raise DispatchDenied(
                f"agent lacks {required.value} capability"
            )

        try:
            response = self.egress_broker.fetch(
                method=method,
                url=url,
            )
        except Exception as exc:
            self.agent_registry.record_event(
                agent_id=agent_id,
                event_type="agent_egress",
                data={
                    "method": method.upper(),
                    "url": str(url),
                    "allowed": False,
                    "error_type": type(exc).__name__,
                },
            )
            raise

        self.agent_registry.record_event(
            agent_id=agent_id,
            event_type="agent_egress",
            data={
                "method": method.upper(),
                "url": str(url),
                "allowed": True,
                "status": response.status,
            },
        )
        return response

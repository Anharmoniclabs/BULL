from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

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
    """
    Trusted wrapper around an untrusted model proposal.

    Security-critical identity and provenance live in
    TrustedExecutionContext, not in model-controlled proposal fields.
    """

    proposal: dict
    trusted: TrustedExecutionContext
    granted_capabilities: frozenset[Capability]
    parent_capabilities: frozenset[Capability] | None = None


class CapabilityDispatcher:
    """
    Central BULL reference-monitor entry point.

    Model-provided actor/provenance/security-context metadata is ignored
    by the trusted canonicalizer. Production mode additionally requires
    host certification, a verified integrity manifest, and a configured
    remote audit anchor before privileged dispatch is enabled.
    """

    def __init__(
        self,
        *,
        runtime: BulldogRuntime | None = None,
        secret_broker: SecretBroker | None = None,
        egress_broker: EgressBroker | None = None,
        production_mode: bool = False,
    ):
        if production_mode:
            verify_production_environment(
                package_root=Path(__file__).resolve().parent,
            )

        self.runtime = (
            runtime
            if runtime is not None
            else BulldogRuntime()
        )
        self.secret_broker = secret_broker
        self.egress_broker = egress_broker
        self.production_mode = bool(production_mode)

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

    def get_secret(
        self,
        *,
        token: str,
        name: str,
        sandbox_id: str | None = None,
        timeout: float = 3.0,
    ) -> str:
        if self.secret_broker is None:
            raise DispatchDenied("secret broker is not configured")

        return request_secret(
            socket_path=self.secret_broker.socket_path,
            token=token,
            name=name,
            sandbox_id=sandbox_id,
            timeout=timeout,
        )

    def fetch_egress(
        self,
        *,
        url: str,
        method: str = "GET",
    ) -> EgressResponse:
        if self.egress_broker is None:
            raise DispatchDenied("egress broker is not configured")
        return self.egress_broker.fetch(
            method=method,
            url=url,
        )

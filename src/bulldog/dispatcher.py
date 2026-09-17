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
from .secret_broker import SecretBroker, SecretGrant, request_secret
from .security_domain import (
    SecurityDomainError,
    SecurityDomainRegistry,
)


class DispatchDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class DispatchRequest:
    """
    Trusted wrapper around an untrusted model proposal.

    In legacy mode, security-critical identity/provenance comes from `trusted`.
    When a SecurityDomainRegistry is configured, `domain_id` becomes the
    authority key and the registry supplies the trusted context; model/request
    metadata cannot replace it.
    """

    proposal: dict
    trusted: TrustedExecutionContext
    granted_capabilities: frozenset[Capability]
    parent_capabilities: frozenset[Capability] | None = None
    domain_id: str | None = None


class CapabilityDispatcher:
    """
    Central BULL reference-monitor entry point.

    Domain mode adds a host-issued multi-agent authority boundary:
      - capabilities must fit the domain ceiling
      - child authority is derived from the registered parent
      - siblings/descendants share root behavioral history
      - secrets are automatically bound to the calling domain
      - egress is intersected with a per-domain exact-host allowlist
      - hard policy violations freeze the whole cooperating domain tree
    """

    def __init__(
        self,
        *,
        runtime: BulldogRuntime | None = None,
        secret_broker: SecretBroker | None = None,
        egress_broker: EgressBroker | None = None,
        domain_registry: SecurityDomainRegistry | None = None,
        production_mode: bool = False,
        freeze_on_violation: bool = True,
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
        self.domain_registry = domain_registry
        self.production_mode = bool(production_mode)
        self.freeze_on_violation = bool(freeze_on_violation)

    def _trusted_context_for(
        self,
        request: DispatchRequest,
    ) -> tuple[
        TrustedExecutionContext,
        frozenset[Capability] | None,
    ]:
        if self.domain_registry is None:
            return request.trusted, request.parent_capabilities

        if not request.domain_id:
            raise DispatchDenied(
                "domain-enabled dispatcher requires a security domain"
            )

        try:
            self.domain_registry.assert_capabilities(
                request.domain_id,
                request.granted_capabilities,
            )
            trusted = self.domain_registry.trusted_context(
                request.domain_id
            )
            parent_capabilities = self.domain_registry.parent_capabilities(
                request.domain_id
            )
        except SecurityDomainError as exc:
            raise DispatchDenied(str(exc)) from exc

        return trusted, parent_capabilities

    def canonicalize(self, request: DispatchRequest):
        trusted, parent_capabilities = self._trusted_context_for(request)
        return canonicalize_action(
            request.proposal,
            trusted=trusted,
            granted_capabilities=request.granted_capabilities,
            parent_capabilities=parent_capabilities,
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

        if self.domain_registry is not None:
            assert request.domain_id is not None
            try:
                self.domain_registry.record_dispatch(
                    request.domain_id,
                    capability=action.capability,
                    resource=action.resource,
                    command=command,
                )
            except SecurityDomainError as exc:
                raise DispatchDenied(str(exc)) from exc

        result = self.runtime.execute(
            action,
            command,
            project_root=project_root,
            timeout=timeout,
        )

        if (
            self.domain_registry is not None
            and self.freeze_on_violation
            and request.domain_id is not None
        ):
            behavioral_violation = any(
                str(reason).startswith("session behavior:")
                for reason in result.evaluation.reasons
            )

            if result.evaluation.hard_block or behavioral_violation:
                domain = self.domain_registry.get(request.domain_id)
                reason = (
                    "hard policy block"
                    if result.evaluation.hard_block
                    else "cross-agent behavioral violation"
                )
                self.domain_registry.freeze_root(
                    domain.root_domain_id,
                    reason,
                )

        return result

    def issue_domain_secret_grant(
        self,
        *,
        domain_id: str,
        allowed_names: set[str] | frozenset[str],
        ttl_seconds: float = 60.0,
        max_uses: int = 1,
    ) -> SecretGrant:
        if self.secret_broker is None:
            raise DispatchDenied("secret broker is not configured")
        if self.domain_registry is None:
            raise DispatchDenied(
                "domain secret grants require a security domain registry"
            )

        try:
            self.domain_registry.require_active(domain_id)
        except SecurityDomainError as exc:
            raise DispatchDenied(str(exc)) from exc

        return self.secret_broker.issue_grant(
            allowed_names=allowed_names,
            ttl_seconds=ttl_seconds,
            sandbox_id=domain_id,
            max_uses=max_uses,
        )

    def get_secret(
        self,
        *,
        token: str,
        name: str,
        sandbox_id: str | None = None,
        domain_id: str | None = None,
        timeout: float = 3.0,
    ) -> str:
        if self.secret_broker is None:
            raise DispatchDenied("secret broker is not configured")

        if self.domain_registry is not None:
            if not domain_id:
                raise DispatchDenied(
                    "domain-enabled dispatcher requires domain_id for secrets"
                )
            try:
                self.domain_registry.require_active(domain_id)
            except SecurityDomainError as exc:
                raise DispatchDenied(str(exc)) from exc

            if sandbox_id is not None and sandbox_id != domain_id:
                raise DispatchDenied(
                    "caller cannot select another domain's sandbox identity"
                )
            sandbox_id = domain_id

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
        domain_id: str | None = None,
    ) -> EgressResponse:
        if self.egress_broker is None:
            raise DispatchDenied("egress broker is not configured")

        if self.domain_registry is not None:
            if not domain_id:
                raise DispatchDenied(
                    "domain-enabled dispatcher requires domain_id for egress"
                )
            try:
                self.domain_registry.assert_egress(domain_id, url)
            except SecurityDomainError as exc:
                raise DispatchDenied(str(exc)) from exc

        return self.egress_broker.fetch(
            method=method,
            url=url,
        )

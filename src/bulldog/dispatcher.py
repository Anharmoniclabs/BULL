from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Sequence

from .canonicalizer import (
    ActionCanonicalizationError,
    TrustedExecutionContext,
    canonicalize_action,
    canonicalize_filesystem_resource,
    canonicalize_resource,
)
from .egress_proxy import EgressBroker, EgressResponse
from .models import Capability, Decision
from .production_gate import verify_production_environment
from .runtime import BulldogRuntime
from .secret_broker import SecretBroker, SecretGrant, request_secret
from .security_domain import (
    SecurityDomainError,
    SecurityDomainRegistry,
    hash_command,
)


class DispatchDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class DispatchRequest:
    """Trusted wrapper around an untrusted model proposal.

    ``authorized_command`` is host-controlled. For process execution it must
    contain the exact argv the host approved; model-provided argv is not a
    substitute for this trusted binding.
    """

    proposal: dict
    trusted: TrustedExecutionContext
    granted_capabilities: frozenset[Capability]
    parent_capabilities: frozenset[Capability] | None = None
    domain_id: str | None = None
    authorized_command: tuple[str, ...] | None = None


class CapabilityDispatcher:
    """
    Central BULL reference-monitor entry point.

    Domain mode adds a host-issued multi-agent authority boundary:
      - capabilities must fit the domain ceiling
      - child authority is derived from the registered parent
      - siblings/descendants share root behavioral history
      - secrets require credential authority and are bound to the domain
      - egress requires network authority AND an exact-host domain grant
      - hard policy violations freeze the whole cooperating domain tree
      - domain lifecycle/broker/dispatch events can share the runtime ledger

    All process launches and broker operations are bound to the authority
    being exercised. Filesystem read authority cannot drive a command, exact
    argv must be host-authorized, and legacy broker calls cannot bypass policy.
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

        self.runtime = runtime if runtime is not None else BulldogRuntime()
        self.secret_broker = secret_broker
        self.egress_broker = egress_broker
        self.domain_registry = domain_registry
        self.production_mode = bool(production_mode)
        self.freeze_on_violation = bool(freeze_on_violation)

        if self.domain_registry is not None and self.domain_registry.ledger is not None:
            engine = getattr(self.runtime, "engine", None)
            if engine is not None:
                existing = getattr(engine, "ledger", None)
                if existing is None:
                    engine.ledger = self.domain_registry.ledger
                elif existing is not self.domain_registry.ledger:
                    raise DispatchDenied(
                        "runtime and security-domain registry must share one audit ledger"
                    )

    def _trusted_context_for(
        self,
        request: DispatchRequest,
    ) -> tuple[TrustedExecutionContext, frozenset[Capability] | None]:
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
            trusted = self.domain_registry.trusted_context(request.domain_id)
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

    @staticmethod
    def _bind_command(
        action,
        request: DispatchRequest,
        command: Sequence[str],
    ) -> str:
        if action.capability != Capability.PROCESS_EXEC:
            raise DispatchDenied(
                "command dispatch requires process.exec authority"
            )
        if not command:
            raise DispatchDenied("command cannot be empty")
        if request.authorized_command is None:
            raise DispatchDenied(
                "process.exec requires host-authorized full argv"
            )

        actual = tuple(str(part) for part in command)
        authorized = tuple(str(part) for part in request.authorized_command)

        if not authorized:
            raise DispatchDenied("authorized command cannot be empty")
        if any("\x00" in part for part in actual + authorized):
            raise DispatchDenied("NUL byte in command argv")

        try:
            executable = canonicalize_filesystem_resource(actual[0])
            authorized_executable = canonicalize_filesystem_resource(
                authorized[0]
            )
        except ActionCanonicalizationError as exc:
            raise DispatchDenied(
                "invalid command executable: " + str(exc)
            ) from exc

        if authorized_executable != action.resource:
            raise DispatchDenied(
                "authorized argv executable does not match action resource: "
                f"{authorized_executable} != {action.resource}"
            )
        if executable != action.resource:
            raise DispatchDenied(
                "command executable does not match authorized resource: "
                f"{executable} != {action.resource}"
            )
        if actual != authorized:
            raise DispatchDenied(
                "command argv does not match host-authorized argv"
            )

        digest = hash_command(actual)
        if digest is None:
            raise DispatchDenied("failed to hash authorized command")
        return digest

    def _authorize_legacy_broker_action(
        self,
        *,
        request: DispatchRequest | None,
        expected_capability: Capability,
        expected_resource: str,
    ):
        """Authorize a non-domain broker operation through BULL policy.

        Host-side brokers have no later sandbox transition. Therefore only an
        explicit ALLOW may reach the broker. SANDBOX, ESCALATE, and DENY all
        fail closed rather than silently becoming host-side permission.
        """
        if request is None:
            raise DispatchDenied(
                "broker operation requires an authorized DispatchRequest"
            )

        action = self.canonicalize(request)
        if action.capability != expected_capability:
            raise DispatchDenied(
                "broker request capability mismatch: expected "
                f"{expected_capability.value}, got {action.capability.value}"
            )

        try:
            canonical_expected = canonicalize_resource(
                action.operation,
                expected_resource,
            )
        except ActionCanonicalizationError as exc:
            raise DispatchDenied(str(exc)) from exc

        if action.resource != canonical_expected:
            raise DispatchDenied(
                "broker resource does not match authorized resource"
            )

        engine = getattr(self.runtime, "engine", None)
        evaluate = getattr(engine, "evaluate", None)
        if not callable(evaluate):
            raise DispatchDenied(
                "broker authorization requires the BULL policy engine"
            )

        evaluation = evaluate(action)
        if evaluation.decision != Decision.ALLOW:
            raise DispatchDenied(
                "broker operation requires explicit ALLOW; got "
                f"{evaluation.decision.value}: "
                + "; ".join(evaluation.reasons)
            )

        return action

    def execute(
        self,
        request: DispatchRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float = 30.0,
    ):
        action = self.canonicalize(request)
        authorized_command_hash = self._bind_command(
            action,
            request,
            command,
        )
        action = replace(
            action,
            metadata={
                **action.metadata,
                "authorized_command_hash": authorized_command_hash,
            },
        )

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
            domain = self.domain_registry.require_active(domain_id)
            if Capability.CREDENTIAL_READ not in domain.capability_ceiling:
                raise SecurityDomainError(
                    "domain lacks credential.read authority"
                )
        except SecurityDomainError as exc:
            raise DispatchDenied(str(exc)) from exc

        grant = self.secret_broker.issue_grant(
            allowed_names=allowed_names,
            ttl_seconds=ttl_seconds,
            sandbox_id=domain_id,
            max_uses=max_uses,
        )
        self.domain_registry.record_broker_event(
            domain_id,
            broker="secret",
            operation="grant",
            allowed=True,
            detail={
                "allowed_names": sorted(str(name) for name in allowed_names),
                "max_uses": int(max_uses),
            },
        )
        return grant

    def get_secret(
        self,
        *,
        token: str,
        name: str,
        sandbox_id: str | None = None,
        domain_id: str | None = None,
        request: DispatchRequest | None = None,
        timeout: float = 3.0,
    ) -> str:
        if self.secret_broker is None:
            raise DispatchDenied("secret broker is not configured")

        authorized_name = str(name)

        if self.domain_registry is not None:
            if not domain_id:
                raise DispatchDenied(
                    "domain-enabled dispatcher requires domain_id for secrets"
                )
            try:
                domain = self.domain_registry.require_active(domain_id)
                if Capability.CREDENTIAL_READ not in domain.capability_ceiling:
                    raise SecurityDomainError(
                        "domain lacks credential.read authority"
                    )
            except SecurityDomainError as exc:
                raise DispatchDenied(str(exc)) from exc

            if sandbox_id is not None and sandbox_id != domain_id:
                raise DispatchDenied(
                    "caller cannot select another domain's sandbox identity"
                )
            sandbox_id = domain_id
        else:
            action = self._authorize_legacy_broker_action(
                request=request,
                expected_capability=Capability.CREDENTIAL_READ,
                expected_resource=name,
            )
            authorized_name = action.resource

        try:
            value = request_secret(
                socket_path=self.secret_broker.socket_path,
                token=token,
                name=authorized_name,
                sandbox_id=sandbox_id,
                timeout=timeout,
            )
        except Exception as exc:
            if self.domain_registry is not None and domain_id is not None:
                self.domain_registry.record_broker_event(
                    domain_id,
                    broker="secret",
                    operation="get",
                    allowed=False,
                    detail={
                        "name": str(name),
                        "error_type": type(exc).__name__,
                    },
                )
            raise

        if self.domain_registry is not None and domain_id is not None:
            self.domain_registry.record_broker_event(
                domain_id,
                broker="secret",
                operation="get",
                allowed=True,
                detail={"name": str(name)},
            )
        return value

    def fetch_egress(
        self,
        *,
        url: str,
        method: str = "GET",
        domain_id: str | None = None,
        request: DispatchRequest | None = None,
    ) -> EgressResponse:
        if self.egress_broker is None:
            raise DispatchDenied("egress broker is not configured")

        authorized_url = str(url)
        required = (
            Capability.NETWORK_OUTBOUND
            if method.upper() in {"GET", "HEAD"}
            else Capability.NETWORK_POST
        )

        if self.domain_registry is not None:
            if not domain_id:
                raise DispatchDenied(
                    "domain-enabled dispatcher requires domain_id for egress"
                )

            try:
                domain = self.domain_registry.require_active(domain_id)
                if required not in domain.capability_ceiling:
                    raise SecurityDomainError(
                        f"domain lacks {required.value} authority"
                    )
                self.domain_registry.assert_egress(domain_id, url)
            except SecurityDomainError as exc:
                try:
                    self.domain_registry.record_broker_event(
                        domain_id,
                        broker="egress",
                        operation=method.upper(),
                        allowed=False,
                        detail={
                            "url": str(url),
                            "reason": str(exc),
                        },
                    )
                except SecurityDomainError:
                    pass
                raise DispatchDenied(str(exc)) from exc
        else:
            action = self._authorize_legacy_broker_action(
                request=request,
                expected_capability=required,
                expected_resource=url,
            )
            authorized_url = action.resource

        try:
            response = self.egress_broker.fetch(
                method=method,
                url=authorized_url,
            )
        except Exception as exc:
            if self.domain_registry is not None and domain_id is not None:
                self.domain_registry.record_broker_event(
                    domain_id,
                    broker="egress",
                    operation=method.upper(),
                    allowed=False,
                    detail={
                        "url": str(url),
                        "error_type": type(exc).__name__,
                    },
                )
            raise

        if self.domain_registry is not None and domain_id is not None:
            self.domain_registry.record_broker_event(
                domain_id,
                broker="egress",
                operation=method.upper(),
                allowed=True,
                detail={
                    "url": str(url),
                    "status": int(response.status),
                },
            )
        return response

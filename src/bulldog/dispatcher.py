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
from .models import ActionRequest, Capability, Decision
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

    ``authorized_command`` is host-owned authorization data. It is deliberately
    separate from ``proposal`` so a model cannot approve its own argv. In
    production mode it is mandatory for process execution and must match the
    complete command vector exactly.
    """

    proposal: dict
    trusted: TrustedExecutionContext
    granted_capabilities: frozenset[Capability]
    parent_capabilities: frozenset[Capability] | None = None
    domain_id: str | None = None
    authorized_command: tuple[str, ...] | None = None


class CapabilityDispatcher:
    """Central BULL reference-monitor entry point.

    Broker operations are fail-closed: only an explicit ``Decision.ALLOW`` may
    reach a host secret/network broker. ``SANDBOX`` is not treated as approval
    because broker calls do not execute inside the workload sandbox.

    In production, process execution is bound to the complete host-authorized
    argv vector in addition to the executable/resource binding.
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
        self.production_mode = bool(production_mode)

        if self.production_mode:
            verify_production_environment(
                package_root=Path(__file__).resolve().parent,
            )

        self.runtime = (
            runtime
            if runtime is not None
            else BulldogRuntime(
                require_full_argv_binding=self.production_mode,
            )
        )
        self.secret_broker = secret_broker
        self.egress_broker = egress_broker
        self.domain_registry = domain_registry
        self.freeze_on_violation = bool(freeze_on_violation)

        if self.production_mode:
            self._verify_actual_production_runtime()

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

    def _verify_actual_production_runtime(self) -> None:
        """Bind production certification to the runtime that will actually run."""
        sandbox = getattr(self.runtime, "sandbox", None)
        failures = []

        if not getattr(self.runtime, "malware_scan_required", False):
            failures.append("runtime malware scanning is not required")
        if getattr(self.runtime, "malware_scanner", None) is None:
            failures.append("runtime malware scanner is unavailable")
        if not getattr(self.runtime, "require_full_argv_binding", False):
            failures.append("runtime full argv binding is disabled")
        if getattr(self.runtime, "trace", None) is None:
            failures.append("runtime transition verifier is unavailable")
        if sandbox is None:
            failures.append("runtime sandbox is unavailable")
        else:
            if getattr(sandbox, "seccomp_profile", None) != "strict":
                failures.append("actual runtime sandbox is not using strict seccomp")
            if getattr(sandbox, "require_attestation", False) is not True:
                failures.append("actual runtime sandbox attestation is disabled")

        if failures:
            raise DispatchDenied(
                "production runtime wiring rejected: " + "; ".join(failures)
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

    def canonicalize(self, request: DispatchRequest) -> ActionRequest:
        trusted, parent_capabilities = self._trusted_context_for(request)
        return canonicalize_action(
            request.proposal,
            trusted=trusted,
            granted_capabilities=request.granted_capabilities,
            parent_capabilities=parent_capabilities,
        )

    def _bind_execution(
        self,
        action: ActionRequest,
        command: Sequence[str],
        request: DispatchRequest,
    ) -> ActionRequest:
        if action.capability != Capability.PROCESS_EXEC:
            raise DispatchDenied("command dispatch requires process.exec authority")
        if not command:
            raise DispatchDenied("command cannot be empty")

        actual_command = tuple(str(part) for part in command)
        try:
            executable = canonicalize_filesystem_resource(actual_command[0])
        except ActionCanonicalizationError as exc:
            raise DispatchDenied(
                "invalid command executable: " + str(exc)
            ) from exc

        if executable != action.resource:
            raise DispatchDenied(
                "command executable does not match authorized resource: "
                f"{executable} != {action.resource}"
            )

        authorized = request.authorized_command
        if self.production_mode and authorized is None:
            raise DispatchDenied(
                "production command dispatch requires host-authorized full argv"
            )

        if authorized is None:
            return action

        authorized_tuple = tuple(str(part) for part in authorized)
        if actual_command != authorized_tuple:
            raise DispatchDenied(
                "command argv does not match host-authorized argv"
            )

        argv_hash = hash_command(authorized_tuple)
        metadata = dict(action.metadata)
        metadata["authorized_argv_hash"] = str(argv_hash)
        metadata["actual_argv_hash"] = str(hash_command(actual_command))
        return replace(action, metadata=metadata)

    def _evaluate_broker_action(self, action: ActionRequest) -> ActionRequest:
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

    def _authorize_legacy_broker_action(
        self,
        *,
        request: DispatchRequest | None,
        expected_capability: Capability,
        expected_resource: str,
    ) -> ActionRequest:
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

        return self._evaluate_broker_action(action)

    def _authorize_domain_broker_action(
        self,
        *,
        domain_id: str,
        operation: str,
        resource: str,
        expected_capability: Capability,
        task: str,
    ) -> ActionRequest:
        if self.domain_registry is None:
            raise DispatchDenied("security-domain registry is not configured")

        try:
            domain = self.domain_registry.require_active(domain_id)
            if expected_capability not in domain.capability_ceiling:
                raise SecurityDomainError(
                    f"domain lacks {expected_capability.value} authority"
                )
            trusted = self.domain_registry.trusted_context(domain_id)
            parent_capabilities = self.domain_registry.parent_capabilities(domain_id)
        except SecurityDomainError as exc:
            raise DispatchDenied(str(exc)) from exc

        action = canonicalize_action(
            {
                "task": task,
                "operation": operation,
                "resource": resource,
            },
            trusted=trusted,
            granted_capabilities=domain.capability_ceiling,
            parent_capabilities=parent_capabilities,
        )
        if action.capability != expected_capability:
            raise DispatchDenied(
                "domain broker capability mismatch: expected "
                f"{expected_capability.value}, got {action.capability.value}"
            )
        return self._evaluate_broker_action(action)

    def execute(
        self,
        request: DispatchRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float = 30.0,
    ):
        action = self.canonicalize(request)
        action = self._bind_execution(action, command, request)

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
            except SecurityDomainError as exc:
                raise DispatchDenied(str(exc)) from exc

            if sandbox_id is not None and sandbox_id != domain_id:
                raise DispatchDenied(
                    "caller cannot select another domain's sandbox identity"
                )
            sandbox_id = domain_id
            action = self._authorize_domain_broker_action(
                domain_id=domain_id,
                operation="secret.get",
                resource=name,
                expected_capability=Capability.CREDENTIAL_READ,
                task="brokered secret access",
            )
            authorized_name = action.resource
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
        method_upper = method.upper()
        required = (
            Capability.NETWORK_OUTBOUND
            if method_upper in {"GET", "HEAD"}
            else Capability.NETWORK_POST
        )

        if self.domain_registry is not None:
            if not domain_id:
                raise DispatchDenied(
                    "domain-enabled dispatcher requires domain_id for egress"
                )

            try:
                self.domain_registry.assert_egress(domain_id, url)
            except SecurityDomainError as exc:
                try:
                    self.domain_registry.record_broker_event(
                        domain_id,
                        broker="egress",
                        operation=method_upper,
                        allowed=False,
                        detail={"url": str(url), "reason": str(exc)},
                    )
                except SecurityDomainError:
                    pass
                raise DispatchDenied(str(exc)) from exc

            operation = (
                "head"
                if method_upper == "HEAD"
                else "fetch"
                if method_upper == "GET"
                else "post"
            )
            action = self._authorize_domain_broker_action(
                domain_id=domain_id,
                operation=operation,
                resource=url,
                expected_capability=required,
                task="brokered network egress",
            )
            authorized_url = action.resource
        else:
            action = self._authorize_legacy_broker_action(
                request=request,
                expected_capability=required,
                expected_resource=url,
            )
            authorized_url = action.resource

        try:
            response = self.egress_broker.fetch(
                method=method_upper,
                url=authorized_url,
            )
        except Exception as exc:
            if self.domain_registry is not None and domain_id is not None:
                self.domain_registry.record_broker_event(
                    domain_id,
                    broker="egress",
                    operation=method_upper,
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
                operation=method_upper,
                allowed=True,
                detail={
                    "url": str(url),
                    "status": int(response.status),
                },
            )
        return response

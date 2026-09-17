from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
from typing import Sequence
import warnings

from .audit import AuditLedger
from .dispatcher import CapabilityDispatcher, DispatchDenied, DispatchRequest
from .engine import BulldogEngine
from .integrity import verify_integrity_manifest
from .malware_scanner import MalwareScanner
from .models import ActionRequest
from .namespace_sandbox import NamespaceSandbox
from .policy import DeterministicPolicy
from .policy_bundle import load_policy_bundle
from .production_gate import verify_production_environment
from .runtime import BulldogRuntime, ExecutionResult
from .security_domain import SecurityDomainError, hash_command
from .workspace_limits import WorkspaceBudget, production_snapshot_root


DEVELOPMENT_WARNING = (
    "UNSAFE DEVELOPMENT MODE — NOT AN ENFORCEMENT BOUNDARY. "
    "Use ProductionRuntime/ProductionDispatcher for security-sensitive workloads."
)


@dataclass(frozen=True)
class _ExecutionPermit:
    token: str
    argv_hash: str
    action_hash: str


def _action_hash(action: ActionRequest) -> str:
    payload = "\0".join(
        (
            action.actor,
            action.operation,
            action.resource,
            action.capability.value,
            action.metadata.get("domain_id", ""),
            action.metadata.get("root_domain_id", ""),
        )
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _verify_broker_boundary(label: str, broker: object | None) -> None:
    if broker is None:
        return
    if getattr(broker, "peer_auth_enforced", False) is not True:
        raise DispatchDenied(
            f"production {label} broker must enforce Unix peer credentials"
        )
    raw = getattr(broker, "socket_path", None)
    if raw is None:
        raise DispatchDenied(f"production {label} broker has no Unix socket path")
    path = Path(raw)
    if not path.is_absolute():
        raise DispatchDenied(
            f"production {label} broker socket path must be absolute"
        )
    try:
        parent = path.parent.resolve(strict=True)
        mode = parent.stat().st_mode
    except OSError as exc:
        raise DispatchDenied(
            f"production {label} broker socket parent is unavailable: {exc}"
        ) from exc
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise DispatchDenied(
            f"production {label} broker socket parent is group/world writable"
        )


class DevelopmentRuntime(BulldogRuntime):
    """Explicitly weak/development runtime."""

    def __init__(self, **kwargs):
        warnings.warn(DEVELOPMENT_WARNING, RuntimeWarning, stacklevel=2)
        kwargs.setdefault("require_full_argv_binding", False)
        super().__init__(**kwargs)


class ProductionRuntime(BulldogRuntime):
    """Fail-closed production runtime assembled from verified host state."""

    production_boundary = True

    def __init__(self, **kwargs):
        if kwargs:
            forbidden = ", ".join(sorted(kwargs))
            raise TypeError(
                "ProductionRuntime does not accept caller-supplied security "
                f"components ({forbidden}); use the signed deployment profile"
            )

        package_root = Path(__file__).resolve().parent
        verify_production_environment(package_root=package_root)

        self._package_root = package_root
        self._integrity_manifest_path = Path(
            os.environ["BULL_INTEGRITY_MANIFEST"]
        ).resolve(strict=True)
        self._integrity_key = os.environ["BULL_INTEGRITY_MANIFEST_KEY"]
        self._policy_bundle_path = Path(
            os.environ["BULL_POLICY_BUNDLE"]
        ).resolve(strict=True)
        self._policy_key = os.environ["BULL_POLICY_BUNDLE_KEY"]

        policy_bundle = load_policy_bundle(
            self._policy_bundle_path,
            self._policy_key,
        )
        policy = DeterministicPolicy(
            project_root=policy_bundle.project_root,
            global_capability_ceiling=policy_bundle.capability_ceiling,
        )

        ledger = AuditLedger(
            os.environ["BULL_AUDIT_LEDGER"],
            remote_anchor_url=os.environ["BULL_REMOTE_AUDIT_ANCHOR_URL"],
            remote_anchor_key=os.environ["BULL_REMOTE_AUDIT_ANCHOR_KEY"],
        )
        engine = BulldogEngine(policy=policy, ledger=ledger)
        budget = WorkspaceBudget.from_environment()
        scanner = MalwareScanner(
            max_file_bytes=min(64 * 1024 * 1024, budget.max_file_bytes),
            max_scan_bytes=min(256 * 1024 * 1024, budget.max_total_bytes),
        )
        sandbox = NamespaceSandbox(
            seccomp_profile="strict",
            require_attestation=True,
        )

        super().__init__(
            engine=engine,
            sandbox=sandbox,
            malware_scanner=scanner,
            malware_scan_required=True,
            require_full_argv_binding=True,
            workspace_budget=budget,
            snapshot_root=production_snapshot_root(),
        )
        self._permit_key = secrets.token_bytes(32)

    def verify_trusted_state(self) -> None:
        """Reverify installed BULL and signed policy before privileged use."""
        manifest = json.loads(
            self._integrity_manifest_path.read_text(encoding="utf-8")
        )
        verify_integrity_manifest(
            self._package_root,
            manifest,
            signature_key=self._integrity_key,
            require_signature=True,
        )
        bundle = load_policy_bundle(self._policy_bundle_path, self._policy_key)
        policy = getattr(self.engine, "policy", None)
        if policy is None:
            raise DispatchDenied("production runtime policy disappeared")
        if bundle.project_root != getattr(policy, "project_root", None):
            raise DispatchDenied("signed policy project root changed after startup")
        if bundle.capability_ceiling != getattr(
            policy,
            "global_capability_ceiling",
            None,
        ):
            raise DispatchDenied("signed policy capability ceiling changed after startup")

    def _mint_dispatch_permit(
        self,
        action: ActionRequest,
        command: Sequence[str],
    ) -> _ExecutionPermit:
        argv_hash = str(hash_command(tuple(str(part) for part in command)))
        action_hash = _action_hash(action)
        message = f"{action_hash}:{argv_hash}".encode("utf-8")
        token = hmac.new(self._permit_key, message, hashlib.sha256).hexdigest()
        return _ExecutionPermit(
            token=token,
            argv_hash=argv_hash,
            action_hash=action_hash,
        )

    def _valid_permit(
        self,
        action: ActionRequest,
        command: Sequence[str],
        permit: object,
    ) -> bool:
        if not isinstance(permit, _ExecutionPermit):
            return False
        argv_hash = str(hash_command(tuple(str(part) for part in command)))
        action_hash = _action_hash(action)
        if permit.argv_hash != argv_hash or permit.action_hash != action_hash:
            return False
        message = f"{action_hash}:{argv_hash}".encode("utf-8")
        expected = hmac.new(self._permit_key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, permit.token)

    def execute(
        self,
        action: ActionRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float | None = 30.0,
        permit: object | None = None,
    ) -> ExecutionResult:
        if not self._valid_permit(action, command, permit):
            parent_has = (
                action.parent_capabilities is not None
                and action.capability in action.parent_capabilities
            )
            self.trace.reset(parent_has_capability=parent_has)
            return self._deny_binding(
                action,
                "production runtime requires a dispatcher-minted execution permit",
            )
        return super().execute(
            action,
            command,
            project_root=project_root,
            timeout=timeout,
        )


class DevelopmentDispatcher(CapabilityDispatcher):
    def __init__(self, *, runtime: BulldogRuntime | None = None, **kwargs):
        warnings.warn(DEVELOPMENT_WARNING, RuntimeWarning, stacklevel=2)
        super().__init__(
            runtime=runtime if runtime is not None else DevelopmentRuntime(),
            production_mode=False,
            **kwargs,
        )


class ProductionDispatcher(CapabilityDispatcher):
    def __init__(self, *, runtime: ProductionRuntime | None = None, **kwargs):
        production_runtime = runtime if runtime is not None else ProductionRuntime()
        if getattr(production_runtime, "production_boundary", False) is not True:
            raise DispatchDenied(
                "ProductionDispatcher requires a ProductionRuntime boundary"
            )
        _verify_broker_boundary("secret", kwargs.get("secret_broker"))
        _verify_broker_boundary("egress", kwargs.get("egress_broker"))
        super().__init__(
            runtime=production_runtime,
            production_mode=True,
            **kwargs,
        )

    def _evaluate_broker_action(self, action: ActionRequest) -> ActionRequest:
        self.runtime.verify_trusted_state()
        return super()._evaluate_broker_action(action)

    def execute(
        self,
        request: DispatchRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float = 30.0,
    ):
        self.runtime.verify_trusted_state()
        action = self._bind_execution(
            self.canonicalize(request),
            command,
            request,
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

        permit = self.runtime._mint_dispatch_permit(action, command)
        result = self.runtime.execute(
            action,
            command,
            project_root=project_root,
            timeout=timeout,
            permit=permit,
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
                self.domain_registry.freeze_root(
                    domain.root_domain_id,
                    "hard policy block"
                    if result.evaluation.hard_block
                    else "cross-agent behavioral violation",
                )
        return result

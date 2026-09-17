from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
from typing import Sequence
import warnings

from .audit import AuditLedger
from .dispatcher import CapabilityDispatcher
from .engine import BulldogEngine
from .malware_scanner import MalwareScanner
from .models import ActionRequest
from .namespace_sandbox import NamespaceSandbox
from .policy import DeterministicPolicy
from .policy_bundle import load_policy_bundle
from .production_gate import verify_production_environment
from .runtime import BulldogRuntime, ExecutionResult
from .security_domain import hash_command
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


class DevelopmentRuntime(BulldogRuntime):
    """Explicitly weak/development runtime.

    It exists so developers must opt into a name that communicates the weaker
    boundary instead of silently toggling a production Boolean off.
    """

    def __init__(self, **kwargs):
        warnings.warn(DEVELOPMENT_WARNING, RuntimeWarning, stacklevel=2)
        kwargs.setdefault("require_full_argv_binding", False)
        super().__init__(**kwargs)


class ProductionRuntime(BulldogRuntime):
    """Fail-closed production runtime assembled from verified host state."""

    def __init__(self, **kwargs):
        if kwargs:
            forbidden = ", ".join(sorted(kwargs))
            raise TypeError(
                "ProductionRuntime does not accept caller-supplied security "
                f"components ({forbidden}); use the signed deployment profile"
            )

        package_root = Path(__file__).resolve().parent
        verify_production_environment(package_root=package_root)

        policy_bundle = load_policy_bundle(
            os.environ["BULL_POLICY_BUNDLE"],
            os.environ["BULL_POLICY_BUNDLE_KEY"],
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
        super().__init__(
            runtime=production_runtime,
            production_mode=True,
            **kwargs,
        )

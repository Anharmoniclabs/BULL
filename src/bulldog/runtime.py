from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .canonicalizer import (
    ActionCanonicalizationError,
    canonicalize_filesystem_resource,
)
from .engine import BulldogEngine
from .filesystem_manifest import (
    FilesystemManifestViolation,
    build_manifest,
)
from .malware_scanner import (
    MalwareScanner,
    MalwareScannerError,
    MalwareScannerUnavailable,
)
from .models import (
    ActionRequest,
    Capability,
    Decision,
    Evaluation,
)
from .namespace_sandbox import (
    NamespaceSandbox,
    SandboxResult,
)
from .resource_limits import ResourceBudget
from .security_domain import hash_command
from .snapshot import (
    SnapshotViolation,
    create_snapshot,
    destroy_snapshot,
    hash_tree,
)
from .trace_runtime import RuntimeTraceVerifier


@dataclass(frozen=True)
class ExecutionResult:
    evaluation: Evaluation
    executed: bool
    sandboxed: bool
    review_required: bool
    returncode: int | None
    stdout: str
    stderr: str

    malware_scan_performed: bool = False
    malware_clean: bool | None = None
    malware_detections: tuple[str, ...] = ()

    trace_state: object | None = None


class BulldogRuntime:
    """
    Unified BULL runtime with live formal-trace enforcement.

    Security-critical execution uses an immutable snapshot. The exact
    snapshot that is scanned and hash-verified is the directory mounted
    into the namespace sandbox.

    The runtime is also a defense-in-depth execution reference monitor:
    launching an OS command requires PROCESS_EXEC authority, the authorized
    executable resource must match command[0], and hardened mode additionally
    requires the entire argv vector to match a host-authorized hash.
    """

    def __init__(
        self,
        *,
        engine: BulldogEngine | None = None,
        sandbox: NamespaceSandbox | None = None,
        malware_scanner: MalwareScanner | None = None,
        malware_scan_required: bool = True,
        trace_verifier: RuntimeTraceVerifier | None = None,
        resource_budget: ResourceBudget | None = None,
        require_full_argv_binding: bool = False,
    ):
        self.engine = engine if engine is not None else BulldogEngine()
        self.sandbox = sandbox if sandbox is not None else NamespaceSandbox()
        self.trace = (
            trace_verifier
            if trace_verifier is not None
            else RuntimeTraceVerifier()
        )
        self.resource_budget = (
            resource_budget
            if resource_budget is not None
            else ResourceBudget()
        )
        self.require_full_argv_binding = bool(require_full_argv_binding)

        self.malware_scan_required = bool(malware_scan_required)

        if malware_scanner is not None:
            self.malware_scanner = malware_scanner
        elif self.malware_scan_required:
            try:
                self.malware_scanner = MalwareScanner()
            except (
                MalwareScannerUnavailable,
                MalwareScannerError,
            ):
                self.malware_scanner = None
        else:
            self.malware_scanner = None

    def _binding_failure(
        self,
        action: ActionRequest,
        command: Sequence[str],
    ) -> str | None:
        if action.capability != Capability.PROCESS_EXEC:
            return "runtime command execution requires process.exec capability"

        if not command:
            return "runtime command cannot be empty"

        try:
            authorized_executable = canonicalize_filesystem_resource(
                action.resource
            )
            requested_executable = canonicalize_filesystem_resource(
                str(command[0])
            )
        except ActionCanonicalizationError as exc:
            return "invalid execution binding: " + str(exc)

        if requested_executable != authorized_executable:
            return (
                "runtime executable does not match authorized resource: "
                f"{requested_executable} != {authorized_executable}"
            )

        expected_argv_hash = action.metadata.get("authorized_argv_hash")
        if self.require_full_argv_binding and not expected_argv_hash:
            return "runtime requires a host-authorized full argv binding"

        if expected_argv_hash:
            actual_hash = hash_command(tuple(str(part) for part in command))
            if actual_hash != expected_argv_hash:
                return "runtime argv does not match host-authorized argv"

        return None

    def _deny_binding(
        self,
        action: ActionRequest,
        reason: str,
    ) -> ExecutionResult:
        evaluation = Evaluation(
            decision=Decision.DENY,
            risk=1.0,
            reasons=(reason,),
            hard_block=True,
        )

        self.trace.emit(
            "Evaluate",
            decision=Decision.DENY.value,
        )
        self.trace.emit("ResolveDeny")

        ledger = getattr(self.engine, "ledger", None)
        if ledger is not None:
            ledger.append(action, evaluation)

        return ExecutionResult(
            evaluation=evaluation,
            executed=False,
            sandboxed=False,
            review_required=False,
            returncode=None,
            stdout="",
            stderr=reason,
            trace_state=self.trace.snapshot(),
        )

    def execute(
        self,
        action: ActionRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float | None = 30.0,
    ) -> ExecutionResult:
        parent_has = (
            action.parent_capabilities is not None
            and action.capability in action.parent_capabilities
        )
        self.trace.reset(parent_has_capability=parent_has)

        binding_failure = self._binding_failure(action, command)
        if binding_failure is not None:
            return self._deny_binding(action, binding_failure)

        evaluation = self.engine.evaluate(action)
        self.trace.emit(
            "Evaluate",
            decision=evaluation.decision.value,
        )

        if evaluation.decision == Decision.DENY:
            self.trace.emit("ResolveDeny")
            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=False,
                returncode=None,
                stdout="",
                stderr="execution denied by BULL policy",
                trace_state=self.trace.snapshot(),
            )

        if evaluation.decision == Decision.ESCALATE:
            self.trace.emit("ResolveEscalate")
            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=True,
                returncode=None,
                stdout="",
                stderr="execution requires review",
                trace_state=self.trace.snapshot(),
            )

        project_root = Path(project_root).resolve(strict=True)

        try:
            build_manifest(project_root)
        except FilesystemManifestViolation as exc:
            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=False,
                returncode=None,
                stdout="",
                stderr="project manifest rejected: " + str(exc),
                trace_state=self.trace.snapshot(),
            )

        try:
            snapshot = create_snapshot(project_root)
        except SnapshotViolation as exc:
            return ExecutionResult(
                evaluation=evaluation,
                executed=False,
                sandboxed=False,
                review_required=False,
                returncode=None,
                stdout="",
                stderr="project snapshot rejected: " + str(exc),
                trace_state=self.trace.snapshot(),
            )

        execution_root = snapshot.snapshot_root

        try:
            try:
                build_manifest(execution_root)
            except FilesystemManifestViolation as exc:
                return ExecutionResult(
                    evaluation=evaluation,
                    executed=False,
                    sandboxed=False,
                    review_required=False,
                    returncode=None,
                    stdout="",
                    stderr="execution snapshot manifest rejected: " + str(exc),
                    trace_state=self.trace.snapshot(),
                )

            if self.malware_scan_required:
                if self.malware_scanner is None:
                    self.trace.emit("ScanMalware")
                    self.trace.emit("BlockMalware")
                    return ExecutionResult(
                        evaluation=evaluation,
                        executed=False,
                        sandboxed=False,
                        review_required=False,
                        returncode=None,
                        stdout="",
                        stderr="malware scan required but scanner unavailable",
                        malware_scan_performed=False,
                        malware_clean=None,
                        trace_state=self.trace.snapshot(),
                    )

                try:
                    scan = self.malware_scanner.scan_project(execution_root)
                except Exception as exc:
                    self.trace.emit("ScanMalware")
                    self.trace.emit("BlockMalware")
                    return ExecutionResult(
                        evaluation=evaluation,
                        executed=False,
                        sandboxed=False,
                        review_required=False,
                        returncode=None,
                        stdout="",
                        stderr="malware scan failed closed: " + str(exc),
                        malware_scan_performed=True,
                        malware_clean=None,
                        trace_state=self.trace.snapshot(),
                    )

                if not scan.clean:
                    self.trace.emit("ScanMalware")
                    self.trace.emit("BlockMalware")
                    detections = tuple(
                        result.signature or result.path
                        for result in scan.detections
                    )
                    return ExecutionResult(
                        evaluation=evaluation,
                        executed=False,
                        sandboxed=False,
                        review_required=False,
                        returncode=None,
                        stdout="",
                        stderr="malware detection blocked execution",
                        malware_scan_performed=True,
                        malware_clean=False,
                        malware_detections=detections,
                        trace_state=self.trace.snapshot(),
                    )

                self.trace.emit("ScanClean")
                malware_clean = True
            else:
                raise RuntimeError(
                    "formal runtime instrumentation requires malware scanning"
                )

            current_snapshot_hash = hash_tree(execution_root)
            if current_snapshot_hash != snapshot.snapshot_hash:
                return ExecutionResult(
                    evaluation=evaluation,
                    executed=False,
                    sandboxed=False,
                    review_required=False,
                    returncode=None,
                    stdout="",
                    stderr="execution snapshot changed after malware scan",
                    malware_scan_performed=True,
                    malware_clean=True,
                    trace_state=self.trace.snapshot(),
                )

            writable = False

            environment_bindings = {
                "BULL_SECURITY_DOMAIN_ID": action.metadata.get("domain_id"),
                "BULL_ROOT_DOMAIN_ID": action.metadata.get("root_domain_id"),
                "BULL_PARENT_DOMAIN_ID": action.metadata.get("parent_domain_id"),
                "BULL_INITIAL_INTENT_HASH": action.metadata.get(
                    "initial_intent_hash"
                ),
                "BULL_INITIAL_COMMAND_HASH": action.metadata.get(
                    "initial_command_hash"
                ),
                "BULL_MODEL_ID_HASH": action.metadata.get("model_id_hash"),
                "BULL_DOMAIN_FINGERPRINT": action.metadata.get(
                    "domain_fingerprint"
                ),
                "BULL_AUTHORIZED_ARGV_HASH": action.metadata.get(
                    "authorized_argv_hash"
                ),
            }
            sandbox_env = {
                key: str(value)
                for key, value in environment_bindings.items()
                if value is not None
            }

            result: SandboxResult = self.sandbox.run(
                command,
                project_root=execution_root,
                writable=writable,
                timeout=timeout,
                env=sandbox_env,
                resource_budget=self.resource_budget,
            )

            self.trace.emit(
                "Execute",
                sandboxed=True,
                seccomp=True,
            )

            return ExecutionResult(
                evaluation=evaluation,
                executed=True,
                sandboxed=True,
                review_required=False,
                returncode=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                malware_scan_performed=True,
                malware_clean=malware_clean,
                trace_state=self.trace.snapshot(),
            )
        finally:
            destroy_snapshot(snapshot)

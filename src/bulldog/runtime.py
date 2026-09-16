from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

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
    Decision,
    Evaluation,
)
from .namespace_sandbox import (
    NamespaceSandbox,
    SandboxResult,
)
from .resource_limits import ResourceBudget
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

    def execute(
        self,
        action: ActionRequest,
        command: Sequence[str],
        *,
        project_root: str | Path,
        timeout: float | None = 30.0,
    ) -> ExecutionResult:
        # Fresh execution trace for each runtime invocation.
        parent_has = (
            action.parent_capabilities is not None
            and action.capability in action.parent_capabilities
        )
        self.trace.reset(parent_has_capability=parent_has)

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

        # Reject unsupported filesystem objects and mount/device boundaries
        # before copying anything into the trusted execution snapshot.
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
            # The copied tree must independently satisfy the same filesystem
            # contract before it can become executable state.
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
                    # IMPORTANT: scan the immutable execution snapshot, not
                    # the mutable source project.
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

            # Bind the exact bytes admitted by the malware scanner to the
            # execution decision. A mutation after scanning fails closed.
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

            writable = action.capability.value == "fs.write.project"
            if action.capability.value == "process.exec":
                writable = False

            # IMPORTANT: the sandbox mounts execution_root. The mutable source
            # project is never mounted after admission.
            result: SandboxResult = self.sandbox.run(
                command,
                project_root=execution_root,
                writable=writable,
                timeout=timeout,
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
